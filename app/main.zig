const std = @import("std");
const fs = std.fs;
const hash = std.crypto.hash;
const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();
const page_allocator = std.heap.page_allocator;
const test_allocator = std.testing.allocator;
const assert = std.debug.assert;
const ArrayList = std.ArrayList;
const ArrayHashMap = std.StringArrayHashMap;

const Command = enum { decode, info, peers, handshake };

const BType = union(enum) {
    string: []const u8,
    integer: isize,
    list: []BType,
    dict: ArrayHashMap(BType),

    fn free(payload: *@This(), allocator: std.mem.Allocator) void {
        switch (payload.*) {
            .dict => {
                var iter = payload.dict.iterator();
                out: while (true) {
                    const entry = iter.next();
                    if (entry == null) {
                        break :out;
                    }
                    var value = entry.?.value_ptr.*;
                    value.free(allocator);
                }
                payload.dict.deinit();
            },
            // [some,[none,done]]
            .list => {
                const list_len = payload.list.len;
                var idx: usize = 0;
                while (idx < list_len) {
                    payload.list[idx].free(allocator);
                    idx += 1;
                }
                allocator.free(payload.list);
            },
            else => return,
        }
    }
};

const Payload = struct {
    btype: BType,
    size: usize,
};

const TorrentInfo = struct {
    announceURL: *const BType,
    length: *const BType,
    info: *const BType,
    infoHash: [hash.Sha1.digest_length]u8,
    pieceLength: *const BType,
    pieces: *const BType,
};

const TrackerResponse = struct {
    interval: *const BType,
    peers: *const BType,
};

const HandshakePayload = extern struct {
    protoLength: u8 align(1) = 19,
    ident: [19]u8 align(1) = "BitTorrent protocol".*,
    reserved: [8]u8 align(1) = std.mem.zeroes([8]u8),
    infoHash: [20]u8 align(1),
    peerId: [20]u8 align(1),
};

const DecodeError = error{
    MalformedInput,
    InvalidEncoding,
};

pub fn main() !void {
    const args = try std.process.argsAlloc(page_allocator);
    defer std.process.argsFree(page_allocator, args);

    if (args.len < 3) {
        try stderr.print("Usage: your_bittorrent.zig <command> <args>\n", .{});
        std.process.exit(1);
    }

    const command = std.meta.stringToEnum(Command, args[1]) orelse return;

    switch (command) {
        .decode => {
            const encodedStr = args[2];
            var decodedStr = decodeBencode(encodedStr, page_allocator) catch |err| {
                switch (err) {
                    DecodeError.InvalidEncoding => try stderr.print("Provided encoding is invalid\n", .{}),
                    DecodeError.MalformedInput => try stderr.print("0 prefixed length for string decoding is not supported.\n", .{}),
                    else => try stderr.print("Error occured: {}\n", .{err}),
                }
                std.process.exit(1);
            };
            // free the resource
            defer decodedStr.btype.free(page_allocator);

            var string = std.ArrayList(u8).init(page_allocator);
            defer string.deinit();
            try printBencode(&string, &decodedStr.btype);
            const resStr = try string.toOwnedSlice();
            try stdout.print("{s}\n", .{resStr});
        },
        .info => {
            const encodedStr = try read_file(args[2]);
            var decodedStr = decodeBencode(encodedStr, page_allocator) catch |err| {
                switch (err) {
                    DecodeError.InvalidEncoding => try stderr.print("Provided encoding is invalid\n", .{}),
                    DecodeError.MalformedInput => try stderr.print("0 prefixed length for string decoding is not supported.\n", .{}),
                    else => try stderr.print("Error occured: {}\n", .{err}),
                }
                std.process.exit(1);
            };
            defer decodedStr.btype.free(page_allocator);

            const torrentInfo = try getTorrentInfo(&decodedStr.btype);

            try stdout.print("Tracker URL: {s}\n", .{torrentInfo.announceURL.string});
            try stdout.print("Length: {d}\n", .{torrentInfo.length.integer});

            try stdout.print("Info Hash: {s}\n", .{std.fmt.fmtSliceHexLower(&torrentInfo.infoHash)});
            try stdout.print("Piece Length: {d}\n", .{torrentInfo.pieceLength.integer});

            var windowIter = std.mem.window(u8, torrentInfo.pieces.string, 20, 20);
            while (windowIter.next()) |entry| {
                try stdout.print("{s}\n", .{std.fmt.fmtSliceHexLower(entry)});
            }
        },
        .peers => {
            const encodedStr = try read_file(args[2]);
            var decodedStr = decodeBencode(encodedStr, page_allocator) catch |err| {
                switch (err) {
                    DecodeError.InvalidEncoding => try stderr.print("Provided encoding is invalid\n", .{}),
                    DecodeError.MalformedInput => try stderr.print("0 prefixed length for string decoding is not supported.\n", .{}),
                    else => try stderr.print("Error occured: {}\n", .{err}),
                }
                std.process.exit(1);
            };
            defer decodedStr.btype.free(page_allocator);

            const torrentInfo = try getTorrentInfo(&decodedStr.btype);

            const body = try performPeerDiscovery(&torrentInfo, page_allocator);

            var respDecoded = decodeBencode(body, page_allocator) catch |err| {
                switch (err) {
                    DecodeError.InvalidEncoding => try stderr.print("Provided encoding is invalid\n", .{}),
                    DecodeError.MalformedInput => try stderr.print("0 prefixed length for string decoding is not supported.\n", .{}),
                    else => try stderr.print("Error occured: {}\n", .{err}),
                }
                std.process.exit(1);
            };
            defer respDecoded.btype.free(page_allocator);

            const trackerInfo = try getTrackerInfo(&respDecoded.btype);

            var windowIter = std.mem.window(u8, trackerInfo.peers.string, 6, 6);

            while (windowIter.next()) |entry| {
                const ip = try std.fmt.allocPrint(page_allocator, "{}.{}.{}.{}", .{ entry[0], entry[1], entry[2], entry[3] });
                defer page_allocator.free(ip);
                const port = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, entry[4..6]));

                try stdout.print("{s}:{d}\n", .{ ip, port });
            }
        },
        .handshake => {
            const encodedStr = try read_file(args[2]);
            var decodedStr = decodeBencode(encodedStr, page_allocator) catch |err| {
                switch (err) {
                    DecodeError.InvalidEncoding => try stderr.print("Provided encoding is invalid\n", .{}),
                    DecodeError.MalformedInput => try stderr.print("0 prefixed length for string decoding is not supported.\n", .{}),
                    else => try stderr.print("Error occured: {}\n", .{err}),
                }
                std.process.exit(1);
            };
            defer decodedStr.btype.free(page_allocator);

            const torrentInfo = try getTorrentInfo(&decodedStr.btype);

            const ipWithPort = args[3];
            const colonIdx = std.mem.indexOf(u8, ipWithPort, ":").?;
            const ip = ipWithPort[0..colonIdx];
            const port = try std.fmt.parseInt(u16, ipWithPort[colonIdx + 1 ..], 10);

            const handshake = HandshakePayload{
                .infoHash = torrentInfo.infoHash,
                .peerId = "11223344556677889009".*,
            };

            const address = try std.net.Address.parseIp(ip, port);
            const stream = try std.net.tcpConnectToAddress(address);

            var reader = stream.reader();
            var writer = stream.writer();

            try writer.writeStruct(handshake);

            const resp = try reader.readStruct(HandshakePayload);

            try stdout.print("Peer ID: {s}\n", .{std.fmt.fmtSliceHexLower(&resp.peerId)});
        },
    }
}

fn getTrackerInfo(payload: *const BType) !TrackerResponse {
    return TrackerResponse{
        .interval = (try retrieveValue(payload, "interval")).?,
        .peers = (try retrieveValue(payload, "peers")).?,
    };
}

fn getTorrentInfo(payload: *const BType) !TorrentInfo {
    const info = (try retrieveValue(payload, "info")).?;

    const encodedInfo = try getMetainfoEncodedValue(null, info, page_allocator);
    defer page_allocator.free(encodedInfo);

    var hashBuf: [hash.Sha1.digest_length]u8 = undefined;
    hash.Sha1.hash(encodedInfo, &hashBuf, .{});

    const torrentInfo = TorrentInfo{
        .announceURL = (try retrieveValue(payload, "announce")).?,
        .info = info,
        .infoHash = hashBuf,
        .length = (try retrieveValue(payload, "length")).?,
        .pieces = (try retrieveValue(payload, "pieces")).?,
        .pieceLength = (try retrieveValue(payload, "piece length")).?,
    };
    // std.mem.copyForwards(u8, torrentInfo.infoHash, &hashBuf);

    return torrentInfo;
}

fn performPeerDiscovery(torrentInfo: *const TorrentInfo, allocator: std.mem.Allocator) ![]const u8 {
    var percentEncodedInfoBuf = ArrayList(u8).init(allocator);
    try std.Uri.Component.format(std.Uri.Component{ .raw = &torrentInfo.infoHash }, "%", .{}, percentEncodedInfoBuf.writer());
    const percentEncodedInfoSlice = try percentEncodedInfoBuf.toOwnedSlice();
    defer allocator.free(percentEncodedInfoSlice);

    const formedURI = try std.fmt.allocPrint(allocator, "{s}?peer_id={}&info_hash={s}&port={}&left={d}&downloaded={}&uploaded={}&compact=1", .{ torrentInfo.announceURL.string, 11223344556677889009, percentEncodedInfoSlice, 6881, torrentInfo.length.integer, 0, 0 });
    try stdout.print("{s}\n", .{formedURI});

    const uri = try std.Uri.parse(formedURI);
    var client = std.http.Client{ .allocator = allocator };

    var serverHeaderBuffer: [1024]u8 = undefined;
    var req = try client.open(.GET, uri, .{ .server_header_buffer = &serverHeaderBuffer });

    try req.send();
    try req.wait();

    var resp = req.reader();
    const body = try resp.readAllAlloc(allocator, 1024);

    return body;
}

fn getMetainfoEncodedValue(key: ?[]const u8, payload: *const BType, allocator: std.mem.Allocator) ![]const u8 {
    var toEncode: *const BType = undefined;
    if (null != key) {
        const value = try retrieveValue(payload, key.?);
        if (value == null) {
            try stderr.print("key not found\n", .{});
            std.process.exit(1);
        }
        toEncode = value.?;
    } else {
        toEncode = payload;
    }

    var encodeBuf = ArrayList(u8).init(allocator);
    try encodeBencode(&encodeBuf, toEncode, allocator);
    const encodedSlice = try encodeBuf.toOwnedSlice();

    return encodedSlice;
}

fn getMetainfoValues(key: []const u8, payload: *BType) ![]const u8 {
    const value = try retrieveValue(payload, key);
    if (value == null) {
        try stderr.print("key not found\n", .{});
        std.process.exit(1);
    }
    return try getValueStr(value.?);
}

fn getValueStr(payload: *const BType) ![]const u8 {
    var buf = ArrayList(u8).init(page_allocator);
    try printBencode(&buf, payload);
    return buf.toOwnedSlice();
}

// the payload passed will always be of map type, where we have to retrieve value
// for provided key
fn retrieveValue(payload: *const BType, keyToLookup: []const u8) !?*const BType {

    // Eg.,
    // d3:oned4:lovel1:i4:love3:youe4:hatel1:i4:hate3:youee3:twod4:theyi3eee
    // {"one":{"love":["i","love","you"],"hate":["i","hate","you"]},"two":{"they":3}}
    if (payload.* != BType.dict) {
        return null;
    }
    var iterator = payload.dict.iterator();
    while (iterator.next()) |entry| {
        const key = entry.key_ptr.*;
        if (std.mem.eql(u8, key, keyToLookup)) {
            return &entry.value_ptr.*;
        }
        const value = try retrieveValue(&entry.value_ptr.*, keyToLookup);
        if (value) |val| {
            return val;
        }
    }
    return null;
}

fn printBencode(string: *ArrayList(u8), payload: *const BType) !void {
    switch (payload.*) {
        .integer => |int| {
            try std.json.stringify(int, .{}, string.writer());
        },
        .string => |str| {
            try std.json.stringify(str, .{}, string.writer());
        },
        // Eg., [int, [string, int]]
        .list => |list| {
            try string.append('[');
            for (list, 0..) |item, idx| {
                try printBencode(string, &item);
                if (idx != list.len - 1) {
                    try string.append(',');
                }
            }
            try string.append(']');
        },

        // Eg., d3:fool3:bari-52ee5:helloi52ee
        .dict => |dict| {
            try string.append('{');
            var iterator = dict.iterator();
            var idx: usize = 0;
            while (iterator.next()) |entry| {
                try std.json.stringify(entry.key_ptr.*, .{}, string.writer());
                try string.append(':');
                try printBencode(string, entry.value_ptr);
                if (idx != dict.count() - 1) {
                    try string.append(',');
                }
                idx += 1;
            }
            // TODO: think of how to free dict
            try string.append('}');
        },
    }
}

fn read_file(filename: []const u8) ![]const u8 {
    const file = try fs.cwd().openFile(filename, .{});
    defer file.close();

    const encodedStr = try file.reader().readAllAlloc(page_allocator, 1e5);

    return encodedStr;
}

fn encodeBencode(string: *ArrayList(u8), payload: *const BType, allocator: std.mem.Allocator) !void {
    switch (payload.*) {
        .string => |str| {
            // NOTE: could have also used std.fmt for printing len also
            const strlen = @as(usize, @intFromFloat(@log10(@as(f64, @floatFromInt(str.len))))) + 1;
            const buf = try page_allocator.alloc(u8, strlen);
            defer page_allocator.free(buf);
            try string.appendSlice(try std.fmt.bufPrint(buf, "{d}", .{str.len}));
            try string.append(':');
            try string.appendSlice(str);
        },
        .integer => |integer| {
            try string.append('i');
            var intLen: usize = @intFromFloat(@log10(@as(f64, @floatFromInt(if (integer < 0) -integer else integer))));
            intLen += if (integer < 0) 2 else 1;
            const buf = try page_allocator.alloc(u8, intLen);
            defer page_allocator.free(buf);
            try string.appendSlice(try std.fmt.bufPrint(buf, "{d}", .{integer}));
            try string.append('e');
        },
        .list => |list| {
            try string.append('l');
            for (list) |item| {
                try encodeBencode(string, &item, allocator);
            }
            try string.append('e');
        },
        .dict => |dict| {
            try string.append('d');
            var iterator = dict.iterator();
            while (iterator.next()) |entry| {
                try encodeBencode(string, &BType{ .string = entry.key_ptr.* }, allocator);
                try encodeBencode(string, &entry.value_ptr.*, allocator);
            }
            try string.append('e');
        },
    }
}

fn decodeBencode(encodedValue: []const u8, allocator: std.mem.Allocator) !Payload {
    switch (encodedValue[0]) {

        // decoding for string
        '0'...'9' => {
            const colon_idx = std.mem.indexOf(u8, encodedValue, ":");
            if (colon_idx) |idx| {
                const str_size = try std.fmt.parseInt(usize, encodedValue[0..idx], 10);
                const start_idx = idx + 1;
                const end_idx = start_idx + str_size;
                return Payload{
                    .btype = .{ .string = encodedValue[start_idx..end_idx] },
                    .size = end_idx,
                };
            } else {
                return DecodeError.MalformedInput;
            }
        },

        // decoding for integer
        'i' => {
            const e_idx = std.mem.indexOf(u8, encodedValue, "e");
            if (e_idx) |idx| {
                const str_int = encodedValue[1..idx];
                const has_prefix_zero = str_int.len > 1 and (str_int[0] == '0' or (str_int[0] == '-' and str_int[1] == '0'));
                if (has_prefix_zero) {
                    return DecodeError.InvalidEncoding;
                }
                return Payload{
                    .btype = .{ .integer = std.fmt.parseInt(isize, encodedValue[1..idx], 10) catch {
                        return DecodeError.MalformedInput;
                    } },
                    .size = e_idx.? + 1,
                };
            } else {
                return DecodeError.MalformedInput;
            }
        },

        // decoding for list
        'l' => {
            var list = ArrayList(BType).init(allocator);
            var cidx: usize = 1;
            while (cidx < encodedValue.len and encodedValue[cidx] != 'e') {
                const deserialized = decodeBencode(encodedValue[cidx..], allocator) catch |err| {
                    list.deinit();
                    return err;
                };
                try list.append(deserialized.btype);
                cidx += deserialized.size;
            }
            if (cidx == encodedValue.len) { // 'e' denoting ending of list is missing
                const len = list.items.len;
                var idx: usize = 0;
                while (idx < len) : (idx += 1) {
                    list.items[idx].free(allocator);
                }
                list.deinit();
                return DecodeError.InvalidEncoding;
            }
            return Payload{
                .btype = .{
                    .list = try list.toOwnedSlice(),
                },
                .size = cidx + 1,
            };
        },

        // decoding for dict
        'd' => {
            var map = ArrayHashMap(BType).init(allocator);
            // defer map.deinit();
            var cidx: usize = 1;
            while (cidx < encodedValue.len and encodedValue[cidx] != 'e') {
                // if key is not string, it should throw error
                var key = decodeBencode(encodedValue[cidx..], allocator) catch |err| {
                    map.deinit();
                    return err;
                };
                if (key.btype != BType.string) {
                    key.btype.free(allocator); // could possibly be list or a dict
                    map.deinit();
                    return DecodeError.InvalidEncoding;
                }
                cidx += key.size;
                const value = decodeBencode(encodedValue[cidx..], allocator) catch |err| {
                    map.deinit();
                    return err;
                };
                cidx += value.size;
                map.put(key.btype.string, value.btype) catch |err| {
                    map.deinit();
                    return err;
                };
            }
            if (cidx == encodedValue.len) {
                var iter = map.iterator();
                const len = map.count();
                var idx: usize = 0;
                while (idx < len) : (idx += 1) {
                    const entry = iter.next();
                    if (entry == null) break;
                    var value = entry.?.value_ptr.*;
                    value.free(allocator);
                }
                map.deinit();
                return DecodeError.InvalidEncoding;
            }

            const Ctx = struct {
                map: ArrayHashMap(BType),

                pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
                    const keys = ctx.map.keys();
                    return std.mem.order(u8, keys[a], keys[b]).compare(std.math.CompareOperator.lt);
                }
            };

            map.sort(Ctx{ .map = map });
            return Payload{
                .btype = .{
                    .dict = map,
                },
                .size = cidx + 1,
            };
        },

        else => {
            try stdout.print("Only strings and integers are supported at the moment\n", .{});
            std.process.exit(1);
        },
    }
}

fn testIfDecodedBencodeEqual(type1: BType, type2: BType) bool {
    switch (type1) {
        .integer => |int1| {
            switch (type2) {
                .integer => |int2| {
                    return if (int1 == int2) true else false;
                },
                else => return false,
            }
        },
        .string => |str1| {
            switch (type2) {
                .string => |str2| {
                    return if (std.mem.eql(u8, str1, str2)) true else false;
                },
                else => return false,
            }
        },
        .list => |list1| {
            switch (type2) {
                .list => |list2| {
                    if (list1.len != list2.len) {
                        return false;
                    }
                    var idx: usize = 0;
                    while (idx != list1.len) : (idx += 1) {
                        if (!testIfDecodedBencodeEqual(list1[idx], list2[idx])) {
                            return false;
                        }
                    }
                    return true;
                },
                else => return false,
            }
        },
        .dict => |dict1| {
            switch (type2) {
                .dict => |dict2| {
                    if (dict1.count() != dict2.count()) {
                        return false;
                    }
                    var iter1 = dict1.iterator();
                    var iter2 = dict2.iterator();
                    out: while (true) {
                        const entry1 = iter1.next();
                        const entry2 = iter2.next();
                        if (entry1 == null or entry2 == null) {
                            break :out;
                        }
                        if (!std.mem.eql(u8, entry1.?.key_ptr.*, entry2.?.key_ptr.*)) {
                            return false;
                        }
                        if (!testIfDecodedBencodeEqual(entry1.?.value_ptr.*, entry2.?.value_ptr.*)) {
                            return false;
                        }
                    }
                    return true;
                },
                else => return false,
            }
        },
    }
}

const TestPair = struct {
    x: []const u8,
    y: []const u8,
    out: bool,
};

// introducing tests here
test "decodeStrings" {
    try std.testing.expectEqualStrings((try decodeBencode("6:banana", test_allocator)).btype.string, "banana");
    try std.testing.expectEqualStrings((try decodeBencode("5:hello", test_allocator)).btype.string, "hello");
    try std.testing.expectEqualStrings((try decodeBencode("3:arm", test_allocator)).btype.string, "arm");
    try std.testing.expectError(DecodeError.MalformedInput, decodeBencode("5hello", test_allocator));
}

test "decodeIntegers" {
    try std.testing.expectEqual((try decodeBencode("i535903435363e", test_allocator)).btype.integer, 535903435363);
    try std.testing.expectEqual((try decodeBencode("i-535903435363e", test_allocator)).btype.integer, -535903435363);
    try std.testing.expectEqual((try decodeBencode("i52e", test_allocator)).btype.integer, 52);
    try std.testing.expectEqual((try decodeBencode("i-52e", test_allocator)).btype.integer, -52);
    try std.testing.expectError(DecodeError.MalformedInput, decodeBencode("i52", test_allocator));
    try std.testing.expectError(DecodeError.MalformedInput, decodeBencode("ihelloe", test_allocator));
    try std.testing.expectError(DecodeError.InvalidEncoding, decodeBencode("i010e", test_allocator));
    try std.testing.expectError(DecodeError.InvalidEncoding, decodeBencode("i-02e", test_allocator));
}

test "decodeLists" {
    var pairs = ArrayList(TestPair).init(test_allocator);
    defer pairs.deinit();
    try pairs.append(TestPair{ .x = "l6:bananae", .y = "l6:bananae", .out = true });
    try pairs.append(TestPair{ .x = "l6:bananae", .y = "l6:thoughe", .out = false });
    try pairs.append(TestPair{ .x = "l6:bananali-52e5:helloeee", .y = "l6:bananai-52ee", .out = false });
    try pairs.append(TestPair{ .x = "l6:bananali-52e5:helloeee", .y = "l6:bananali-52e5:helloeee", .out = true });

    for (pairs.items) |pair| {
        var payload1 = try decodeBencode(pair.x, test_allocator);
        var payload2 = try decodeBencode(pair.y, test_allocator);
        try std.testing.expectEqual(testIfDecodedBencodeEqual(payload1.btype, payload2.btype), pair.out);
        payload1.btype.free(test_allocator);
        payload2.btype.free(test_allocator);
    }

    // in case of error, no need to call free explicitly
    // decodeBencode will free the resources it allocated during execution
    try std.testing.expectError(DecodeError.InvalidEncoding, decodeBencode("l6:bananali-52e5:helloe", test_allocator));
}

test "decodeDicts" {
    var pairs = ArrayList(TestPair).init(test_allocator);
    defer pairs.deinit();
    try pairs.append(TestPair{ .x = "d3:foo3:bar5:helloi52ee", .y = "d3:foo3:bar5:helloi52ee", .out = true });
    try pairs.append(TestPair{ .x = "d3:foo3:bar5:helloi52ee", .y = "d3:fee3:bar5:helloi52ee", .out = false });
    try pairs.append(TestPair{ .x = "d3:fool3:bari-52ee5:helloi52ee", .y = "d3:fool3:bari-52ee5:helloi52ee", .out = true });
    try pairs.append(TestPair{ .x = "d3:fool3:bari-52ee5:helloi52ee", .y = "d3:fool3:bari-52ee5:helloi52ee", .out = true });
    try pairs.append(TestPair{ .x = "d3:fool3:bari-52ee5:hellod6:bananai52eee", .y = "d3:fool3:bari-52ee5:hellod6:bananai52eee", .out = true });

    for (pairs.items) |pair| {
        var payload1 = try decodeBencode(pair.x, test_allocator);
        var payload2 = try decodeBencode(pair.y, test_allocator);
        try std.testing.expectEqual(testIfDecodedBencodeEqual(payload1.btype, payload2.btype), pair.out);
        payload1.btype.free(test_allocator);
        payload2.btype.free(test_allocator);
    }

    // decodeBencode will clean up all the resources allocated to it's object in case of failure
    try std.testing.expectError(DecodeError.InvalidEncoding, decodeBencode("d3:fee3:bar5:helloi52e", test_allocator));
    try std.testing.expectError(DecodeError.InvalidEncoding, decodeBencode("d3:fee3:barl5:helloei52ee", test_allocator));
}

test "retrieveValue" {
    var payload = try decodeBencode("d3:oned3:twoi2eee", test_allocator);
    try std.testing.expectEqual((try retrieveValue(&payload.btype, "two")).?.integer, 2);
    try std.testing.expectEqual((try retrieveValue(&payload.btype, "three")), null);
    payload.btype.free(test_allocator);
}

test "encodeBencode" {
    const bencodes = [_]struct { input: []const u8, output: []const u8 }{ .{ .input = "d5:hellod6:bananai52ee3:fool3:bari-52eee", .output = "d3:fool3:bari-52ee5:hellod6:bananai52eee" }, .{ .input = "d5:hellod6:bananai52e3:armi1000ee3:fool3:bari-52eee", .output = "d3:fool3:bari-52ee5:hellod3:armi1000e6:bananai52eee" } };

    for (bencodes) |bencode| {
        var encodeBuf = ArrayList(u8).init(test_allocator);
        var payload = try decodeBencode(bencode.input, test_allocator);
        defer payload.btype.free(test_allocator);

        try encodeBencode(&encodeBuf, &payload.btype, test_allocator);
        const encoded = try encodeBuf.toOwnedSlice();
        defer test_allocator.free(encoded);
        try std.testing.expectEqualSlices(u8, encoded, bencode.output);
    }
}

test "memory" {
    var payload = try decodeBencode("d3:fool3:bari-52ee5:hellod6:bananai52eee", test_allocator);
    // var payload = try decodeBencode("l6:bananali-52e5:helloeee", test_allocator);
    // test_allocator.free(payload.btype.list);
    payload.btype.free(test_allocator);
}
