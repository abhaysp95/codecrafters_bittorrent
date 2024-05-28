const std = @import("std");
const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();
const page_allocator = std.heap.page_allocator;
const test_allocator = std.testing.allocator;
const assert = std.debug.assert;
const ArrayList = std.ArrayList;
const HashMap = std.StringHashMap;

const BType = union(enum) {
    string: []const u8,
    integer: isize,
    list: []BType,
    dict: HashMap(BType),

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

    const command = args[1];

    if (std.mem.eql(u8, command, "decode")) {
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
        try printBencode(&string, decodedStr.btype);
        const resStr = try string.toOwnedSlice();
        try stdout.print("{s}\n", .{resStr});
    }
}

fn printBencode(string: *ArrayList(u8), payload: BType) !void {
    switch (payload) {
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
                try printBencode(string, item);
                if (idx != list.len - 1) {
                    try string.append(',');
                }
            }
            try string.append(']');
        },

        // Eg., d3:fool3:bari-52ee5:helloi52ee
        .dict => |dict| {
            try string.append('{');
            var iterator = dict.keyIterator();
            var idx: usize = 0;
            while (iterator.next()) |key| {
                try std.json.stringify(key.*, .{}, string.writer());
                try string.append(':');
                try printBencode(string, dict.get(key.*).?);
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
            var map = HashMap(BType).init(allocator);
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
                    try stdout.print("key: {s}\n", .{entry.?.key_ptr.*});
                    value.free(allocator);
                }
                map.deinit();
                return DecodeError.InvalidEncoding;
            }
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
test "strings" {
    try std.testing.expectEqualStrings((try decodeBencode("6:banana", test_allocator)).btype.string, "banana");
    try std.testing.expectEqualStrings((try decodeBencode("5:hello", test_allocator)).btype.string, "hello");
    try std.testing.expectEqualStrings((try decodeBencode("3:arm", test_allocator)).btype.string, "arm");
    try std.testing.expectError(DecodeError.MalformedInput, decodeBencode("5hello", test_allocator));
}

test "integers" {
    try std.testing.expectEqual((try decodeBencode("i535903435363e", test_allocator)).btype.integer, 535903435363);
    try std.testing.expectEqual((try decodeBencode("i-535903435363e", test_allocator)).btype.integer, -535903435363);
    try std.testing.expectEqual((try decodeBencode("i52e", test_allocator)).btype.integer, 52);
    try std.testing.expectEqual((try decodeBencode("i-52e", test_allocator)).btype.integer, -52);
    try std.testing.expectError(DecodeError.MalformedInput, decodeBencode("i52", test_allocator));
    try std.testing.expectError(DecodeError.MalformedInput, decodeBencode("ihelloe", test_allocator));
    try std.testing.expectError(DecodeError.InvalidEncoding, decodeBencode("i010e", test_allocator));
    try std.testing.expectError(DecodeError.InvalidEncoding, decodeBencode("i-02e", test_allocator));
}

test "lists" {
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

test "dicts" {
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

test "memory" {
    var payload = try decodeBencode("d3:fool3:bari-52ee5:hellod6:bananai52eee", test_allocator);
    // var payload = try decodeBencode("l6:bananali-52e5:helloeee", test_allocator);
    // test_allocator.free(payload.btype.list);
    payload.btype.free(test_allocator);
}
