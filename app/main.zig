const std = @import("std");
const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();
const allocator = std.heap.page_allocator;
const assert = std.debug.assert;
const ArrayList = std.ArrayList;

const BType = union(enum) {
    string: []const u8,
    integer: isize,
    list: []BType,
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
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        try stderr.print("Usage: your_bittorrent.zig <command> <args>\n", .{});
        std.process.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "decode")) {
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        // try stdout.print("Logs from your program will appear here\n", .{});

        // Uncomment this block to pass the first stage
        const encodedStr = args[2];
        const decodedStr = decodeBencode(encodedStr) catch |err| {
            switch (err) {
                DecodeError.InvalidEncoding => try stderr.print("Provided encoding is invalid\n", .{}),
                DecodeError.MalformedInput => try stderr.print("0 prefixed length for string decoding is not supported.\n", .{}),
                else => try stderr.print("Error occured: {}\n", .{err}),
            }
            std.process.exit(1);
        };
        var string = std.ArrayList(u8).init(allocator);
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
    }
}

fn decodeBencode(encodedValue: []const u8) !Payload {
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
            defer list.deinit();
            var cidx: usize = 1;
            while (cidx < encodedValue.len and encodedValue[cidx] != 'e') {
                const deserialized = try decodeBencode(encodedValue[cidx..]);
                try list.append(deserialized.btype);
                cidx += deserialized.size;
            }
            if (cidx == encodedValue.len) { // 'e' denoting ending of list is missing
                return error.InvalidEncoding;
            }
            return Payload{
                .btype = .{
                    .list = try list.toOwnedSlice(),
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

fn testIsListEqual(l1: BType, l2: BType) bool {
    switch (l1) {
        .integer => |int1| {
            switch (l2) {
                .integer => |int2| {
                    return if (int1 == int2) true else false;
                },
                else => return false,
            }
        },
        .string => |str1| {
            switch (l2) {
                .string => |str2| {
                    return if (std.mem.eql(u8, str1, str2)) true else false;
                },
                else => return false,
            }
        },
        .list => |list1| {
            switch (l2) {
                .list => |list2| {
                    if (list1.len != list2.len) {
                        return false;
                    }
                    var idx: usize = 0;
                    while (idx != list1.len) : (idx += 1) {
                        if (!testIsListEqual(list1[idx], list2[idx])) {
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

// introducing tests here
test "strings" {
    try std.testing.expectEqualStrings((try decodeBencode("6:banana")).btype.string, "banana");
    try std.testing.expectEqualStrings((try decodeBencode("5:hello")).btype.string, "hello");
    try std.testing.expectEqualStrings((try decodeBencode("3:arm")).btype.string, "arm");
    try std.testing.expectError(error.MalformedInput, decodeBencode("5hello"));
}

test "integers" {
    try std.testing.expectEqual((try decodeBencode("i535903435363e")).btype.integer, 535903435363);
    try std.testing.expectEqual((try decodeBencode("i-535903435363e")).btype.integer, -535903435363);
    try std.testing.expectEqual((try decodeBencode("i52e")).btype.integer, 52);
    try std.testing.expectEqual((try decodeBencode("i-52e")).btype.integer, -52);
    try std.testing.expectError(error.MalformedInput, decodeBencode("i52"));
    try std.testing.expectError(error.MalformedInput, decodeBencode("ihelloe"));
    try std.testing.expectError(error.InvalidEncoding, decodeBencode("i010e"));
    try std.testing.expectError(error.InvalidEncoding, decodeBencode("i-02e"));
}

test "lists" {
    try std.testing.expectEqual(testIsListEqual((try decodeBencode("l6:bananae")).btype, (try decodeBencode("l6:bananae")).btype), true);
    try std.testing.expectEqual(testIsListEqual((try decodeBencode("l6:bananae")).btype, (try decodeBencode("l6:thoughe")).btype), false);
    try std.testing.expectEqual(testIsListEqual((try decodeBencode("l6:bananali-52e5:helloeee")).btype, (try decodeBencode("l6:bananai-52ee")).btype), false);
    try std.testing.expectEqual(testIsListEqual((try decodeBencode("l6:bananali-52e5:helloeee")).btype, (try decodeBencode("l6:bananali-52e5:helloeee")).btype), true);
}
