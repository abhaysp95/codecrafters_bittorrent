const std = @import("std");
const stdout = std.io.getStdOut().writer();
const allocator = std.heap.page_allocator;
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

pub fn main() !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        try stdout.print("Usage: your_bittorrent.zig <command> <args>\n", .{});
        std.process.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "decode")) {
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        // try stdout.print("Logs from your program will appear here\n", .{});

        // Uncomment this block to pass the first stage
        const encodedStr = args[2];
        const decodedStr = decodeBencodeList(encodedStr[1..]) catch {
            try stdout.print("Invalid encoded value\n", .{});
            std.process.exit(1);
        };
        var string = std.ArrayList(u8).init(allocator);
        switch (decodedStr) {
            // .string, .integer => |str| try std.json.stringify(str, .{}, string.writer()),
            .list => |l| try std.json.stringify(l, .{}, string.writer()),
        }
        const jsonStr = try string.toOwnedSlice();
        try stdout.print("{s}\n", .{jsonStr});
    }
}

fn decodeBencodeList(encodedValue: []const u8) !Payload {
    switch (encodedValue[0]) {
        0...9 => {
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
                // TODO: work on error
                return error.InvalidArgument;
            }
        },
        'i' => {
            const e_idx = std.mem.indexOf(u8, encodedValue, "e");
            if (e_idx) |idx| {
                return Payload{
                    .btype = .{
                        .integer = try std.fmt.parseInt(isize, encodedValue[1..idx], 10),
                    },
                    .size = e_idx + 1,
                };
            } else {
                // TODO: work on error
                return error.InvalidArgument;
            }
        },
        'l' => {
            const list = ArrayList(BType).init(allocator);
            defer list.deinit();
            var cidx: usize = 1;
            while (encodedValue[cidx] != 'e') {
                const deserialized = try decodeBencodeList(encodedValue[cidx..]);
                try list.append(deserialized.btype);
                cidx += deserialized.size;
            }
            return Payload{
                .btype = list.toOwnedSlice(),
                .size = cidx + 1,
            };
        },
        else => {
            try stdout.print("Only strings and integers are supported at the moment\n", .{});
            std.process.exit(1);
        },
    }
}

fn decodeBencode(encodedValue: []const u8) !BType {
    if (encodedValue[0] >= '0' and encodedValue[0] <= '9') {
        const firstColon = std.mem.indexOf(u8, encodedValue, ":");
        if (firstColon) |cidx| {
            return BType{
                .string = encodedValue[cidx + 1 ..],
            };
        }
        return error.InvalidArgument;
    } else if (encodedValue[0] == 'i') {
        const eidx = std.mem.indexOf(u8, encodedValue, "e");
        if (eidx) |idx| {
            return BType{
                .integer = try std.fmt.parseInt(isize, encodedValue[1..idx], 10),
            };
        }
        return error.InvalidArgument;
    } else {
        try stdout.print("Only strings and integers are supported at the moment\n", .{});
        std.process.exit(1);
    }
}

// introducing tests here
test "strings" {
    try std.testing.expectEqualStrings((try decodeBencode("6:banana")).string, "banana");
    try std.testing.expectEqualStrings((try decodeBencode("5:hello")).string, "hello");
    try std.testing.expectEqualStrings((try decodeBencode("3:arm")).string, "arm");
}

test "integers" {
    try std.testing.expectEqual((try decodeBencode("i535903435363e")).integer, 535903435363);
    try std.testing.expectEqual((try decodeBencode("i-535903435363e")).integer, -535903435363);
    try std.testing.expectEqual((try decodeBencode("i52e")).integer, 52);
    try std.testing.expectEqual((try decodeBencode("i-52e")).integer, -52);
    try std.testing.expectError(error.InvalidArgument, decodeBencode("i52"));
    try std.testing.expectError(error.InvalidCharacter, decodeBencode("ihelloe"));
}
