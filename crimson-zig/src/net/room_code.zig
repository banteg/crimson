const std = @import("std");
const msgpack = @import("msgpack");

pub const room_code_length: usize = 4;
pub const RoomCode = struct {
    bytes: [room_code_length]u8,

    pub fn msgpackWrite(self: RoomCode, packer: anytype) !void {
        try packer.writeString(self.bytes[0..]);
    }

    pub fn msgpackRead(unpacker: anytype) !RoomCode {
        const text = try unpacker.readString();
        return parseRoomCode(text);
    }
};

pub const RoomCodeError = error{
    InvalidRoomCode,
};

pub fn parseRoomCode(value: []const u8) RoomCodeError!RoomCode {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len != room_code_length) return error.InvalidRoomCode;

    var out: [room_code_length]u8 = undefined;
    for (trimmed, 0..) |ch, idx| {
        if (!std.ascii.isAlphanumeric(ch)) return error.InvalidRoomCode;
        out[idx] = std.ascii.toLower(ch);
    }
    return .{ .bytes = out };
}

pub fn parseOptionalRoomCode(value: ?[]const u8) RoomCodeError!?RoomCode {
    const text = std.mem.trim(u8, value orelse "", " \t\r\n");
    if (text.len == 0) return null;
    const code = try parseRoomCode(text);
    return code;
}

pub fn roomCodeSlice(code: *const RoomCode) []const u8 {
    return code.bytes[0..];
}

test "room code parser trims and lowercases ascii code" {
    const code = try parseRoomCode(" Ab9Z\n");
    try std.testing.expectEqualStrings("ab9z", roomCodeSlice(&code));
}

test "room code parser rejects wrong shape" {
    try std.testing.expectError(error.InvalidRoomCode, parseRoomCode("abc"));
    try std.testing.expectError(error.InvalidRoomCode, parseRoomCode("abcde"));
    try std.testing.expectError(error.InvalidRoomCode, parseRoomCode("ab-c"));
}

test "optional room code parser treats blank as none" {
    try std.testing.expect((try parseOptionalRoomCode(null)) == null);
    try std.testing.expect((try parseOptionalRoomCode(" \n\t")) == null);

    const code = (try parseOptionalRoomCode("WXYZ")).?;
    try std.testing.expectEqualStrings("wxyz", roomCodeSlice(&code));
}

test "room code msgpack roundtrips as lowercase string" {
    const code = try parseRoomCode("WXYZ");
    var writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer writer.deinit();
    try msgpack.encode(code, &writer.writer);

    const decoded = try msgpack.decodeFromSlice(RoomCode, std.testing.allocator, writer.written());
    defer decoded.deinit();
    try std.testing.expectEqualStrings("wxyz", roomCodeSlice(&decoded.value));
}
