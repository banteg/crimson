const std = @import("std");

pub const BinaryError = error{
    UnexpectedEof,
};

pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    pub fn remaining(self: Reader) usize {
        return self.bytes.len - self.pos;
    }

    pub fn readU8(self: *Reader) BinaryError!u8 {
        if (self.remaining() < 1) return error.UnexpectedEof;
        const value = self.bytes[self.pos];
        self.pos += 1;
        return value;
    }

    pub fn readU16Le(self: *Reader) BinaryError!u16 {
        const raw = try self.readBytes(2);
        return std.mem.readInt(u16, raw, .little);
    }

    pub fn readU32Le(self: *Reader) BinaryError!u32 {
        const raw = try self.readBytes(4);
        return std.mem.readInt(u32, raw, .little);
    }

    pub fn readF32Le(self: *Reader) BinaryError!f32 {
        return @bitCast(try self.readU32Le());
    }

    pub fn readBytes(self: *Reader, len: usize) BinaryError![]const u8 {
        if (self.remaining() < len) return error.UnexpectedEof;
        const out = self.bytes[self.pos .. self.pos + len];
        self.pos += len;
        return out;
    }

    pub fn readArray(self: *Reader, comptime len: usize) BinaryError![len]u8 {
        var out: [len]u8 = undefined;
        const raw = try self.readBytes(len);
        @memcpy(&out, raw);
        return out;
    }
};

pub const Writer = struct {
    bytes: []u8,
    pos: usize = 0,

    pub fn init(bytes: []u8) Writer {
        return .{ .bytes = bytes };
    }

    pub fn remaining(self: Writer) usize {
        return self.bytes.len - self.pos;
    }

    pub fn writeU8(self: *Writer, value: u8) BinaryError!void {
        if (self.remaining() < 1) return error.UnexpectedEof;
        self.bytes[self.pos] = value;
        self.pos += 1;
    }

    pub fn writeU16Le(self: *Writer, value: u16) BinaryError!void {
        if (self.remaining() < 2) return error.UnexpectedEof;
        std.mem.writeInt(u16, self.bytes[self.pos .. self.pos + 2], value, .little);
        self.pos += 2;
    }

    pub fn writeU32Le(self: *Writer, value: u32) BinaryError!void {
        if (self.remaining() < 4) return error.UnexpectedEof;
        std.mem.writeInt(u32, self.bytes[self.pos .. self.pos + 4], value, .little);
        self.pos += 4;
    }

    pub fn writeF32Le(self: *Writer, value: f32) BinaryError!void {
        try self.writeU32Le(@bitCast(value));
    }

    pub fn writeBytes(self: *Writer, bytes: []const u8) BinaryError!void {
        if (self.remaining() < bytes.len) return error.UnexpectedEof;
        @memcpy(self.bytes[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }
};

test "reader and writer roundtrip" {
    var bytes: [7]u8 = undefined;
    var writer = Writer.init(bytes[0..]);
    try writer.writeU8(0x01);
    try writer.writeU16Le(0x0203);
    try writer.writeU32Le(0x04050607);

    try std.testing.expectEqual(@as(usize, 7), writer.pos);

    var reader = Reader.init(bytes[0..]);
    try std.testing.expectEqual(@as(u8, 0x01), try reader.readU8());
    try std.testing.expectEqual(@as(u16, 0x0203), try reader.readU16Le());
    try std.testing.expectEqual(@as(u32, 0x04050607), try reader.readU32Le());
    try std.testing.expectEqual(@as(usize, 0), reader.remaining());
}
