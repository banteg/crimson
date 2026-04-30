const std = @import("std");
const hdrs = @import("headers.zig");

const isOptional = @import("utils.zig").isOptional;
const NonOptional = @import("utils.zig").NonOptional;

const maybePackNull = @import("null.zig").maybePackNull;
const maybeUnpackNull = @import("null.zig").maybeUnpackNull;

const packIntValue = @import("int.zig").packIntValue;
const unpackIntValue = @import("int.zig").unpackIntValue;
const unpackShortIntValue = @import("int.zig").unpackShortIntValue;

pub fn sizeOfPackedBinaryHeader(len: usize) !usize {
    if (len <= hdrs.FIXSTR_MAX - hdrs.FIXSTR_MIN) {
        return 1;
    } else if (len <= std.math.maxInt(u8)) {
        return 1 + @sizeOf(u8);
    } else if (len <= std.math.maxInt(u16)) {
        return 1 + @sizeOf(u16);
    } else if (len <= std.math.maxInt(u32)) {
        return 1 + @sizeOf(u32);
    } else {
        return error.BinaryTooLong;
    }
}

pub fn sizeOfPackedBinary(len: usize) !usize {
    return try sizeOfPackedBinaryHeader(len) + len;
}

pub fn packBinaryHeader(writer: *std.Io.Writer, len: usize) !void {
    if (len <= hdrs.FIXSTR_MAX - hdrs.FIXSTR_MIN) {
        try writer.writeByte(hdrs.FIXSTR_MIN + @as(u8, @intCast(len)));
    } else if (len <= std.math.maxInt(u8)) {
        try writer.writeByte(hdrs.STR8);
        try packIntValue(writer, u8, @intCast(len));
    } else if (len <= std.math.maxInt(u16)) {
        try writer.writeByte(hdrs.STR16);
        try packIntValue(writer, u16, @intCast(len));
    } else if (len <= std.math.maxInt(u32)) {
        try writer.writeByte(hdrs.STR32);
        try packIntValue(writer, u32, @intCast(len));
    } else {
        return error.BinaryTooLong;
    }
}

pub fn unpackBinaryHeader(reader: *std.Io.Reader, comptime MaybeOptionalType: type) !MaybeOptionalType {
    const Type = NonOptional(MaybeOptionalType);
    const header = try reader.takeByte();
    switch (header) {
        hdrs.FIXSTR_MIN...hdrs.FIXSTR_MAX => return try unpackShortIntValue(header, hdrs.FIXSTR_MIN, hdrs.FIXSTR_MAX, Type),
        hdrs.STR8 => return try unpackIntValue(reader, u8, Type),
        hdrs.STR16 => return try unpackIntValue(reader, u16, Type),
        hdrs.STR32 => return try unpackIntValue(reader, u32, Type),
        else => return maybeUnpackNull(header, MaybeOptionalType),
    }
}

pub fn packBinary(writer: *std.Io.Writer, comptime T: type, value_or_maybe_null: T) !void {
    const value = try maybePackNull(writer, T, value_or_maybe_null) orelse return;
    try packBinaryHeader(writer, value.len);
    try writer.writeAll(value);
}

pub fn unpackBinary(reader: *std.Io.Reader, allocator: std.mem.Allocator) ![]u8 {
    const len = try unpackBinaryHeader(reader, u32);

    const data = try allocator.alloc(u8, len);
    errdefer allocator.free(data);

    try reader.readSliceAll(data);
    return data;
}

pub fn unpackBinaryInto(reader: *std.Io.Reader, buf: []u8) ![]u8 {
    const len = try unpackBinaryHeader(reader, u32);

    if (len > buf.len) {
        return error.NoSpaceLeft;
    }

    const data = buf[0..len];
    try reader.readSliceAll(data);
    return data;
}

pub const Binary = struct {
    data: []const u8,

    pub fn msgpackWrite(self: *Binary, packer: anytype) !void {
        try packer.writeBinary(self.data);
    }

    pub fn msgpackRead(unpacker: anytype) !Binary {
        const data = try unpacker.readBinary();
        return Binary{ .data = data };
    }
};

const packed_null = [_]u8{0xc0};
const packed_abc = [_]u8{ 0xa3, 0x61, 0x62, 0x63 };

test "packBinary: abc" {
    var buffer: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packBinary(&writer, []const u8, "abc");
    try std.testing.expectEqualSlices(u8, &packed_abc, writer.buffered());
}

test "unpackBinary: abc" {
    var reader = std.Io.Reader.fixed(&packed_abc);
    const data = try unpackBinary(&reader, std.testing.allocator);
    defer std.testing.allocator.free(data);
    try std.testing.expectEqualSlices(u8, "abc", data);
}

test "packBinary: null" {
    var buffer: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packBinary(&writer, ?[]const u8, null);
    try std.testing.expectEqualSlices(u8, &packed_null, writer.buffered());
}

test "sizeOfPackedBinary" {
    try std.testing.expectEqual(1, sizeOfPackedBinary(0));
}
