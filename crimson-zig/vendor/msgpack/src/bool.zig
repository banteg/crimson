const std = @import("std");
const hdrs = @import("headers.zig");

const maybePackNull = @import("null.zig").maybePackNull;
const maybeUnpackNull = @import("null.zig").maybeUnpackNull;

pub fn getBoolSize() usize {
    return 1;
}

inline fn forceBoolType(value: anytype) type {
    const T = @TypeOf(value);
    if (@typeInfo(T) == .null) {
        return ?bool;
    }
    assertBoolType(T);
    return T;
}

inline fn assertBoolType(T: type) void {
    switch (@typeInfo(T)) {
        .bool => return,
        .optional => |opt_info| {
            return assertBoolType(opt_info.child);
        },
        else => @compileError("Expected bool, got " ++ @typeName(T)),
    }
}

pub fn packBool(writer: *std.Io.Writer, value_or_maybe_null: anytype) !void {
    const T = forceBoolType(value_or_maybe_null);
    const value = try maybePackNull(writer, T, value_or_maybe_null) orelse return;

    try writer.writeByte(if (value) hdrs.TRUE else hdrs.FALSE);
}

pub fn unpackBool(reader: *std.Io.Reader, comptime T: type) !T {
    assertBoolType(T);
    const header = try reader.takeByte();
    switch (header) {
        hdrs.TRUE => return true,
        hdrs.FALSE => return false,
        else => return maybeUnpackNull(header, T),
    }
}

const packed_null = [_]u8{0xc0};
const packed_true = [_]u8{0xc3};
const packed_false = [_]u8{0xc2};
const packed_zero = [_]u8{0x00};

test "packBool: false" {
    var buffer: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packBool(&writer, false);
    try std.testing.expectEqualSlices(u8, &packed_false, writer.buffered());
}

test "packBool: true" {
    var buffer: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packBool(&writer, true);
    try std.testing.expectEqualSlices(u8, &packed_true, writer.buffered());
}

test "packBool: null" {
    var buffer: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packBool(&writer, null);
    try std.testing.expectEqualSlices(u8, &packed_null, writer.buffered());
}

test "unpackBool: false" {
    var reader = std.Io.Reader.fixed(&packed_false);
    try std.testing.expectEqual(false, try unpackBool(&reader, bool));
}

test "unpackBool: true" {
    var reader = std.Io.Reader.fixed(&packed_true);
    try std.testing.expectEqual(true, try unpackBool(&reader, bool));
}

test "unpackBool: null into optional" {
    var reader = std.Io.Reader.fixed(&packed_null);
    try std.testing.expectEqual(null, try unpackBool(&reader, ?bool));
}

test "unpackBool: null into non-optional" {
    var reader = std.Io.Reader.fixed(&packed_null);
    try std.testing.expectError(error.Null, unpackBool(&reader, bool));
}

test "unpackBool: wrong type" {
    var reader = std.Io.Reader.fixed(&packed_zero);
    try std.testing.expectError(error.InvalidFormat, unpackBool(&reader, bool));
}

test "getBoolSize" {
    try std.testing.expectEqual(1, getBoolSize());
}
