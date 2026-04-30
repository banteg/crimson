const std = @import("std");

const maybePackNull = @import("null.zig").maybePackNull;

const getIntSize = @import("int.zig").getIntSize;
const packInt = @import("int.zig").packInt;
const unpackInt = @import("int.zig").unpackInt;

inline fn assertEnumType(comptime T: type) type {
    switch (@typeInfo(T)) {
        .@"enum" => return T,
        .optional => |opt_info| {
            return assertEnumType(opt_info.child);
        },
        else => @compileError("Expected enum, got " ++ @typeName(T)),
    }
}

pub fn getMaxEnumSize(comptime T: type) usize {
    const Type = assertEnumType(T);
    const tag_type = @typeInfo(Type).@"enum".tag_type;
    return 1 + @sizeOf(tag_type);
}

pub fn getEnumSize(comptime T: type, value: T) usize {
    if (@typeInfo(T) == .optional) {
        if (value) |v| {
            return getEnumSize(@typeInfo(T).optional.child, v);
        } else {
            return 1; // size of null
        }
    }

    const tag_type = @typeInfo(T).@"enum".tag_type;
    const int_value = @intFromEnum(value);
    return getIntSize(tag_type, int_value);
}

pub fn packEnum(writer: *std.Io.Writer, comptime T: type, value_or_maybe_null: T) !void {
    const Type = assertEnumType(T);
    const value: Type = try maybePackNull(writer, T, value_or_maybe_null) orelse return;

    const tag_type = @typeInfo(Type).@"enum".tag_type;
    const int_value = @intFromEnum(value);

    try packInt(writer, tag_type, int_value);
}

pub fn unpackEnum(reader: *std.Io.Reader, comptime T: type) !T {
    const Type = assertEnumType(T);
    const tag_type = @typeInfo(Type).@"enum".tag_type;

    // Construct the optional tag type to match T's optionality
    const OptionalTagType = if (@typeInfo(T) == .optional) ?tag_type else tag_type;

    // Use unpackInt directly with the constructed optional tag type
    const int_value = try unpackInt(reader, OptionalTagType);

    // Handle the optional case
    if (@typeInfo(T) == .optional) {
        if (int_value) |value| {
            return @enumFromInt(value);
        } else {
            return null;
        }
    } else {
        return @enumFromInt(int_value);
    }
}

test "getMaxEnumSize" {
    const PlainEnum = enum { foo, bar };
    const U8Enum = enum(u8) { foo = 1, bar = 2 };
    const U16Enum = enum(u16) { foo, bar };

    try std.testing.expectEqual(2, getMaxEnumSize(PlainEnum)); // u1 + header
    try std.testing.expectEqual(2, getMaxEnumSize(U8Enum)); // u8 + header
    try std.testing.expectEqual(3, getMaxEnumSize(U16Enum)); // u16 + header
}

test "getEnumSize" {
    const U8Enum = enum(u8) { foo = 0, bar = 150 };

    try std.testing.expectEqual(1, getEnumSize(U8Enum, .foo)); // fits in positive fixint
    try std.testing.expectEqual(2, getEnumSize(U8Enum, .bar)); // requires u8 format
}

test "pack/unpack enum" {
    const PlainEnum = enum { foo, bar };
    const U8Enum = enum(u8) { foo = 1, bar = 2 };
    const U16Enum = enum(u16) { alpha = 1000, beta = 2000 };

    // Test plain enum
    {
        var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer aw.deinit();

        try packEnum(&aw.writer, PlainEnum, .bar);

        var reader = std.Io.Reader.fixed(aw.written());
        const result = try unpackEnum(&reader, PlainEnum);
        try std.testing.expectEqual(PlainEnum.bar, result);
    }

    // Test enum(u8)
    {
        var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer aw.deinit();

        try packEnum(&aw.writer, U8Enum, .bar);

        var reader = std.Io.Reader.fixed(aw.written());
        const result = try unpackEnum(&reader, U8Enum);
        try std.testing.expectEqual(U8Enum.bar, result);
    }

    // Test enum(u16)
    {
        var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer aw.deinit();

        try packEnum(&aw.writer, U16Enum, .alpha);

        var reader = std.Io.Reader.fixed(aw.written());
        const result = try unpackEnum(&reader, U16Enum);
        try std.testing.expectEqual(U16Enum.alpha, result);
    }
}

test "enum edge cases" {
    // Test enum with explicit and auto values
    const MixedEnum = enum(u8) {
        first = 10,
        second, // auto-assigned to 11
        third = 20,
        fourth, // auto-assigned to 21
    };

    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();

    try packEnum(&aw.writer, MixedEnum, .second);

    var reader = std.Io.Reader.fixed(aw.written());
    const result = try unpackEnum(&reader, MixedEnum);
    try std.testing.expectEqual(MixedEnum.second, result);
    try std.testing.expectEqual(11, @intFromEnum(result));
}

test "optional enum" {
    const TestEnum = enum(u8) { foo = 1, bar = 2 };
    const OptionalEnum = ?TestEnum;

    // Test non-null optional enum
    {
        var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer aw.deinit();

        const value: OptionalEnum = .bar;
        try packEnum(&aw.writer, OptionalEnum, value);

        var reader = std.Io.Reader.fixed(aw.written());
        const result = try unpackEnum(&reader, OptionalEnum);
        try std.testing.expectEqual(@as(OptionalEnum, .bar), result);
    }

    // Test null optional enum
    {
        var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer aw.deinit();

        const value: OptionalEnum = null;
        try packEnum(&aw.writer, OptionalEnum, value);

        var reader = std.Io.Reader.fixed(aw.written());
        const result = try unpackEnum(&reader, OptionalEnum);
        try std.testing.expectEqual(@as(OptionalEnum, null), result);
    }
}

test "getEnumSize with optional" {
    const TestEnum = enum(u8) { foo = 0, bar = 150 };
    const OptionalEnum = ?TestEnum;

    // Test non-null optional enum size
    const value: OptionalEnum = .bar;
    try std.testing.expectEqual(2, getEnumSize(OptionalEnum, value)); // requires u8 format

    // Test null optional enum size
    const null_value: OptionalEnum = null;
    try std.testing.expectEqual(1, getEnumSize(OptionalEnum, null_value)); // size of null
}
