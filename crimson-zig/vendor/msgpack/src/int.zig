const std = @import("std");
const hdrs = @import("headers.zig");

const NonOptional = @import("utils.zig").NonOptional;
const maybePackNull = @import("null.zig").maybePackNull;
const maybeUnpackNull = @import("null.zig").maybeUnpackNull;

inline fn assertIntType(comptime T: type) type {
    switch (@typeInfo(T)) {
        .int => return T,
        .optional => |opt_info| {
            return assertIntType(opt_info.child);
        },
        else => @compileError("Expected int, got " ++ @typeName(T)),
    }
}

pub fn getMaxIntSize(comptime T: type) usize {
    const Type = assertIntType(T);
    return 1 + @sizeOf(Type);
}

pub fn getIntSize(comptime T: type, value: T) usize {
    const Type = assertIntType(T);
    const type_info = @typeInfo(Type);

    const is_signed = type_info.int.signedness == .signed;
    const bits = type_info.int.bits;

    if (is_signed) {
        if (value >= -32 and value <= -1) {
            return 1;
        } else if (value >= 0 and value <= 127) {
            return 1;
        }
        if (bits == 8 or value >= std.math.minInt(i8) and value <= std.math.maxInt(i8)) {
            return 1 + @sizeOf(i8);
        }
        if (bits == 16 or value >= std.math.minInt(i16) and value <= std.math.maxInt(i16)) {
            return 1 + @sizeOf(i16);
        }
        if (bits == 32 or value >= std.math.minInt(i32) and value <= std.math.maxInt(i32)) {
            return 1 + @sizeOf(i32);
        }
        if (bits == 64 or value >= std.math.minInt(i64) and value <= std.math.maxInt(i64)) {
            return 1 + @sizeOf(i64);
        }
        @compileError("Unsupported signed int with " ++ type_info.int.bits ++ "bits");
    } else {
        if (value <= 127) {
            return 1;
        }
        if (bits == 8 or value <= std.math.maxInt(u8)) {
            return 1 + @sizeOf(u8);
        }
        if (bits == 16 or value <= std.math.maxInt(u16)) {
            return 1 + @sizeOf(u16);
        }
        if (bits == 32 or value <= std.math.maxInt(u32)) {
            return 1 + @sizeOf(u32);
        }
        if (bits == 64 or value <= std.math.maxInt(u64)) {
            return 1 + @sizeOf(u64);
        }
        @compileError("Unsupported integer size of " ++ bits ++ "bits");
    }
}

pub fn packIntValue(writer: *std.Io.Writer, comptime T: type, value: T) !void {
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, buf[0..], value, .big);
    try writer.writeAll(buf[0..]);
}

pub fn packInt(writer: *std.Io.Writer, comptime T: type, value_or_maybe_null: T) !void {
    const Type = assertIntType(T);
    const value: Type = try maybePackNull(writer, T, value_or_maybe_null) orelse return;

    const type_info = @typeInfo(Type);
    const is_signed = type_info.int.signedness == .signed;
    const bits = type_info.int.bits;

    if (is_signed) {
        if (value >= -32 and value <= -1) {
            try writer.writeByte(@bitCast(@as(i8, @intCast(value))));
            return;
        } else if (value >= 0 and value <= 127) {
            try writer.writeByte(@bitCast(@as(u8, @intCast(value))));
            return;
        }
        if (bits == 8 or value >= std.math.minInt(i8) and value <= std.math.maxInt(i8)) {
            return packFixedSizeInt(writer, i8, @intCast(value));
        }
        if (bits == 16 or value >= std.math.minInt(i16) and value <= std.math.maxInt(i16)) {
            return packFixedSizeInt(writer, i16, @intCast(value));
        }
        if (bits == 32 or value >= std.math.minInt(i32) and value <= std.math.maxInt(i32)) {
            return packFixedSizeInt(writer, i32, @intCast(value));
        }
        if (bits == 64 or value >= std.math.minInt(i64) and value <= std.math.maxInt(i64)) {
            return packFixedSizeInt(writer, i64, @intCast(value));
        }
        @compileError("Unsupported signed int with " ++ type_info.int.bits ++ "bits");
    } else {
        if (value <= 127) {
            return writer.writeByte(@bitCast(@as(u8, @intCast(value))));
        }
        if (bits == 8 or value <= std.math.maxInt(u8)) {
            return packFixedSizeInt(writer, u8, @intCast(value));
        }
        if (bits == 16 or value <= std.math.maxInt(u16)) {
            return packFixedSizeInt(writer, u16, @intCast(value));
        }
        if (bits == 32 or value <= std.math.maxInt(u32)) {
            return packFixedSizeInt(writer, u32, @intCast(value));
        }
        if (bits == 64 or value <= std.math.maxInt(u64)) {
            return packFixedSizeInt(writer, u64, @intCast(value));
        }
        @compileError("Unsupported integer size of " ++ bits ++ "bits");
    }
}

pub fn packFixedSizeInt(writer: *std.Io.Writer, comptime T: type, value: T) !void {
    try writer.writeByte(resolveFixedSizeIntHeader(T));
    try packIntValue(writer, T, value);
}

inline fn resolveFixedSizeIntHeader(comptime T: type) u8 {
    const type_info = @typeInfo(T);
    switch (type_info.int.signedness) {
        .signed => {
            switch (type_info.int.bits) {
                8 => return hdrs.INT8,
                16 => return hdrs.INT16,
                32 => return hdrs.INT32,
                64 => return hdrs.INT64,
                else => @compileError("Unsupported signed int with " ++ type_info.int.bits ++ "bits"),
            }
        },
        .unsigned => {
            switch (type_info.int.bits) {
                8 => return hdrs.UINT8,
                16 => return hdrs.UINT16,
                32 => return hdrs.UINT32,
                64 => return hdrs.UINT64,
                else => @compileError("Unsupported unsigned int with " ++ type_info.int.bits ++ "bits"),
            }
        },
    }
}

pub fn unpackShortIntValue(header: u8, min_value: u8, max_value: u8, comptime TargetType: type) !TargetType {
    std.debug.assert(header >= min_value and header <= max_value);
    const value = header - min_value;

    if (value >= std.math.minInt(TargetType) and value <= std.math.maxInt(TargetType)) {
        return @intCast(value);
    }
    return error.IntegerOverflow;
}

pub fn unpackIntValue(reader: *std.Io.Reader, comptime SourceType: type, comptime TargetType: type) !TargetType {
    const size = @divExact(@bitSizeOf(SourceType), 8);
    var buf: [size]u8 = undefined;
    try reader.readSliceAll(&buf);
    const value = std.mem.readInt(SourceType, &buf, .big);

    const source_type_info = @typeInfo(SourceType).int;
    const target_type_info = @typeInfo(TargetType).int;

    if (source_type_info.signedness == target_type_info.signedness and source_type_info.bits <= target_type_info.bits) {
        return @intCast(value);
    }
    if (value >= std.math.minInt(TargetType) and value <= std.math.maxInt(TargetType)) {
        return @intCast(value);
    }
    return error.IntegerOverflow;
}

pub fn unpackInt(reader: *std.Io.Reader, comptime T: type) !T {
    const Type = assertIntType(T);
    const type_info = @typeInfo(Type);

    const header = try reader.takeByte();

    if (header <= hdrs.POSITIVE_FIXINT_MAX) {
        return @intCast(header);
    }

    if (header >= hdrs.NEGATIVE_FIXINT_MIN) {
        const value: i8 = @bitCast(header);
        if (type_info.int.signedness == .signed) {
            return value;
        } else if (value >= 0) {
            return @intCast(value);
        }
        return error.IntegerOverflow;
    }

    switch (header) {
        hdrs.INT8 => return try unpackIntValue(reader, i8, Type),
        hdrs.INT16 => return try unpackIntValue(reader, i16, Type),
        hdrs.INT32 => return try unpackIntValue(reader, i32, Type),
        hdrs.INT64 => return try unpackIntValue(reader, i64, Type),
        hdrs.UINT8 => return try unpackIntValue(reader, u8, Type),
        hdrs.UINT16 => return try unpackIntValue(reader, u16, Type),
        hdrs.UINT32 => return try unpackIntValue(reader, u32, Type),
        hdrs.UINT64 => return try unpackIntValue(reader, u64, Type),
        else => return maybeUnpackNull(header, T),
    }
}

const int_types = [_]type{ i8, i16, i32, i64, u8, u16, u32, u64 };

fn expectIntOrOverflow(comptime T: type, expected: anytype, reader: *std.Io.Reader, comptime should_fit: bool) !void {
    if (should_fit) {
        try std.testing.expectEqual(expected, try unpackInt(reader, T));
    } else {
        try std.testing.expectError(error.IntegerOverflow, unpackInt(reader, T));
    }
}

test "readInt: null" {
    const buffer = [_]u8{0xc0};
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        try std.testing.expectEqual(null, try unpackInt(&reader, ?T));
    }
}

test "readInt: positive fixint" {
    const buffer = [_]u8{0x7f};
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        try std.testing.expectEqual(127, try unpackInt(&reader, T));
    }
}

test "readInt: negative fixint" {
    const buffer = [_]u8{0xe0};
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        if (info.signedness == .unsigned) {
            try std.testing.expectError(error.IntegerOverflow, unpackInt(&reader, T));
        } else {
            try std.testing.expectEqual(-32, try unpackInt(&reader, T));
        }
    }
}

test "readInt: uint8" {
    const buffer = [_]u8{ 0xcc, 0xff };
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        const fits = info.bits >= 8 and !(info.bits == 8 and info.signedness == .signed);
        try expectIntOrOverflow(T, 0xff, &reader, fits);
    }
}

test "readInt: uint16" {
    const buffer = [_]u8{ 0xcd, 0xff, 0xff };
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        if (info.bits < 16 or (info.bits == 16 and info.signedness == .signed)) {
            try std.testing.expectError(error.IntegerOverflow, unpackInt(&reader, T));
        } else {
            try std.testing.expectEqual(0xffff, try unpackInt(&reader, T));
        }
    }
}

test "readInt: uint32" {
    const buffer = [_]u8{ 0xce, 0xff, 0xff, 0xff, 0xff };
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        if (info.bits < 32 or (info.bits == 32 and info.signedness == .signed)) {
            try std.testing.expectError(error.IntegerOverflow, unpackInt(&reader, T));
        } else {
            try std.testing.expectEqual(0xffffffff, try unpackInt(&reader, T));
        }
    }
}

test "readInt: uint64" {
    const buffer = [_]u8{ 0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        if (info.bits < 64 or (info.bits == 64 and info.signedness == .signed)) {
            try std.testing.expectError(error.IntegerOverflow, unpackInt(&reader, T));
        } else {
            try std.testing.expectEqual(0xffffffffffffffff, try unpackInt(&reader, T));
        }
    }
}

test "readInt: negative int8" {
    const buffer = [_]u8{ 0xd0, 0x80 };
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        if (info.signedness == .unsigned or info.bits < 8) {
            try std.testing.expectError(error.IntegerOverflow, unpackInt(&reader, T));
        } else {
            try std.testing.expectEqual(-128, try unpackInt(&reader, T));
        }
    }
}

test "readInt: positive int8" {
    const buffer = [_]u8{ 0xd0, 0x7f };
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        if (info.bits < 7) {
            try std.testing.expectError(error.IntegerOverflow, unpackInt(&reader, T));
        } else {
            try std.testing.expectEqual(127, try unpackInt(&reader, T));
        }
    }
}

test "readInt: negative int16" {
    const buffer = [_]u8{ 0xd1, 0x80, 0x00 };
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        if (info.signedness == .unsigned or info.bits < 16) {
            try std.testing.expectError(error.IntegerOverflow, unpackInt(&reader, T));
        } else {
            try std.testing.expectEqual(-32768, try unpackInt(&reader, T));
        }
    }
}

test "readInt: positive int16" {
    const buffer = [_]u8{ 0xd1, 0x7f, 0xff };
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        if (info.bits < 15) {
            try std.testing.expectError(error.IntegerOverflow, unpackInt(&reader, T));
        } else {
            try std.testing.expectEqual(32767, try unpackInt(&reader, T));
        }
    }
}

test "readInt: negative int32" {
    const buffer = [_]u8{ 0xd2, 0x80, 0x00, 0x00, 0x00 };
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        if (info.signedness == .unsigned or info.bits < 32) {
            try std.testing.expectError(error.IntegerOverflow, unpackInt(&reader, T));
        } else {
            try std.testing.expectEqual(-2147483648, try unpackInt(&reader, T));
        }
    }
}

test "readInt: positive int32" {
    const buffer = [_]u8{ 0xd2, 0x7f, 0xff, 0xff, 0xff };
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        if (info.bits < 31) {
            try std.testing.expectError(error.IntegerOverflow, unpackInt(&reader, T));
        } else {
            try std.testing.expectEqual(2147483647, try unpackInt(&reader, T));
        }
    }
}

test "readInt: negative int64" {
    const buffer = [_]u8{ 0xd3, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        if (info.signedness == .unsigned or info.bits < 64) {
            try std.testing.expectError(error.IntegerOverflow, unpackInt(&reader, T));
        } else {
            try std.testing.expectEqual(-9223372036854775808, try unpackInt(&reader, T));
        }
    }
}

test "readInt: positive int64" {
    const buffer = [_]u8{ 0xd3, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    inline for (int_types) |T| {
        var reader = std.Io.Reader.fixed(&buffer);
        const info = @typeInfo(T).int;
        if (info.bits < 63) {
            try std.testing.expectError(error.IntegerOverflow, unpackInt(&reader, T));
        } else {
            try std.testing.expectEqual(9223372036854775807, try unpackInt(&reader, T));
        }
    }
}

test "writeInt: positive fixint" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        var writer = std.Io.Writer.fixed(&buffer);
        try packInt(&writer, T, 127);
        try std.testing.expectEqualSlices(u8, &.{0x7f}, writer.buffered());
    }
}

test "writeInt: negative fixint" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .signed) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, -32);
            try std.testing.expectEqualSlices(u8, &.{0xE0}, writer.buffered());
        }
    }
}

test "writeInt: uint8" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .unsigned and info.bits >= 8) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, 200);
            try std.testing.expectEqualSlices(u8, &.{ 0xcc, 200 }, writer.buffered());
        }
    }
}

test "writeInt: uint16" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .unsigned and info.bits >= 16) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, 40000);
            try std.testing.expectEqualSlices(u8, &.{ 0xcd, 0x9c, 0x40 }, writer.buffered());
        }
    }
}

test "writeInt: uint32" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .unsigned and info.bits >= 32) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, 3000000000);
            try std.testing.expectEqualSlices(u8, &.{ 0xce, 0xb2, 0xd0, 0x5e, 0x00 }, writer.buffered());
        }
    }
}

test "writeInt: uint64" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .unsigned and info.bits >= 64) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, 9000000000000000000);
            try std.testing.expectEqualSlices(u8, &.{ 0xcf, 0x7c, 0xe6, 0x6c, 0x50, 0xe2, 0x84, 0x0, 0x0 }, writer.buffered());
        }
    }
}

test "writeInt: positive int8" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .signed and info.bits > 8) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, 100);
            try std.testing.expectEqualSlices(u8, &.{100}, writer.buffered());
        }
    }
}

test "writeInt: negative int8" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .signed and info.bits >= 8) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, -100);
            try std.testing.expectEqualSlices(u8, &.{ 0xd0, 156 }, writer.buffered());
        }
    }
}

test "writeInt: positive int16" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .signed and info.bits >= 16) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, 20000);
            try std.testing.expectEqualSlices(u8, &.{ 0xd1, 0x4e, 0x20 }, writer.buffered());
        }
    }
}

test "writeInt: negative int16" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .signed and info.bits >= 16) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, -20000);
            try std.testing.expectEqualSlices(u8, &.{ 0xd1, 0xb1, 0xe0 }, writer.buffered());
        }
    }
}

test "writeInt: positive int32" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .signed and info.bits >= 32) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, 2000000000);
            try std.testing.expectEqualSlices(u8, &.{ 0xd2, 0x77, 0x35, 0x94, 0x0 }, writer.buffered());
        }
    }
}

test "writeInt: negative int32" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .signed and info.bits >= 32) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, -2000000000);
            try std.testing.expectEqualSlices(u8, &.{ 0xd2, 0x88, 0xca, 0x6c, 0x00 }, writer.buffered());
        }
    }
}

test "writeInt: positive int64" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .signed and info.bits >= 64) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, 8000000000000000000);
            try std.testing.expectEqualSlices(u8, &.{ 0xd3, 0x6f, 0x5, 0xb5, 0x9d, 0x3b, 0x20, 0x0, 0x0 }, writer.buffered());
        }
    }
}

test "writeInt: negative int64" {
    var buffer: [100]u8 = undefined;
    inline for (int_types) |T| {
        const info = @typeInfo(T).int;
        if (info.signedness == .signed and info.bits >= 64) {
            var writer = std.Io.Writer.fixed(&buffer);
            try packInt(&writer, T, -9000000000000000000);
            try std.testing.expectEqualSlices(u8, &.{ 0xd3, 0x83, 0x19, 0x93, 0xaf, 0x1d, 0x7c, 0x0, 0x0 }, writer.buffered());
        }
    }
}

test "getMaxIntSize" {
    try std.testing.expectEqual(2, getMaxIntSize(u8));
    try std.testing.expectEqual(3, getMaxIntSize(u16));
    try std.testing.expectEqual(5, getMaxIntSize(u32));
    try std.testing.expectEqual(9, getMaxIntSize(u64));
}

test "getIntSize" {
    try std.testing.expectEqual(1, getIntSize(u8, 0));
    try std.testing.expectEqual(2, getIntSize(u8, 150));
    try std.testing.expectEqual(1, getIntSize(u16, 0));
    try std.testing.expectEqual(2, getIntSize(u16, 150));
    try std.testing.expectEqual(1, getIntSize(u16, 0));
    try std.testing.expectEqual(2, getIntSize(u16, 150));
    try std.testing.expectEqual(3, getIntSize(u16, 15000));
    try std.testing.expectEqual(1, getIntSize(u32, 0));
    try std.testing.expectEqual(2, getIntSize(u32, 150));
    try std.testing.expectEqual(3, getIntSize(u32, 15000));
    try std.testing.expectEqual(5, getIntSize(u32, 1500000));
    try std.testing.expectEqual(1, getIntSize(u64, 0));
    try std.testing.expectEqual(2, getIntSize(u64, 150));
    try std.testing.expectEqual(3, getIntSize(u64, 15000));
    try std.testing.expectEqual(5, getIntSize(u64, 1500000));
    try std.testing.expectEqual(9, getIntSize(u64, 15000000000000000));
}
