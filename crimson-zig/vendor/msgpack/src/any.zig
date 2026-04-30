const std = @import("std");
const hdrs = @import("headers.zig");

const NonOptional = @import("utils.zig").NonOptional;

const packNull = @import("null.zig").packNull;
const unpackNull = @import("null.zig").unpackNull;

const getBoolSize = @import("bool.zig").getBoolSize;
const packBool = @import("bool.zig").packBool;
const unpackBool = @import("bool.zig").unpackBool;

const getIntSize = @import("int.zig").getIntSize;
const packInt = @import("int.zig").packInt;
const unpackInt = @import("int.zig").unpackInt;

const getFloatSize = @import("float.zig").getFloatSize;
const packFloat = @import("float.zig").packFloat;
const unpackFloat = @import("float.zig").unpackFloat;

const sizeOfPackedString = @import("string.zig").sizeOfPackedString;
const packString = @import("string.zig").packString;
const unpackString = @import("string.zig").unpackString;
const String = @import("string.zig").String;

const sizeOfPackedArray = @import("array.zig").sizeOfPackedArray;
const packArray = @import("array.zig").packArray;
const unpackArray = @import("array.zig").unpackArray;

const packStruct = @import("struct.zig").packStruct;
const unpackStruct = @import("struct.zig").unpackStruct;

const packUnion = @import("union.zig").packUnion;
const unpackUnion = @import("union.zig").unpackUnion;

const getEnumSize = @import("enum.zig").getEnumSize;
const packEnum = @import("enum.zig").packEnum;
const unpackEnum = @import("enum.zig").unpackEnum;

inline fn isString(comptime T: type) bool {
    switch (@typeInfo(T)) {
        .pointer => |ptr_info| {
            if (ptr_info.size == .slice) {
                if (ptr_info.child == u8) {
                    return true;
                }
            }
        },
        .optional => |opt_info| {
            return isString(opt_info.child);
        },
        else => {},
    }
    return false;
}

pub fn sizeOfPackedAny(comptime T: type, value: T) usize {
    switch (@typeInfo(NonOptional(T))) {
        .bool => return getBoolSize(),
        .int => return getIntSize(T, value),
        .float => return getFloatSize(T, value),
        .@"enum" => return getEnumSize(T, value),
        .pointer => |ptr_info| {
            if (ptr_info.size == .Slice) {
                if (isString(T)) {
                    return sizeOfPackedString(value.len);
                } else {
                    return sizeOfPackedArray(value.len);
                }
            }
        },
        else => {},
    }
    @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
}

pub fn packAny(writer: *std.Io.Writer, value: anytype) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .void => return packNull(writer),
        .bool => return packBool(writer, value),
        .int => return packInt(writer, T, value),
        .float => return packFloat(writer, T, value),
        .comptime_int => return packInt(writer, i64, @intCast(value)),
        .comptime_float => return packFloat(writer, f64, @floatCast(value)),
        .array => |arr_info| {
            switch (arr_info.child) {
                u8 => {
                    return packString(writer, &value);
                },
                else => {
                    return packArray(writer, []const arr_info.child, &value);
                },
            }
        },
        .pointer => |ptr_info| {
            if (ptr_info.size == .slice) {
                switch (ptr_info.child) {
                    u8 => {
                        return packString(writer, value);
                    },
                    else => {
                        return packArray(writer, T, value);
                    },
                }
            } else if (ptr_info.size == .one) {
                return packAny(writer, value.*);
            }
        },
        .@"struct" => return packStruct(writer, T, value),
        .@"union" => return packUnion(writer, T, value),
        .@"enum" => return packEnum(writer, T, value),
        .optional => {
            if (value) |val| {
                return packAny(writer, val);
            } else {
                return packNull(writer);
            }
        },
        else => {},
    }
    @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
}

pub fn unpackAny(reader: *std.Io.Reader, allocator: std.mem.Allocator, comptime T: type) !T {
    switch (@typeInfo(T)) {
        .void => return unpackNull(reader),
        .bool => return unpackBool(reader, T),
        .int => return unpackInt(reader, T),
        .float => return unpackFloat(reader, T),
        .@"struct" => return unpackStruct(reader, allocator, T),
        .@"union" => return unpackUnion(reader, allocator, T),
        .@"enum" => return unpackEnum(reader, T),
        .pointer => |ptr_info| {
            if (ptr_info.size == .slice) {
                if (isString(T)) {
                    return unpackString(reader, allocator);
                } else {
                    return unpackArray(reader, allocator, T);
                }
            }
        },
        .optional => |opt_info| {
            unpackNull(reader) catch {
                return try unpackAny(reader, allocator, opt_info.child);
            };
            return null;
        },
        else => {},
    }
    @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
}

test "packAny/unpackAny: bool" {
    var buffer: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packAny(&writer, true);

    var reader = std.Io.Reader.fixed(writer.buffered());
    try std.testing.expectEqual(true, try unpackAny(&reader, std.testing.allocator, bool));
}

test "packAny/unpackAny: optional bool" {
    const values = [_]?bool{ true, null };
    for (values) |value| {
        var buffer: [16]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try packAny(&writer, value);

        var reader = std.Io.Reader.fixed(writer.buffered());
        try std.testing.expectEqual(value, try unpackAny(&reader, std.testing.allocator, ?bool));
    }
}

test "packAny/unpackAny: int" {
    var buffer: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packAny(&writer, -42);

    var reader = std.Io.Reader.fixed(writer.buffered());
    try std.testing.expectEqual(-42, try unpackAny(&reader, std.testing.allocator, i32));
}

test "packAny/unpackAny: optional int" {
    const values = [_]?i32{ -42, null };
    for (values) |value| {
        var buffer: [16]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try packAny(&writer, value);

        var reader = std.Io.Reader.fixed(writer.buffered());
        try std.testing.expectEqual(value, try unpackAny(&reader, std.testing.allocator, ?i32));
    }
}

test "packAny/unpackAny: float" {
    var buffer: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packAny(&writer, 3.14);

    var reader = std.Io.Reader.fixed(writer.buffered());
    try std.testing.expectEqual(3.14, try unpackAny(&reader, std.testing.allocator, f32));
}

test "packAny/unpackAny: optional float" {
    const values = [_]?f32{ 3.14, null };
    for (values) |value| {
        var buffer: [16]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try packAny(&writer, value);

        var reader = std.Io.Reader.fixed(writer.buffered());
        try std.testing.expectEqual(value, try unpackAny(&reader, std.testing.allocator, ?f32));
    }
}

test "packAny/unpackAny: string" {
    var buffer: [32]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packAny(&writer, "hello");

    var reader = std.Io.Reader.fixed(writer.buffered());
    const result = try unpackAny(&reader, std.testing.allocator, []const u8);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("hello", result);
}

test "packAny/unpackAny: optional string" {
    const values = [_]?[]const u8{ "hello", null };
    for (values) |value| {
        var buffer: [32]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try packAny(&writer, value);

        var reader = std.Io.Reader.fixed(writer.buffered());
        const result = try unpackAny(&reader, std.testing.allocator, ?[]const u8);
        defer if (result) |str| std.testing.allocator.free(str);
        if (value) |str| {
            try std.testing.expectEqualStrings(str, result.?);
        } else {
            try std.testing.expectEqual(value, result);
        }
    }
}

test "packAny/unpackAny: array" {
    var buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const array = [_]i32{ 1, 2, 3, 4, 5 };
    try packAny(&writer, &array);

    var reader = std.Io.Reader.fixed(writer.buffered());
    const result = try unpackAny(&reader, std.testing.allocator, []const i32);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualSlices(i32, &array, result);
}

test "packAny/unpackAny: optional array" {
    const array = [_]i32{ 1, 2, 3, 4, 5 };
    const values = [_]?[]const i32{ &array, null };
    for (values) |value| {
        var buffer: [64]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try packAny(&writer, value);

        var reader = std.Io.Reader.fixed(writer.buffered());
        const result = try unpackAny(&reader, std.testing.allocator, ?[]const i32);
        defer if (result) |arr| std.testing.allocator.free(arr);
        if (value) |arr| {
            try std.testing.expectEqualSlices(i32, arr, result.?);
        } else {
            try std.testing.expectEqual(value, result);
        }
    }
}

test "packAny/unpackAny: struct" {
    const Point = struct {
        x: i32,
        y: i32,
    };
    var buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const point = Point{ .x = 10, .y = 20 };
    try packAny(&writer, point);

    var reader = std.Io.Reader.fixed(writer.buffered());
    const result = try unpackAny(&reader, std.testing.allocator, Point);
    try std.testing.expectEqualDeep(point, result);
}

test "packAny/unpackAny: optional struct" {
    const Point = struct {
        x: i32,
        y: i32,
    };
    const point = Point{ .x = 10, .y = 20 };
    const values = [_]?Point{ point, null };
    for (values) |value| {
        var buffer: [64]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try packAny(&writer, value);

        var reader = std.Io.Reader.fixed(writer.buffered());
        const result = try unpackAny(&reader, std.testing.allocator, ?Point);
        try std.testing.expectEqualDeep(value, result);
    }
}

test "packAny/unpackAny: union" {
    const Value = union(enum) {
        int: i32,
        float: f32,
    };

    const values = [_]Value{
        Value{ .int = 42 },
        Value{ .float = 3.14 },
    };

    for (values) |value| {
        var buffer: [64]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try packAny(&writer, value);

        var reader = std.Io.Reader.fixed(writer.buffered());
        const result = try unpackAny(&reader, std.testing.allocator, Value);
        try std.testing.expectEqualDeep(value, result);
    }
}

test "packAny/unpackAny: optional union" {
    const Value = union(enum) {
        int: i32,
        float: f32,
    };

    const values = [_]?Value{
        Value{ .int = 42 },
        Value{ .float = 3.14 },
        null,
    };

    for (values) |value| {
        var buffer: [64]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try packAny(&writer, value);

        var reader = std.Io.Reader.fixed(writer.buffered());
        const result = try unpackAny(&reader, std.testing.allocator, ?Value);
        try std.testing.expectEqualDeep(value, result);
    }
}

test "packAny/unpackAny: String struct" {
    var buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const str = String{ .data = "hello" };
    try packAny(&writer, str);

    var reader = std.Io.Reader.fixed(writer.buffered());
    const result = try unpackAny(&reader, std.testing.allocator, String);
    defer std.testing.allocator.free(result.data);
    try std.testing.expectEqualStrings("hello", result.data);
}

test "packAny/unpackAny: Binary struct" {
    var buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const str = String{ .data = "\x01\x02\x03\x04" };
    try packAny(&writer, str);

    var reader = std.Io.Reader.fixed(writer.buffered());
    const result = try unpackAny(&reader, std.testing.allocator, String);
    defer std.testing.allocator.free(result.data);
    try std.testing.expectEqualStrings("\x01\x02\x03\x04", result.data);
}
