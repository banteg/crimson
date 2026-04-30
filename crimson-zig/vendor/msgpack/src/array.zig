const std = @import("std");
const hdrs = @import("headers.zig");

const NonOptional = @import("utils.zig").NonOptional;
const isOptional = @import("utils.zig").isOptional;

const maybePackNull = @import("null.zig").maybePackNull;
const maybeUnpackNull = @import("null.zig").maybeUnpackNull;

const packIntValue = @import("int.zig").packIntValue;
const unpackIntValue = @import("int.zig").unpackIntValue;

const packAny = @import("any.zig").packAny;
const unpackAny = @import("any.zig").unpackAny;

pub fn sizeOfPackedArrayHeader(len: usize) !usize {
    if (len <= hdrs.FIXARRAY_MAX - hdrs.FIXARRAY_MIN) {
        return 1;
    } else if (len <= std.math.maxInt(u8)) {
        return 1 + @sizeOf(u8);
    } else if (len <= std.math.maxInt(u16)) {
        return 1 + @sizeOf(u16);
    } else if (len <= std.math.maxInt(u32)) {
        return 1 + @sizeOf(u32);
    } else {
        return error.ArrayTooLong;
    }
}

pub fn sizeOfPackedArray(len: usize) !usize {
    return try sizeOfPackedArrayHeader(len) + len;
}

pub fn packArrayHeader(writer: *std.Io.Writer, len: usize) !void {
    if (len <= hdrs.FIXARRAY_MAX - hdrs.FIXARRAY_MIN) {
        try writer.writeByte(hdrs.FIXARRAY_MIN + @as(u8, @intCast(len)));
    } else if (len <= std.math.maxInt(u16)) {
        try writer.writeByte(hdrs.ARRAY16);
        try packIntValue(writer, u16, @intCast(len));
    } else if (len <= std.math.maxInt(u32)) {
        try writer.writeByte(hdrs.ARRAY32);
        try packIntValue(writer, u32, @intCast(len));
    } else {
        return error.ArrayTooLong;
    }
}

pub fn unpackArrayHeader(reader: *std.Io.Reader, comptime T: type) !T {
    const header = try reader.takeByte();
    switch (header) {
        hdrs.FIXARRAY_MIN...hdrs.FIXARRAY_MAX => {
            return header - hdrs.FIXARRAY_MIN;
        },
        hdrs.ARRAY16 => {
            return try unpackIntValue(reader, u16, NonOptional(T));
        },
        hdrs.ARRAY32 => {
            return try unpackIntValue(reader, u32, NonOptional(T));
        },
        else => {
            return maybeUnpackNull(header, T);
        },
    }
}

pub fn packArray(writer: *std.Io.Writer, comptime T: type, value_or_maybe_null: T) !void {
    const value = try maybePackNull(writer, T, value_or_maybe_null) orelse return;
    try packArrayHeader(writer, value.len);

    for (value) |item| {
        try packAny(writer, item);
    }
}

pub fn unpackArray(reader: *std.Io.Reader, allocator: std.mem.Allocator, comptime T: type) !T {
    const len = if (isOptional(T))
        try unpackArrayHeader(reader, ?u32) orelse return null
    else
        try unpackArrayHeader(reader, u32);

    const Item = std.meta.Child(NonOptional(T));

    const data = try allocator.alloc(Item, len);
    errdefer allocator.free(data);

    for (0..len) |i| {
        data[i] = try unpackAny(reader, allocator, Item);
    }

    return data;
}

pub fn unpackArrayInto(reader: *std.Io.Reader, allocator: std.mem.Allocator, comptime Item: type, buffer: []Item) ![]Item {
    const len = try unpackArrayHeader(reader, u32);

    if (buffer.len < len) {
        return error.NoSpaceLeft;
    }

    const data = buffer[0..len];

    for (0..len) |i| {
        data[i] = try unpackAny(reader, allocator, Item);
    }

    return data;
}

pub fn Array(comptime T: type) type {
    return struct {
        data: []T,

        pub fn msgpackWrite(self: @This(), packer: anytype) !void {
            try packer.writeArray(self.data);
        }

        pub fn msgpackRead(unpacker: anytype) !@This() {
            const data = try unpacker.readArray([]T);
            return .{ .data = data };
        }
    };
}

const packed_null = [_]u8{0xc0};
const packed_abc = [_]u8{ 0x93, 0x61, 0x62, 0x63 };

test "packArray: abc" {
    var buffer: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packArray(&writer, []const u8, "abc");
    try std.testing.expectEqualSlices(u8, &packed_abc, writer.buffered());
}

test "packArray: null" {
    var buffer: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packArray(&writer, ?[]const u8, null);
    try std.testing.expectEqualSlices(u8, &packed_null, writer.buffered());
}

test "sizeOfPackedArray" {
    try std.testing.expectEqual(1, sizeOfPackedArray(0));
}
