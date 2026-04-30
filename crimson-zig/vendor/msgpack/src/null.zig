const std = @import("std");
const hdrs = @import("headers.zig");

const isOptional = @import("utils.zig").isOptional;
const NonOptional = @import("utils.zig").NonOptional;

pub fn getNullSize() usize {
    return 1;
}

pub fn packNull(writer: *std.Io.Writer) !void {
    try writer.writeByte(hdrs.NIL);
}

pub fn unpackNull(reader: *std.Io.Reader) !void {
    const header = try reader.peekByte();
    if (header == hdrs.NIL) {
        reader.toss(1);
        return;
    }
    return error.InvalidFormat;
}

pub fn maybePackNull(writer: *std.Io.Writer, comptime T: type, value: T) !?NonOptional(T) {
    if (@typeInfo(T) == .optional) {
        if (value == null) {
            try packNull(writer);
            return null;
        } else {
            return value;
        }
    }
    return value;
}

pub fn maybeUnpackNull(header: u8, comptime T: type) !T {
    switch (header) {
        hdrs.NIL => return if (isOptional(T)) null else error.Null,
        else => return error.InvalidFormat,
    }
}

const packed_null = [_]u8{0xc0};
const packed_zero = [_]u8{0x00};

test "packNull" {
    var buffer: [100]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packNull(&writer);
    try std.testing.expectEqualSlices(u8, &packed_null, writer.buffered());
}

test "unpackNull" {
    var reader = std.Io.Reader.fixed(&packed_null);
    try unpackNull(&reader);
}

test "unpackNull: wrong data" {
    var reader = std.Io.Reader.fixed(&packed_zero);
    try std.testing.expectError(error.InvalidFormat, unpackNull(&reader));
}

test "getMaxNullSize/getNullSize" {
    try std.testing.expectEqual(1, getNullSize());
}
