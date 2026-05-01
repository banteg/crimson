const std = @import("std");

const msgpack_bin8: u8 = 0xc4;
const msgpack_bin16: u8 = 0xc5;
const msgpack_bin32: u8 = 0xc6;

pub const SlotState = struct {
    slot_index: i32 = -1,
    connected: bool = false,
    ready: bool = false,
    is_host: bool = false,
    peer_name: []const u8 = "",
};

pub const PacketHeader = struct {
    seq: i32 = 0,
    ack: i32 = 0,
    reliable: bool = false,
};

pub const WireBytes = struct {
    data: []const u8 = "",

    pub fn msgpackWrite(self: WireBytes, packer: anytype) !void {
        try writeBinHeader(packer.writer, self.data.len);
        try packer.writer.writeAll(self.data);
    }

    pub fn msgpackRead(unpacker: anytype) !WireBytes {
        const len = try readBinHeader(unpacker.reader);
        const bytes = try unpacker.allocator.alloc(u8, len);
        errdefer unpacker.allocator.free(bytes);
        try unpacker.reader.readSliceAll(bytes);
        return .{ .data = bytes };
    }
};

fn writeBinHeader(writer: *std.Io.Writer, len: usize) !void {
    if (len <= std.math.maxInt(u8)) {
        try writer.writeByte(msgpack_bin8);
        try writePackedInt(u8, writer, @intCast(len));
    } else if (len <= std.math.maxInt(u16)) {
        try writer.writeByte(msgpack_bin16);
        try writePackedInt(u16, writer, @intCast(len));
    } else if (len <= std.math.maxInt(u32)) {
        try writer.writeByte(msgpack_bin32);
        try writePackedInt(u32, writer, @intCast(len));
    } else {
        return error.BinaryTooLong;
    }
}

fn readBinHeader(reader: *std.Io.Reader) !usize {
    const header = try reader.takeByte();
    return switch (header) {
        msgpack_bin8 => try readPackedInt(u8, reader),
        msgpack_bin16 => try readPackedInt(u16, reader),
        msgpack_bin32 => try readPackedInt(u32, reader),
        else => error.InvalidFormat,
    };
}

fn writePackedInt(comptime T: type, writer: *std.Io.Writer, value: T) !void {
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &buf, value, .big);
    try writer.writeAll(&buf);
}

fn readPackedInt(comptime T: type, reader: *std.Io.Reader) !T {
    var buf: [@sizeOf(T)]u8 = undefined;
    try reader.readSliceAll(&buf);
    return std.mem.readInt(T, &buf, .big);
}

test "shared slot state mirrors python defaults" {
    const slot: SlotState = .{};
    try std.testing.expectEqual(@as(i32, -1), slot.slot_index);
    try std.testing.expect(!slot.connected);
    try std.testing.expect(!slot.ready);
    try std.testing.expect(!slot.is_host);
    try std.testing.expectEqualStrings("", slot.peer_name);
}

test "shared packet header mirrors python defaults" {
    const header: PacketHeader = .{};
    try std.testing.expectEqual(@as(i32, 0), header.seq);
    try std.testing.expectEqual(@as(i32, 0), header.ack);
    try std.testing.expect(!header.reliable);
}

test "wire bytes encode as msgpack bin" {
    const msgpack = @import("msgpack");

    var writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer writer.deinit();

    const bytes: WireBytes = .{ .data = "abc" };
    try msgpack.encode(bytes, &writer.writer);
    try std.testing.expectEqualSlices(u8, &.{ 0xc4, 0x03, 'a', 'b', 'c' }, writer.written());

    const decoded = try msgpack.decodeFromSlice(WireBytes, std.testing.allocator, writer.written());
    defer decoded.deinit();
    try std.testing.expectEqualSlices(u8, "abc", decoded.value.data);
}
