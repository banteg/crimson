const std = @import("std");
const msgpack = @import("msgpack");

pub const PackedPlayerInput = struct {
    move_x: f32 = 0.0,
    move_y: f32 = 0.0,
    aim_x: f32 = 0.0,
    aim_y: f32 = 0.0,
    flags: u32 = 0,

    pub fn msgpackFormat() msgpack.StructFormat {
        return .{ .as_array = .{} };
    }
};

pub const neutral: PackedPlayerInput = .{};

pub fn eql(lhs: PackedPlayerInput, rhs: PackedPlayerInput) bool {
    return lhs.move_x == rhs.move_x and
        lhs.move_y == rhs.move_y and
        lhs.aim_x == rhs.aim_x and
        lhs.aim_y == rhs.aim_y and
        lhs.flags == rhs.flags;
}

test "packed player input stores replay scalar shape" {
    const input: PackedPlayerInput = .{
        .move_x = -1.0,
        .move_y = 0.5,
        .aim_x = 8.0,
        .aim_y = -3.25,
        .flags = 5,
    };
    try std.testing.expectEqual(@as(f32, -1.0), input.move_x);
    try std.testing.expectEqual(@as(f32, 0.5), input.move_y);
    try std.testing.expectEqual(@as(f32, 8.0), input.aim_x);
    try std.testing.expectEqual(@as(f32, -3.25), input.aim_y);
    try std.testing.expectEqual(@as(u32, 5), input.flags);
}

test "packed player input has neutral default" {
    try std.testing.expect(eql(neutral, .{}));
    try std.testing.expectEqual(@as(u32, 0), neutral.flags);
}

test "packed player input encodes as five-field msgpack array" {
    var writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer writer.deinit();

    const input: PackedPlayerInput = .{
        .move_x = 1.0,
        .move_y = 2.0,
        .aim_x = 3.0,
        .aim_y = 4.0,
        .flags = 5,
    };
    try msgpack.encode(input, &writer.writer);
    try std.testing.expectEqual(@as(u8, 0x95), writer.written()[0]);

    const decoded = try msgpack.decodeFromSlice(PackedPlayerInput, std.testing.allocator, writer.written());
    defer decoded.deinit();
    try std.testing.expect(eql(input, decoded.value));
}
