const std = @import("std");

const relay_protocol = @import("relay_protocol.zig");
const reliable_channel = @import("reliable_channel.zig");

pub const PendingReliable = reliable_channel.PendingReliable(relay_protocol.RelayPacket);
pub const IngestResult = reliable_channel.IngestResult(relay_protocol.NetMessage);
pub const RelayReliableLink = reliable_channel.ReliableLink(
    relay_protocol.RelayPacket,
    relay_protocol.NetMessage,
    relay_protocol.reliable_resend_ms,
);

test "relay reliable packet is acked and removed" {
    const allocator = std.testing.allocator;
    var sender: RelayReliableLink = .{ .resend_ms = 40 };
    defer sender.deinit(allocator);
    var receiver: RelayReliableLink = .{ .resend_ms = 40 };
    defer receiver.deinit(allocator);

    const packet = try sender.buildPacket(
        allocator,
        .{ .room_ready = .{ .slot_index = 1, .ready = true } },
        true,
        1000,
    );
    var delivered = try receiver.ingestPacket(allocator, packet, 1000);
    defer delivered.deinit(allocator);
    try std.testing.expect(!delivered.duplicate);
    try std.testing.expectEqual(@as(usize, 1), delivered.messages.items.len);
    switch (delivered.messages.items[0]) {
        .room_ready => |ready| try std.testing.expectEqual(@as(i32, 1), ready.slot_index),
        else => return error.TestExpectedEqual,
    }

    const ack = try receiver.buildPacket(allocator, .{ .ping = .{} }, false, 1001);
    var ack_result = try sender.ingestPacket(allocator, ack, 1001);
    defer ack_result.deinit(allocator);

    var resends = try sender.pollResends(allocator, 2000);
    defer resends.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), resends.items.len);
    try std.testing.expectEqual(@as(usize, 0), sender.pendingCount());
    try std.testing.expectEqual(@as(i64, 1), sender.rtt_last_ms);
}

test "relay duplicate reliable packet is dropped" {
    const allocator = std.testing.allocator;
    var receiver: RelayReliableLink = .{ .resend_ms = 40 };
    defer receiver.deinit(allocator);
    var sender: RelayReliableLink = .{ .resend_ms = 40 };
    defer sender.deinit(allocator);

    const packet = try sender.buildPacket(
        allocator,
        .{ .room_ready = .{ .slot_index = 2, .ready = true } },
        true,
        10,
    );

    var first = try receiver.ingestPacket(allocator, packet, 10);
    defer first.deinit(allocator);
    var second = try receiver.ingestPacket(allocator, packet, 10);
    defer second.deinit(allocator);

    try std.testing.expect(!first.duplicate);
    try std.testing.expectEqual(@as(usize, 1), first.messages.items.len);
    try std.testing.expect(second.duplicate);
    try std.testing.expectEqual(@as(usize, 0), second.messages.items.len);
}

test "relay reliable packet is resent after timeout" {
    const allocator = std.testing.allocator;
    var sender: RelayReliableLink = .{ .resend_ms = 40 };
    defer sender.deinit(allocator);

    _ = try sender.buildPacket(allocator, .{ .room_ready = .{ .slot_index = 1, .ready = true } }, true, 0);

    var early = try sender.pollResends(allocator, 39);
    defer early.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), early.items.len);

    var resent = try sender.pollResends(allocator, 40);
    defer resent.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), resent.items.len);
    try std.testing.expect(resent.items[0].reliable);
    try std.testing.expectEqual(@as(i32, 1), resent.items[0].seq);
    try std.testing.expectEqual(@as(i64, 1), sender.resend_count);
}

test "relay reliable delivery buffers out of order packets and acks contiguously" {
    const allocator = std.testing.allocator;
    var sender: RelayReliableLink = .{ .resend_ms = 40 };
    defer sender.deinit(allocator);
    var receiver: RelayReliableLink = .{ .resend_ms = 40 };
    defer receiver.deinit(allocator);

    const p1 = try sender.buildPacket(allocator, .{ .room_ready = .{ .slot_index = 1, .ready = true } }, true, 0);
    const p2 = try sender.buildPacket(allocator, .{ .room_ready = .{ .slot_index = 2, .ready = true } }, true, 0);

    var second = try receiver.ingestPacket(allocator, p2, 0);
    defer second.deinit(allocator);
    try std.testing.expect(!second.duplicate);
    try std.testing.expectEqual(@as(usize, 0), second.messages.items.len);
    try std.testing.expectEqual(@as(i32, 0), receiver.recv_highest_seq);

    var first = try receiver.ingestPacket(allocator, p1, 0);
    defer first.deinit(allocator);
    try std.testing.expect(!first.duplicate);
    try std.testing.expectEqual(@as(usize, 2), first.messages.items.len);
    switch (first.messages.items[0]) {
        .room_ready => |ready| try std.testing.expectEqual(@as(i32, 1), ready.slot_index),
        else => return error.TestExpectedEqual,
    }
    switch (first.messages.items[1]) {
        .room_ready => |ready| try std.testing.expectEqual(@as(i32, 2), ready.slot_index),
        else => return error.TestExpectedEqual,
    }
    try std.testing.expectEqual(@as(i32, 2), receiver.recv_highest_seq);
}
