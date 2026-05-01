const std = @import("std");

const lockstep_protocol = @import("lockstep_protocol.zig");
const reliable_channel = @import("reliable_channel.zig");

pub const PendingReliable = reliable_channel.PendingReliable(lockstep_protocol.LockstepPacket);
pub const IngestResult = reliable_channel.IngestResult(lockstep_protocol.NetMessage);
pub const ReliableLink = reliable_channel.ReliableLink(
    lockstep_protocol.LockstepPacket,
    lockstep_protocol.NetMessage,
    lockstep_protocol.reliable_resend_ms,
);

test "reliable packet is acked and removed" {
    const allocator = std.testing.allocator;
    var sender: ReliableLink = .{ .resend_ms = 40 };
    defer sender.deinit(allocator);
    var receiver: ReliableLink = .{ .resend_ms = 40 };
    defer receiver.deinit(allocator);

    const packet = try sender.buildPacket(
        allocator,
        .{ .ready = .{ .slot_index = 1, .ready = true } },
        true,
        1000,
    );
    var delivered = try receiver.ingestPacket(allocator, packet, 1000);
    defer delivered.deinit(allocator);
    try std.testing.expect(!delivered.duplicate);
    try std.testing.expectEqual(@as(usize, 1), delivered.messages.items.len);
    switch (delivered.messages.items[0]) {
        .ready => |ready| try std.testing.expectEqual(@as(i32, 1), ready.slot_index),
        else => return error.TestExpectedEqual,
    }

    const ack = try receiver.buildPacket(allocator, .{ .pause_state = .{} }, false, 1001);
    var ack_result = try sender.ingestPacket(allocator, ack, 1001);
    defer ack_result.deinit(allocator);

    var resends = try sender.pollResends(allocator, 2000);
    defer resends.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), resends.items.len);
    try std.testing.expectEqual(@as(usize, 0), sender.pendingCount());
    try std.testing.expectEqual(@as(i64, 1), sender.rtt_last_ms);
}

test "duplicate reliable packet is dropped" {
    const allocator = std.testing.allocator;
    var receiver: ReliableLink = .{ .resend_ms = 40 };
    defer receiver.deinit(allocator);
    var sender: ReliableLink = .{ .resend_ms = 40 };
    defer sender.deinit(allocator);

    const packet = try sender.buildPacket(
        allocator,
        .{ .ready = .{ .slot_index = 2, .ready = true } },
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

test "reliable packet is resent after timeout" {
    const allocator = std.testing.allocator;
    var sender: ReliableLink = .{ .resend_ms = 40 };
    defer sender.deinit(allocator);

    _ = try sender.buildPacket(allocator, .{ .ready = .{ .slot_index = 1, .ready = true } }, true, 0);

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

test "reliable delivery buffers out of order packets and acks contiguously" {
    const allocator = std.testing.allocator;
    var sender: ReliableLink = .{ .resend_ms = 40 };
    defer sender.deinit(allocator);
    var receiver: ReliableLink = .{ .resend_ms = 40 };
    defer receiver.deinit(allocator);

    const p1 = try sender.buildPacket(allocator, .{ .ready = .{ .slot_index = 1, .ready = true } }, true, 0);
    const p2 = try sender.buildPacket(allocator, .{ .ready = .{ .slot_index = 2, .ready = true } }, true, 0);

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
        .ready => |ready| try std.testing.expectEqual(@as(i32, 1), ready.slot_index),
        else => return error.TestExpectedEqual,
    }
    switch (first.messages.items[1]) {
        .ready => |ready| try std.testing.expectEqual(@as(i32, 2), ready.slot_index),
        else => return error.TestExpectedEqual,
    }
    try std.testing.expectEqual(@as(i32, 2), receiver.recv_highest_seq);
}

test "reliable link can prime receive sequence" {
    var link: ReliableLink = .{};
    link.primeRecvSeq(4);
    link.primeRecvSeq(3);
    try std.testing.expectEqual(@as(i32, 4), link.recv_highest_seq);
}
