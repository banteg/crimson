const std = @import("std");

const relay_protocol = @import("relay_protocol.zig");
const room_code = @import("room_code.zig");

pub const PendingReliable = struct {
    packet: relay_protocol.RelayPacket,
    sent_at_ms: i64,

    pub fn deinit(self: *PendingReliable, allocator: std.mem.Allocator) void {
        relay_protocol.deinitPacket(allocator, &self.packet);
        self.* = undefined;
    }
};

pub const IngestResult = struct {
    messages: std.ArrayList(relay_protocol.NetMessage) = .empty,
    duplicate: bool = false,

    pub fn deinit(self: *IngestResult, allocator: std.mem.Allocator) void {
        for (self.messages.items) |*message| relay_protocol.deinitMessage(allocator, message);
        self.messages.deinit(allocator);
        self.* = undefined;
    }
};

pub const RelayReliableLink = struct {
    resend_ms: i64 = relay_protocol.reliable_resend_ms,
    next_seq: i32 = 1,
    recv_highest_seq: i32 = 0,
    pending: std.ArrayList(PendingReliable) = .empty,
    recv_buffer: std.ArrayList(relay_protocol.RelayPacket) = .empty,
    rtt_last_ms: i64 = 0,
    rtt_ewma_ms: f64 = 0.0,
    resend_count: i64 = 0,

    pub fn deinit(self: *RelayReliableLink, allocator: std.mem.Allocator) void {
        for (self.pending.items) |*pending| pending.deinit(allocator);
        self.pending.deinit(allocator);
        for (self.recv_buffer.items) |*packet| relay_protocol.deinitPacket(allocator, packet);
        self.recv_buffer.deinit(allocator);
        self.* = undefined;
    }

    pub fn pendingCount(self: *const RelayReliableLink) usize {
        return self.pending.items.len;
    }

    pub fn primeRecvSeq(self: *RelayReliableLink, seq: i32) void {
        if (seq <= self.recv_highest_seq) return;
        self.recv_highest_seq = seq;
    }

    pub fn buildPacket(
        self: *RelayReliableLink,
        allocator: std.mem.Allocator,
        message: relay_protocol.NetMessage,
        reliable: bool,
        now_ms: i64,
    ) !relay_protocol.RelayPacket {
        var seq: i32 = 0;
        if (reliable) {
            seq = self.next_seq;
            self.next_seq += 1;
        }

        const packet: relay_protocol.RelayPacket = .{
            .seq = seq,
            .ack = self.recv_highest_seq,
            .reliable = reliable,
            .message = message,
        };
        if (reliable) {
            var owned = try relay_protocol.clonePacket(allocator, packet);
            errdefer relay_protocol.deinitPacket(allocator, &owned);
            try self.pending.append(allocator, .{ .packet = owned, .sent_at_ms = now_ms });
            owned = .{};
        }
        return packet;
    }

    pub fn ingestPacket(
        self: *RelayReliableLink,
        allocator: std.mem.Allocator,
        packet: relay_protocol.RelayPacket,
        now_ms: i64,
    ) !IngestResult {
        self.applyAck(allocator, packet.ack, now_ms);

        var result: IngestResult = .{};
        errdefer result.deinit(allocator);

        if (!packet.reliable) {
            var owned_message = try relay_protocol.cloneMessage(allocator, packet.message);
            errdefer relay_protocol.deinitMessage(allocator, &owned_message);
            try result.messages.append(allocator, owned_message);
            owned_message = .{ .ping = .{} };
            return result;
        }

        const seq = packet.seq;
        if (seq <= 0) return result;

        if (seq <= self.recv_highest_seq or self.findRecvBufferIndex(seq) != null) {
            result.duplicate = true;
            return result;
        }

        var owned = try relay_protocol.clonePacket(allocator, packet);
        errdefer relay_protocol.deinitPacket(allocator, &owned);
        try self.recv_buffer.append(allocator, owned);
        owned = .{};

        var next_seq = self.recv_highest_seq + 1;
        while (self.findRecvBufferIndex(next_seq)) |idx| {
            var next_packet = self.recv_buffer.orderedRemove(idx);
            errdefer relay_protocol.deinitPacket(allocator, &next_packet);
            try result.messages.append(allocator, next_packet.message);
            next_packet.message = .{ .ping = .{} };
            self.recv_highest_seq = next_seq;
            next_seq += 1;
        }

        return result;
    }

    pub fn pollResends(self: *RelayReliableLink, allocator: std.mem.Allocator, now_ms: i64) !std.ArrayList(relay_protocol.RelayPacket) {
        var out: std.ArrayList(relay_protocol.RelayPacket) = .empty;
        errdefer {
            for (out.items) |*packet| relay_protocol.deinitPacket(allocator, packet);
            out.deinit(allocator);
        }

        for (self.pending.items) |*pending| {
            if (now_ms - pending.sent_at_ms < self.resend_ms) continue;
            pending.packet.ack = self.recv_highest_seq;
            pending.sent_at_ms = now_ms;
            var packet = try relay_protocol.clonePacket(allocator, pending.packet);
            errdefer relay_protocol.deinitPacket(allocator, &packet);
            try out.append(allocator, packet);
            packet = .{};
            self.resend_count += 1;
        }

        return out;
    }

    fn applyAck(self: *RelayReliableLink, allocator: std.mem.Allocator, ack: i32, now_ms: i64) void {
        if (ack <= 0) return;

        var newest_index: ?usize = null;
        var newest_seq: i32 = std.math.minInt(i32);
        for (self.pending.items, 0..) |pending, idx| {
            if (pending.packet.seq <= ack and pending.packet.seq > newest_seq) {
                newest_seq = pending.packet.seq;
                newest_index = idx;
            }
        }
        if (newest_index == null) return;

        const newest = self.pending.items[newest_index.?];
        const sample_ms = @max(@as(i64, 0), now_ms - newest.sent_at_ms);
        self.rtt_last_ms = sample_ms;
        if (self.rtt_ewma_ms <= 0.0) {
            self.rtt_ewma_ms = @floatFromInt(sample_ms);
        } else {
            self.rtt_ewma_ms = self.rtt_ewma_ms * 0.9 + @as(f64, @floatFromInt(sample_ms)) * 0.1;
        }

        var idx: usize = 0;
        while (idx < self.pending.items.len) {
            if (self.pending.items[idx].packet.seq <= ack) {
                var removed = self.pending.orderedRemove(idx);
                removed.deinit(allocator);
            } else {
                idx += 1;
            }
        }
    }

    fn findRecvBufferIndex(self: *const RelayReliableLink, seq: i32) ?usize {
        for (self.recv_buffer.items, 0..) |packet, idx| {
            if (packet.seq == seq) return idx;
        }
        return null;
    }
};

/// Free packet payloads returned by pollResends and then release the packet list.
pub fn deinitPacketList(allocator: std.mem.Allocator, packets: *std.ArrayList(relay_protocol.RelayPacket)) void {
    for (packets.items) |*packet| relay_protocol.deinitPacket(allocator, packet);
    packets.deinit(allocator);
    packets.* = .empty;
}

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
    defer deinitPacketList(allocator, &resends);
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
    defer deinitPacketList(allocator, &early);
    try std.testing.expectEqual(@as(usize, 0), early.items.len);

    var resent = try sender.pollResends(allocator, 40);
    defer deinitPacketList(allocator, &resent);
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

test "relay reliable pending packets own room state payloads" {
    const allocator = std.testing.allocator;
    var sender: RelayReliableLink = .{ .resend_ms = 40 };
    defer sender.deinit(allocator);

    const slots = [_]relay_protocol.RelaySlot{
        .{ .slot_index = 0, .connected = true, .ready = true, .is_host = true, .peer_name = "host" },
    };
    _ = try sender.buildPacket(allocator, .{ .room_state = .{
        .room_code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .slots = slots[0..],
    } }, true, 0);
    try std.testing.expectEqual(@as(usize, 1), sender.pendingCount());

    var resent = try sender.pollResends(allocator, 40);
    defer deinitPacketList(allocator, &resent);
    switch (resent.items[0].message) {
        .room_state => |state| {
            try std.testing.expectEqualStrings("session", state.session_id);
            try std.testing.expectEqual(@as(usize, 1), state.slots.len);
            try std.testing.expectEqualStrings("host", state.slots[0].peer_name);
        },
        else => return error.TestExpectedEqual,
    }
}

test "relay reliable buffers decoded out of order payloads after decode storage is freed" {
    const allocator = std.testing.allocator;
    var receiver: RelayReliableLink = .{ .resend_ms = 40 };
    defer receiver.deinit(allocator);

    const encoded = try relay_protocol.encodePacket(allocator, .{
        .seq = 2,
        .ack = 0,
        .reliable = true,
        .message = .{ .rb_resync_chunk = .{
            .request_id = "request",
            .chunk_index = 1,
            .payload = .{ .data = "payload" },
        } },
    });
    defer allocator.free(encoded);
    {
        const decoded = try relay_protocol.decodePacket(allocator, encoded);
        defer decoded.deinit();
        var second = try receiver.ingestPacket(allocator, decoded.value, 0);
        defer second.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 0), second.messages.items.len);
    }

    var first = try receiver.ingestPacket(allocator, .{
        .seq = 1,
        .ack = 0,
        .reliable = true,
        .message = .{ .ping = .{ .stamp_ms = 7 } },
    }, 1);
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), first.messages.items.len);
    switch (first.messages.items[1]) {
        .rb_resync_chunk => |chunk| {
            try std.testing.expectEqualStrings("request", chunk.request_id);
            try std.testing.expectEqualStrings("payload", chunk.payload.data);
        },
        else => return error.TestExpectedEqual,
    }
}
