const std = @import("std");

pub fn PendingReliable(comptime Packet: type) type {
    return struct {
        packet: Packet,
        sent_at_ms: i64,
    };
}

pub fn IngestResult(comptime Message: type) type {
    return struct {
        const Self = @This();

        messages: std.ArrayList(Message) = .empty,
        duplicate: bool = false,

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.messages.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn ReliableLink(comptime Packet: type, comptime Message: type, comptime default_resend_ms: i64) type {
    const Pending = PendingReliable(Packet);
    const Result = IngestResult(Message);

    return struct {
        const Self = @This();

        resend_ms: i64 = default_resend_ms,
        next_seq: i32 = 1,
        recv_highest_seq: i32 = 0,
        pending: std.ArrayList(Pending) = .empty,
        recv_buffer: std.ArrayList(Packet) = .empty,
        rtt_last_ms: i64 = 0,
        rtt_ewma_ms: f64 = 0.0,
        resend_count: i64 = 0,

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.pending.deinit(allocator);
            self.recv_buffer.deinit(allocator);
            self.* = undefined;
        }

        pub fn pendingCount(self: *const Self) usize {
            return self.pending.items.len;
        }

        pub fn primeRecvSeq(self: *Self, seq: i32) void {
            if (seq <= self.recv_highest_seq) return;
            self.recv_highest_seq = seq;
        }

        pub fn buildPacket(
            self: *Self,
            allocator: std.mem.Allocator,
            message: Message,
            reliable: bool,
            now_ms: i64,
        ) !Packet {
            var seq: i32 = 0;
            if (reliable) {
                seq = self.next_seq;
                self.next_seq += 1;
            }

            const packet: Packet = .{
                .seq = seq,
                .ack = self.recv_highest_seq,
                .reliable = reliable,
                .message = message,
            };
            if (reliable) {
                try self.pending.append(allocator, .{ .packet = packet, .sent_at_ms = now_ms });
            }
            return packet;
        }

        pub fn ingestPacket(self: *Self, allocator: std.mem.Allocator, packet: Packet, now_ms: i64) !Result {
            self.applyAck(packet.ack, now_ms);

            var result: Result = .{};
            errdefer result.deinit(allocator);

            if (!packet.reliable) {
                try result.messages.append(allocator, packet.message);
                return result;
            }

            const seq = packet.seq;
            if (seq <= 0) return result;

            if (seq <= self.recv_highest_seq or self.findRecvBufferIndex(seq) != null) {
                result.duplicate = true;
                return result;
            }

            try self.recv_buffer.append(allocator, packet);

            var next_seq = self.recv_highest_seq + 1;
            while (self.findRecvBufferIndex(next_seq)) |idx| {
                const next_packet = self.recv_buffer.orderedRemove(idx);
                try result.messages.append(allocator, next_packet.message);
                self.recv_highest_seq = next_seq;
                next_seq += 1;
            }

            return result;
        }

        pub fn pollResends(self: *Self, allocator: std.mem.Allocator, now_ms: i64) !std.ArrayList(Packet) {
            var out: std.ArrayList(Packet) = .empty;
            errdefer out.deinit(allocator);

            for (self.pending.items) |*pending| {
                if (now_ms - pending.sent_at_ms < self.resend_ms) continue;
                const refreshed: Packet = .{
                    .seq = pending.packet.seq,
                    .ack = self.recv_highest_seq,
                    .reliable = true,
                    .message = pending.packet.message,
                };
                pending.* = .{ .packet = refreshed, .sent_at_ms = now_ms };
                try out.append(allocator, refreshed);
                self.resend_count += 1;
            }

            return out;
        }

        fn applyAck(self: *Self, ack: i32, now_ms: i64) void {
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
                    _ = self.pending.orderedRemove(idx);
                } else {
                    idx += 1;
                }
            }
        }

        fn findRecvBufferIndex(self: *const Self, seq: i32) ?usize {
            for (self.recv_buffer.items, 0..) |packet, idx| {
                if (packet.seq == seq) return idx;
            }
            return null;
        }
    };
}
