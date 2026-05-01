const std = @import("std");

const lockstep_protocol = @import("lockstep_protocol.zig");
const lockstep_transport = @import("lockstep_transport.zig");

pub const PeerAddr = lockstep_transport.PeerAddr;

pub const OutgoingPacket = struct {
    addr: PeerAddr,
    packet: lockstep_protocol.LockstepPacket,

    pub fn deinit(self: *OutgoingPacket, allocator: std.mem.Allocator) void {
        lockstep_protocol.deinitPacket(allocator, &self.packet);
        self.* = undefined;
    }
};

pub const Outbox = struct {
    packets: std.ArrayList(OutgoingPacket) = .empty,

    pub fn deinit(self: *Outbox, allocator: std.mem.Allocator) void {
        for (self.packets.items) |*packet| packet.deinit(allocator);
        self.packets.deinit(allocator);
        self.* = undefined;
    }

    pub fn appendPacket(
        self: *Outbox,
        allocator: std.mem.Allocator,
        addr: PeerAddr,
        packet: lockstep_protocol.LockstepPacket,
    ) !void {
        var owned = try lockstep_protocol.clonePacket(allocator, packet);
        errdefer lockstep_protocol.deinitPacket(allocator, &owned);
        try self.packets.append(allocator, .{ .addr = addr, .packet = owned });
        owned = .{};
    }
};

test "lockstep outbox owns dynamic packet payloads" {
    const allocator = std.testing.allocator;
    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);

    var packet = try lockstep_protocol.clonePacket(allocator, .{
        .seq = 1,
        .ack = 0,
        .reliable = true,
        .message = .{ .debug_log_batch = .{
            .slot_index = 1,
            .lines = &.{ "alpha", "beta" },
        } },
    });
    defer lockstep_protocol.deinitPacket(allocator, &packet);

    try outbox.appendPacket(allocator, PeerAddr.loopback(31993), packet);
    lockstep_protocol.deinitPacket(allocator, &packet);
    packet = .{};

    try std.testing.expectEqual(@as(usize, 1), outbox.packets.items.len);
    switch (outbox.packets.items[0].packet.message) {
        .debug_log_batch => |batch| {
            try std.testing.expectEqualStrings("alpha", batch.lines[0]);
            try std.testing.expectEqualStrings("beta", batch.lines[1]);
        },
        else => return error.TestExpectedEqual,
    }
}
