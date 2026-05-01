const std = @import("std");

const relay_core = @import("relay_core.zig");
const relay_dispatch = @import("relay_dispatch.zig");
const relay_protocol = @import("relay_protocol.zig");
const relay_reliable = @import("relay_reliable.zig");

pub const PacketOutbound = struct {
    peer_index: usize,
    packet: relay_protocol.RelayPacket,

    pub fn deinit(self: *PacketOutbound, allocator: std.mem.Allocator) void {
        relay_protocol.deinitPacket(allocator, &self.packet);
        self.* = undefined;
    }
};

pub const PacketOutbox = struct {
    items: std.ArrayList(PacketOutbound) = .empty,

    pub fn deinit(self: *PacketOutbox, allocator: std.mem.Allocator) void {
        for (self.items.items) |*item| item.deinit(allocator);
        self.items.deinit(allocator);
        self.* = undefined;
    }
};

pub fn handleClientHello(
    allocator: std.mem.Allocator,
    core: *relay_core.RelayCore,
    peer_index: usize,
    message: relay_protocol.ClientHello,
    now_ms: i64,
) !PacketOutbox {
    var outbox = try relay_dispatch.handleClientHello(allocator, core, peer_index, message, now_ms);
    defer outbox.deinit(allocator);
    return packetizeOutbox(allocator, core, outbox, now_ms);
}

pub fn handlePeerPacket(
    allocator: std.mem.Allocator,
    core: *relay_core.RelayCore,
    peer_index: usize,
    packet: relay_protocol.RelayPacket,
    options: relay_dispatch.DispatchOptions,
) !PacketOutbox {
    var packets: PacketOutbox = .{};
    errdefer packets.deinit(allocator);
    if (peer_index >= core.peers.items.len) return packets;

    core.peers.items[peer_index].peer.last_seen_ms = options.now_ms;
    var delivered = try core.peers.items[peer_index].link.ingestPacket(allocator, packet, options.now_ms);
    defer delivered.deinit(allocator);

    for (delivered.messages.items) |message| {
        {
            var dispatch_outbox = try relay_dispatch.handleMessage(allocator, core, peer_index, message, options);
            defer dispatch_outbox.deinit(allocator);
            try appendDispatchOutbox(allocator, core, dispatch_outbox, options.now_ms, &packets);
        }
    }
    return packets;
}

pub fn pollResends(allocator: std.mem.Allocator, core: *relay_core.RelayCore, now_ms: i64) !PacketOutbox {
    var packets: PacketOutbox = .{};
    errdefer packets.deinit(allocator);

    for (core.peers.items, 0..) |*peer, peer_index| {
        var resends = try peer.link.pollResends(allocator, now_ms);
        defer relay_reliable.deinitPacketList(allocator, &resends);
        for (resends.items) |*packet| {
            var moved = packet.*;
            errdefer relay_protocol.deinitPacket(allocator, &moved);
            try packets.items.append(allocator, .{
                .peer_index = peer_index,
                .packet = moved,
            });
            packet.* = .{};
            moved = .{};
        }
    }
    return packets;
}

pub fn packetizeOutbox(
    allocator: std.mem.Allocator,
    core: *relay_core.RelayCore,
    dispatch_outbox: relay_dispatch.Outbox,
    now_ms: i64,
) !PacketOutbox {
    var packets: PacketOutbox = .{};
    errdefer packets.deinit(allocator);
    try appendDispatchOutbox(allocator, core, dispatch_outbox, now_ms, &packets);
    return packets;
}

fn appendDispatchOutbox(
    allocator: std.mem.Allocator,
    core: *relay_core.RelayCore,
    dispatch_outbox: relay_dispatch.Outbox,
    now_ms: i64,
    packets: *PacketOutbox,
) !void {
    for (dispatch_outbox.items.items) |outbound| {
        if (outbound.peer_index >= core.peers.items.len) continue;
        const packet = try core.peers.items[outbound.peer_index].link.buildPacket(
            allocator,
            outbound.message,
            outbound.reliable,
            now_ms,
        );
        var owned = try relay_protocol.clonePacket(allocator, packet);
        errdefer relay_protocol.deinitPacket(allocator, &owned);
        try packets.items.append(allocator, .{
            .peer_index = outbound.peer_index,
            .packet = owned,
        });
        owned = .{};
    }
}

test "relay pump packetizes client hello as reliable welcome" {
    const allocator = std.testing.allocator;
    var core: relay_core.RelayCore = .{};
    defer core.deinit(allocator);
    const peer_idx = try core.addPeer(allocator, .{ .peer_id = "peer-1" });

    var packets = try handleClientHello(allocator, &core, peer_idx, .{
        .protocol_version = relay_protocol.protocol_version,
        .build_id = "0.1.0",
        .peer_name = "host",
    }, 1000);
    defer packets.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), packets.items.items.len);
    try std.testing.expectEqual(peer_idx, packets.items.items[0].peer_index);
    try std.testing.expect(packets.items.items[0].packet.reliable);
    try std.testing.expectEqual(@as(i32, 1), packets.items.items[0].packet.seq);
    try std.testing.expectEqual(@as(usize, 1), core.peers.items[peer_idx].link.pendingCount());
    switch (packets.items.items[0].packet.message) {
        .client_welcome => |welcome| {
            try std.testing.expect(welcome.accepted);
            try std.testing.expectEqualStrings("peer-1", welcome.peer_id);
        },
        else => return error.TestExpectedEqual,
    }
}

test "relay pump ingests peer ping and emits pong packet" {
    const allocator = std.testing.allocator;
    var core: relay_core.RelayCore = .{};
    defer core.deinit(allocator);
    const peer_idx = try core.addPeer(allocator, .{ .peer_id = "peer-1" });

    var packets = try handlePeerPacket(allocator, &core, peer_idx, .{
        .message = .{ .ping = .{ .stamp_ms = 1234 } },
    }, .{ .now_ms = 1001 });
    defer packets.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), packets.items.items.len);
    try std.testing.expectEqual(peer_idx, packets.items.items[0].peer_index);
    try std.testing.expect(!packets.items.items[0].packet.reliable);
    switch (packets.items.items[0].packet.message) {
        .pong => |pong| try std.testing.expectEqual(@as(i32, 1234), pong.stamp_ms),
        else => return error.TestExpectedEqual,
    }
    try std.testing.expectEqual(@as(i64, 1001), core.peers.items[peer_idx].peer.last_seen_ms);
}

test "relay pump polls owned reliable resends" {
    const allocator = std.testing.allocator;
    var core: relay_core.RelayCore = .{};
    defer core.deinit(allocator);
    const peer_idx = try core.addPeer(allocator, .{ .peer_id = "peer-1" });

    var welcome = try handleClientHello(allocator, &core, peer_idx, .{
        .protocol_version = relay_protocol.protocol_version,
        .peer_name = "host",
    }, 1000);
    defer welcome.deinit(allocator);

    var early = try pollResends(allocator, &core, 1039);
    defer early.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), early.items.items.len);

    var resent = try pollResends(allocator, &core, 1040);
    defer resent.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), resent.items.items.len);
    try std.testing.expectEqual(peer_idx, resent.items.items[0].peer_index);
    try std.testing.expect(resent.items.items[0].packet.reliable);
    switch (resent.items.items[0].packet.message) {
        .client_welcome => |resent_welcome| try std.testing.expectEqualStrings("peer-1", resent_welcome.peer_id),
        else => return error.TestExpectedEqual,
    }
}
