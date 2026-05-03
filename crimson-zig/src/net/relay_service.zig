const std = @import("std");

const relay_core = @import("relay_core.zig");
const relay_dispatch = @import("relay_dispatch.zig");
const relay_lobby = @import("relay_lobby.zig");
const relay_protocol = @import("relay_protocol.zig");
const relay_pump = @import("relay_pump.zig");
const relay_reliable = @import("relay_reliable.zig");
const room_code = @import("room_code.zig");

pub const PeerAddr = struct {
    host: [4]u8 = .{ 127, 0, 0, 1 },
    port: u16 = 0,

    pub fn eql(self: PeerAddr, other: PeerAddr) bool {
        return std.mem.eql(u8, &self.host, &other.host) and self.port == other.port;
    }
};

pub const ServiceOptions = struct {
    peer_id: []const u8 = "",
    dispatch: relay_dispatch.DispatchOptions = .{},
};

pub const AddressedPacket = struct {
    addr: PeerAddr,
    packet: relay_protocol.RelayPacket,

    pub fn deinit(self: *AddressedPacket, allocator: std.mem.Allocator) void {
        relay_protocol.deinitPacket(allocator, &self.packet);
        self.* = undefined;
    }
};

pub const AddressedOutbox = struct {
    items: std.ArrayList(AddressedPacket) = .empty,

    pub fn deinit(self: *AddressedOutbox, allocator: std.mem.Allocator) void {
        for (self.items.items) |*item| item.deinit(allocator);
        self.items.deinit(allocator);
        self.* = undefined;
    }
};

const AddrPeer = struct {
    addr: PeerAddr,
    peer_index: usize,
};

pub const RelayService = struct {
    core: relay_core.RelayCore = .{},
    peers_by_addr: std.ArrayList(AddrPeer) = .empty,
    owned_labels: std.ArrayList([]u8) = .empty,
    next_peer_id: u64 = 1,
    next_session_id: u64 = 1,
    next_reconnect_token: u64 = 1,
    next_room_code: u32 = 0,

    pub fn deinit(self: *RelayService, allocator: std.mem.Allocator) void {
        self.peers_by_addr.deinit(allocator);
        self.core.deinit(allocator);
        for (self.owned_labels.items) |label| allocator.free(label);
        self.owned_labels.deinit(allocator);
        self.* = undefined;
    }

    pub fn receivePacket(
        self: *RelayService,
        allocator: std.mem.Allocator,
        addr: PeerAddr,
        packet: relay_protocol.RelayPacket,
        options: ServiceOptions,
    ) !AddressedOutbox {
        const dispatch_options = try self.prepareDispatchOptions(allocator, packet.message, options.dispatch);
        if (self.findPeerIndexByAddr(addr)) |peer_index| {
            var packets = try relay_pump.handlePeerPacket(allocator, &self.core, peer_index, packet, dispatch_options);
            defer packets.deinit(allocator);
            return self.addressPackets(allocator, packets);
        }

        return switch (packet.message) {
            .client_hello => |hello| try self.receiveClientHello(allocator, addr, packet, hello, .{
                .peer_id = options.peer_id,
                .dispatch = dispatch_options,
            }),
            else => .{},
        };
    }

    pub fn pollResends(self: *RelayService, allocator: std.mem.Allocator, now_ms: i64) !AddressedOutbox {
        var packets = try relay_pump.pollResends(allocator, &self.core, now_ms);
        defer packets.deinit(allocator);
        return self.addressPackets(allocator, packets);
    }

    pub fn pruneTimeouts(
        self: *RelayService,
        allocator: std.mem.Allocator,
        now_ms: i64,
        link_timeout_ms: i64,
    ) !AddressedOutbox {
        var outbox: AddressedOutbox = .{};
        errdefer outbox.deinit(allocator);

        var idx: usize = 0;
        while (idx < self.peers_by_addr.items.len) {
            const peer_index = self.peers_by_addr.items[idx].peer_index;
            if (peer_index >= self.core.peers.items.len) {
                _ = self.peers_by_addr.orderedRemove(idx);
                continue;
            }
            if (!relay_lobby.isTimedOut(self.core.peers.items[peer_index].peer, now_ms, link_timeout_ms)) {
                idx += 1;
                continue;
            }

            _ = self.peers_by_addr.orderedRemove(idx);
            var disconnect = try relay_dispatch.handleDisconnect(allocator, &self.core, peer_index, "timeout", now_ms);
            defer disconnect.deinit(allocator);
            var packets = try relay_pump.packetizeOutbox(allocator, &self.core, disconnect, now_ms);
            defer packets.deinit(allocator);
            try self.appendAddressedPackets(allocator, packets, &outbox);
        }
        return outbox;
    }

    fn receiveClientHello(
        self: *RelayService,
        allocator: std.mem.Allocator,
        addr: PeerAddr,
        packet: relay_protocol.RelayPacket,
        hello: relay_protocol.ClientHello,
        options: ServiceOptions,
    ) !AddressedOutbox {
        if (hello.protocol_version != relay_protocol.protocol_version) {
            var temp: relay_pump.PacketOutbox = .{};
            defer temp.deinit(allocator);
            var link: relay_reliable.RelayReliableLink = .{};
            defer link.deinit(allocator);
            const welcome = try link.buildPacket(allocator, .{ .client_welcome = .{
                .accepted = false,
                .reason = "protocol_mismatch_v5_required",
                .protocol_version = relay_protocol.protocol_version,
            } }, true, options.dispatch.now_ms);
            var owned = try relay_protocol.clonePacket(allocator, welcome);
            errdefer relay_protocol.deinitPacket(allocator, &owned);
            try temp.items.append(allocator, .{ .peer_index = 0, .packet = owned });
            owned = .{};
            return addressTemporaryPacket(allocator, addr, temp);
        }

        const peer_id = if (options.peer_id.len != 0) options.peer_id else try self.allocLabel(allocator, "p", &self.next_peer_id);
        const build_id = try self.allocOwnedText(allocator, hello.build_id);
        const peer_name = try self.allocOwnedText(allocator, hello.peer_name);
        const peer_index = try self.addPeer(allocator, addr, .{
            .peer_id = peer_id,
            .build_id = build_id,
            .peer_name = peer_name,
            .last_seen_ms = options.dispatch.now_ms,
        });
        var packets = try relay_pump.handleClientHello(allocator, &self.core, peer_index, hello, options.dispatch.now_ms);
        defer packets.deinit(allocator);
        self.core.peers.items[peer_index].peer.build_id = build_id;
        self.core.peers.items[peer_index].peer.peer_name = peer_name;
        if (packet.reliable and packet.seq > 0) {
            self.core.peers.items[peer_index].link.primeRecvSeq(packet.seq);
        }
        return self.addressPackets(allocator, packets);
    }

    fn addPeer(self: *RelayService, allocator: std.mem.Allocator, addr: PeerAddr, peer: relay_lobby.Peer) !usize {
        const peer_index = try self.core.addPeer(allocator, peer);
        errdefer _ = self.core.peers.pop();
        try self.peers_by_addr.append(allocator, .{
            .addr = addr,
            .peer_index = peer_index,
        });
        return peer_index;
    }

    fn prepareDispatchOptions(
        self: *RelayService,
        allocator: std.mem.Allocator,
        message: relay_protocol.NetMessage,
        base: relay_dispatch.DispatchOptions,
    ) !relay_dispatch.DispatchOptions {
        var options = base;
        switch (message) {
            .room_create => {
                if (isDefaultRoomCode(options.room_code)) {
                    options.room_code = try self.allocRoomCode();
                }
                if (options.session_id.len == 0) {
                    options.session_id = try self.allocLabel(allocator, "s", &self.next_session_id);
                }
                if (options.reconnect_token.len == 0) {
                    options.reconnect_token = try self.allocLabel(allocator, "r", &self.next_reconnect_token);
                }
            },
            .room_join => {
                if (options.reconnect_token.len == 0) {
                    options.reconnect_token = try self.allocLabel(allocator, "r", &self.next_reconnect_token);
                }
            },
            else => {},
        }
        return options;
    }

    fn allocLabel(self: *RelayService, allocator: std.mem.Allocator, prefix: []const u8, counter: *u64) ![]const u8 {
        const label = try std.fmt.allocPrint(allocator, "{s}{d}", .{ prefix, counter.* });
        errdefer allocator.free(label);
        counter.* += 1;
        try self.owned_labels.append(allocator, label);
        return label;
    }

    fn allocOwnedText(self: *RelayService, allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
        if (text.len == 0) return "";
        const owned = try allocator.dupe(u8, text);
        errdefer allocator.free(owned);
        try self.owned_labels.append(allocator, owned);
        return owned;
    }

    fn allocRoomCode(self: *RelayService) !room_code.RoomCode {
        for (0..36 * 36 * 36 * 36) |_| {
            const code = roomCodeFromOrdinal(self.next_room_code);
            self.next_room_code +%= 1;
            if (self.core.findRoomByCode(code) == null) return code;
        }
        return error.RoomCodeExhausted;
    }

    fn addressPackets(self: *const RelayService, allocator: std.mem.Allocator, packets: relay_pump.PacketOutbox) !AddressedOutbox {
        var outbox: AddressedOutbox = .{};
        errdefer outbox.deinit(allocator);
        try self.appendAddressedPackets(allocator, packets, &outbox);
        return outbox;
    }

    fn appendAddressedPackets(
        self: *const RelayService,
        allocator: std.mem.Allocator,
        packets: relay_pump.PacketOutbox,
        outbox: *AddressedOutbox,
    ) !void {
        for (packets.items.items) |item| {
            const addr = self.findAddrByPeerIndex(item.peer_index) orelse continue;
            var packet = try relay_protocol.clonePacket(allocator, item.packet);
            errdefer relay_protocol.deinitPacket(allocator, &packet);
            try outbox.items.append(allocator, .{
                .addr = addr,
                .packet = packet,
            });
            packet = .{};
        }
    }

    fn findPeerIndexByAddr(self: *const RelayService, addr: PeerAddr) ?usize {
        for (self.peers_by_addr.items) |item| {
            if (item.addr.eql(addr)) return item.peer_index;
        }
        return null;
    }

    fn findAddrByPeerIndex(self: *const RelayService, peer_index: usize) ?PeerAddr {
        for (self.peers_by_addr.items) |item| {
            if (item.peer_index == peer_index) return item.addr;
        }
        return null;
    }
};

fn addressTemporaryPacket(allocator: std.mem.Allocator, addr: PeerAddr, packets: relay_pump.PacketOutbox) !AddressedOutbox {
    var outbox: AddressedOutbox = .{};
    errdefer outbox.deinit(allocator);
    for (packets.items.items) |item| {
        var packet = try relay_protocol.clonePacket(allocator, item.packet);
        errdefer relay_protocol.deinitPacket(allocator, &packet);
        try outbox.items.append(allocator, .{
            .addr = addr,
            .packet = packet,
        });
        packet = .{};
    }
    return outbox;
}

fn isDefaultRoomCode(code: room_code.RoomCode) bool {
    const default_code: room_code.RoomCode = .{ .bytes = .{ 'a', 'a', 'a', 'a' } };
    return std.mem.eql(u8, &code.bytes, &default_code.bytes);
}

fn roomCodeFromOrdinal(ordinal: u32) room_code.RoomCode {
    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
    var value = ordinal % (36 * 36 * 36 * 36);
    var out: room_code.RoomCode = .{ .bytes = .{ 'a', 'a', 'a', 'a' } };
    var idx: usize = 4;
    while (idx > 0) {
        idx -= 1;
        out.bytes[idx] = alphabet[value % alphabet.len];
        value /= alphabet.len;
    }
    return out;
}

fn testAddr(port: u16) PeerAddr {
    return .{ .host = .{ 127, 0, 0, 1 }, .port = port };
}

test "relay service drops unregistered non-hello packets" {
    const allocator = std.testing.allocator;
    var service: RelayService = .{};
    defer service.deinit(allocator);

    var outbox = try service.receivePacket(allocator, testAddr(1001), .{ .message = .{ .ping = .{} } }, .{ .peer_id = "peer" });
    defer outbox.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), outbox.items.items.len);
    try std.testing.expectEqual(@as(usize, 0), service.core.peers.items.len);
}

test "relay service registers client hello and primes reliable receive seq" {
    const allocator = std.testing.allocator;
    var service: RelayService = .{};
    defer service.deinit(allocator);
    const addr = testAddr(1001);

    var outbox = try service.receivePacket(allocator, addr, .{
        .seq = 9,
        .reliable = true,
        .message = .{ .client_hello = .{
            .protocol_version = relay_protocol.protocol_version,
            .build_id = "0.1.0",
            .peer_name = "host",
        } },
    }, .{
        .peer_id = "peer-1",
        .dispatch = .{ .now_ms = 1000 },
    });
    defer outbox.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), service.core.peers.items.len);
    try std.testing.expectEqual(@as(i32, 9), service.core.peers.items[0].link.recv_highest_seq);
    try std.testing.expect(outbox.items.items[0].addr.eql(addr));
    switch (outbox.items.items[0].packet.message) {
        .client_welcome => |welcome| {
            try std.testing.expect(welcome.accepted);
            try std.testing.expectEqualStrings("peer-1", welcome.peer_id);
        },
        else => return error.TestExpectedEqual,
    }
}

test "relay service owns client hello identity fields" {
    const allocator = std.testing.allocator;
    var service: RelayService = .{};
    defer service.deinit(allocator);
    const addr = testAddr(1001);

    var build_id = [_]u8{ '0', '.', '1', '.', '0' };
    var peer_name = [_]u8{ 'h', 'o', 's', 't' };
    var outbox = try service.receivePacket(allocator, addr, .{
        .message = .{ .client_hello = .{
            .protocol_version = relay_protocol.protocol_version,
            .build_id = build_id[0..],
            .peer_name = peer_name[0..],
        } },
    }, .{
        .peer_id = "peer-1",
        .dispatch = .{ .now_ms = 1000 },
    });
    defer outbox.deinit(allocator);

    @memset(build_id[0..], 'x');
    @memset(peer_name[0..], 'y');

    try std.testing.expectEqualStrings("0.1.0", service.core.peers.items[0].peer.build_id);
    try std.testing.expectEqualStrings("host", service.core.peers.items[0].peer.peer_name);
}

test "relay service generates owned peer ids when omitted" {
    const allocator = std.testing.allocator;
    var service: RelayService = .{};
    defer service.deinit(allocator);
    const addr = testAddr(1001);

    var outbox = try service.receivePacket(allocator, addr, .{
        .message = .{ .client_hello = .{ .protocol_version = relay_protocol.protocol_version } },
    }, .{ .dispatch = .{ .now_ms = 1000 } });
    defer outbox.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), service.owned_labels.items.len);
    try std.testing.expectEqualStrings("p1", service.core.peers.items[0].peer.peer_id);
    switch (outbox.items.items[0].packet.message) {
        .client_welcome => |welcome| try std.testing.expectEqualStrings("p1", welcome.peer_id),
        else => return error.TestExpectedEqual,
    }
}

test "relay service rejects protocol mismatch without registering peer" {
    const allocator = std.testing.allocator;
    var service: RelayService = .{};
    defer service.deinit(allocator);

    var outbox = try service.receivePacket(allocator, testAddr(1001), .{
        .seq = 1,
        .reliable = true,
        .message = .{ .client_hello = .{ .protocol_version = relay_protocol.protocol_version - 1 } },
    }, .{ .peer_id = "peer-1", .dispatch = .{ .now_ms = 1000 } });
    defer outbox.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), service.core.peers.items.len);
    try std.testing.expectEqual(@as(usize, 1), outbox.items.items.len);
    switch (outbox.items.items[0].packet.message) {
        .client_welcome => |welcome| {
            try std.testing.expect(!welcome.accepted);
            try std.testing.expectEqualStrings("protocol_mismatch_v5_required", welcome.reason);
        },
        else => return error.TestExpectedEqual,
    }
}

test "relay service generates room codes session ids and reconnect tokens" {
    const allocator = std.testing.allocator;
    var service: RelayService = .{};
    defer service.deinit(allocator);
    const host_addr = testAddr(1001);
    const guest_addr = testAddr(1002);

    var host_welcome = try service.receivePacket(allocator, host_addr, .{
        .message = .{ .client_hello = .{ .protocol_version = relay_protocol.protocol_version } },
    }, .{ .dispatch = .{ .now_ms = 1000 } });
    defer host_welcome.deinit(allocator);
    var guest_welcome = try service.receivePacket(allocator, guest_addr, .{
        .message = .{ .client_hello = .{ .protocol_version = relay_protocol.protocol_version } },
    }, .{ .dispatch = .{ .now_ms = 1001 } });
    defer guest_welcome.deinit(allocator);

    var created = try service.receivePacket(allocator, host_addr, .{
        .message = .{ .room_create = .{ .player_count = 2 } },
    }, .{ .dispatch = .{ .now_ms = 1002 } });
    defer created.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), service.core.rooms.items.len);
    try std.testing.expectEqualStrings("aaaa", room_code.roomCodeSlice(&service.core.rooms.items[0].room.room_code));
    try std.testing.expectEqualStrings("s1", service.core.rooms.items[0].room.session_id);
    try std.testing.expectEqualStrings("r1", service.core.rooms.items[0].room.slots[0].reconnect_token);

    var joined = try service.receivePacket(allocator, guest_addr, .{
        .message = .{ .room_join = .{ .room_code = service.core.rooms.items[0].room.room_code } },
    }, .{ .dispatch = .{ .now_ms = 1003 } });
    defer joined.deinit(allocator);
    try std.testing.expectEqualStrings("r2", service.core.rooms.items[0].room.slots[1].reconnect_token);
}

test "relay service routes registered ping response to peer address" {
    const allocator = std.testing.allocator;
    var service: RelayService = .{};
    defer service.deinit(allocator);
    const addr = testAddr(1001);

    var welcome = try service.receivePacket(allocator, addr, .{
        .message = .{ .client_hello = .{ .protocol_version = relay_protocol.protocol_version } },
    }, .{ .peer_id = "peer-1", .dispatch = .{ .now_ms = 1000 } });
    defer welcome.deinit(allocator);

    var pong = try service.receivePacket(allocator, addr, .{
        .message = .{ .ping = .{ .stamp_ms = 42 } },
    }, .{ .dispatch = .{ .now_ms = 1001 } });
    defer pong.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), pong.items.items.len);
    try std.testing.expect(pong.items.items[0].addr.eql(addr));
    switch (pong.items.items[0].packet.message) {
        .pong => |message| try std.testing.expectEqual(@as(i32, 42), message.stamp_ms),
        else => return error.TestExpectedEqual,
    }
}

test "relay service polls resends with peer addresses" {
    const allocator = std.testing.allocator;
    var service: RelayService = .{};
    defer service.deinit(allocator);
    const addr = testAddr(1001);

    var welcome = try service.receivePacket(allocator, addr, .{
        .message = .{ .client_hello = .{ .protocol_version = relay_protocol.protocol_version } },
    }, .{ .peer_id = "peer-1", .dispatch = .{ .now_ms = 1000 } });
    defer welcome.deinit(allocator);

    var resends = try service.pollResends(allocator, 1040);
    defer resends.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), resends.items.items.len);
    try std.testing.expect(resends.items.items[0].addr.eql(addr));
    switch (resends.items.items[0].packet.message) {
        .client_welcome => |message| try std.testing.expectEqualStrings("peer-1", message.peer_id),
        else => return error.TestExpectedEqual,
    }
}

test "relay service prunes timed out peer and routes disconnect packets" {
    const allocator = std.testing.allocator;
    var service: RelayService = .{};
    defer service.deinit(allocator);
    const host_addr = testAddr(1001);
    const guest_addr = testAddr(1002);
    const code = try room_code.parseRoomCode("ABCD");

    var host_welcome = try service.receivePacket(allocator, host_addr, .{
        .message = .{ .client_hello = .{ .protocol_version = relay_protocol.protocol_version } },
    }, .{ .peer_id = "host", .dispatch = .{ .now_ms = 1000 } });
    defer host_welcome.deinit(allocator);
    var guest_welcome = try service.receivePacket(allocator, guest_addr, .{
        .message = .{ .client_hello = .{ .protocol_version = relay_protocol.protocol_version } },
    }, .{ .peer_id = "guest", .dispatch = .{ .now_ms = 1001 } });
    defer guest_welcome.deinit(allocator);

    var created = try service.receivePacket(allocator, host_addr, .{
        .message = .{ .room_create = .{ .player_count = 2 } },
    }, .{ .dispatch = .{
        .now_ms = 1002,
        .room_code = code,
        .session_id = "session",
        .reconnect_token = "host-token",
    } });
    defer created.deinit(allocator);
    var joined = try service.receivePacket(allocator, guest_addr, .{
        .message = .{ .room_join = .{ .room_code = code } },
    }, .{ .dispatch = .{
        .now_ms = 1003,
        .reconnect_token = "guest-token",
    } });
    defer joined.deinit(allocator);

    service.core.peers.items[0].peer.last_seen_ms = 4000;
    service.core.peers.items[1].peer.last_seen_ms = 1000;
    var pruned = try service.pruneTimeouts(allocator, 6000, relay_protocol.link_timeout_ms);
    defer pruned.deinit(allocator);

    try std.testing.expect(service.findPeerIndexByAddr(guest_addr) == null);
    try std.testing.expectEqual(@as(usize, 1), service.core.rooms.items.len);
    try std.testing.expectEqualStrings("", service.core.rooms.items[0].room.slots[1].peer_id);
    try std.testing.expectEqual(@as(usize, 2), pruned.items.items.len);
    try std.testing.expect(pruned.items.items[0].addr.eql(host_addr));
    try std.testing.expect(pruned.items.items[1].addr.eql(host_addr));
    switch (pruned.items.items[1].packet.message) {
        .peer_disconnect => |notice| try std.testing.expectEqual(@as(i32, 1), notice.slot_index),
        else => return error.TestExpectedEqual,
    }
}
