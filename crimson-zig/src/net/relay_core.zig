const std = @import("std");

const relay_lobby = @import("relay_lobby.zig");
const relay_reliable = @import("relay_reliable.zig");
const relay_room = @import("relay_room.zig");
const room_code = @import("room_code.zig");

pub const PeerRecord = struct {
    peer: relay_lobby.Peer = .{},
    link: relay_reliable.RelayReliableLink = .{},

    pub fn deinit(self: *PeerRecord, allocator: std.mem.Allocator) void {
        self.link.deinit(allocator);
        self.* = undefined;
    }
};

pub const RoomRecord = struct {
    room: relay_room.Room,

    pub fn deinit(self: *RoomRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.room.slots);
        self.* = undefined;
    }
};

pub const ReconnectMapping = struct {
    room_index: usize,
    slot_index: i32,
};

pub const RelayCore = struct {
    peers: std.ArrayList(PeerRecord) = .empty,
    rooms: std.ArrayList(RoomRecord) = .empty,

    pub fn deinit(self: *RelayCore, allocator: std.mem.Allocator) void {
        for (self.peers.items) |*peer| peer.deinit(allocator);
        self.peers.deinit(allocator);
        for (self.rooms.items) |*room| room.deinit(allocator);
        self.rooms.deinit(allocator);
        self.* = undefined;
    }

    pub fn addPeer(self: *RelayCore, allocator: std.mem.Allocator, peer: relay_lobby.Peer) !usize {
        try self.peers.append(allocator, .{ .peer = peer });
        return self.peers.items.len - 1;
    }

    pub fn addRoom(self: *RelayCore, allocator: std.mem.Allocator, room: relay_room.Room) !usize {
        try self.rooms.append(allocator, .{ .room = room });
        return self.rooms.items.len - 1;
    }

    pub fn findPeerById(self: *const RelayCore, peer_id: []const u8) ?usize {
        for (self.peers.items, 0..) |record, idx| {
            if (std.mem.eql(u8, record.peer.peer_id, peer_id)) return idx;
        }
        return null;
    }

    pub fn findRoomByCode(self: *const RelayCore, code: room_code.RoomCode) ?usize {
        for (self.rooms.items, 0..) |record, idx| {
            if (std.mem.eql(u8, room_code.roomCodeSlice(&record.room.room_code), room_code.roomCodeSlice(&code))) return idx;
        }
        return null;
    }

    pub fn findReconnectToken(self: *const RelayCore, reconnect_token: []const u8) ?ReconnectMapping {
        if (reconnect_token.len == 0) return null;
        for (self.rooms.items, 0..) |record, room_idx| {
            for (record.room.slots) |slot| {
                if (std.mem.eql(u8, slot.reconnect_token, reconnect_token)) {
                    return .{ .room_index = room_idx, .slot_index = slot.slot_index };
                }
            }
        }
        return null;
    }

    pub fn connectedPeerRecipients(
        self: *const RelayCore,
        allocator: std.mem.Allocator,
        room: relay_room.Room,
        exclude_peer_id: []const u8,
    ) !std.ArrayList(usize) {
        var out: std.ArrayList(usize) = .empty;
        errdefer out.deinit(allocator);

        for (room.slots) |slot| {
            if (!slot.connected()) continue;
            if (std.mem.eql(u8, slot.peer_id, exclude_peer_id)) continue;
            if (self.findPeerById(slot.peer_id)) |peer_idx| {
                try out.append(allocator, peer_idx);
            }
        }
        return out;
    }

    pub fn disconnectPeer(self: *RelayCore, peer_index: usize, reason: []const u8, now_ms: i64) ?relay_lobby.DisconnectResult {
        if (peer_index >= self.peers.items.len) return null;
        const peer = self.peers.items[peer_index].peer;
        const code = peer.room_code orelse return null;
        const room_index = self.findRoomByCode(code) orelse return null;
        return relay_lobby.disconnectPeer(&self.rooms.items[room_index].room, peer, reason, now_ms);
    }

    pub fn removeRoom(self: *RelayCore, allocator: std.mem.Allocator, room_index: usize) bool {
        if (room_index >= self.rooms.items.len) return false;
        var removed = self.rooms.orderedRemove(room_index);
        removed.deinit(allocator);
        return true;
    }
};

test "relay core stores peers and rooms and finds them by borrowed ids" {
    const allocator = std.testing.allocator;
    var core: RelayCore = .{};
    defer core.deinit(allocator);

    const peer_idx = try core.addPeer(allocator, .{ .peer_id = "host", .build_id = "0.1.0" });
    try std.testing.expectEqual(@as(usize, 0), peer_idx);
    try std.testing.expectEqual(@as(usize, 0), core.findPeerById("host").?);
    try std.testing.expect(core.findPeerById("missing") == null);

    const host = &core.peers.items[peer_idx].peer;
    const room = try relay_lobby.createRoom(allocator, host, .{ .player_count = 2 }, .{
        .code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .host_reconnect_token = "host-token",
    });
    const room_idx = try core.addRoom(allocator, room);
    try std.testing.expectEqual(@as(usize, 0), room_idx);
    try std.testing.expectEqual(@as(usize, 0), core.findRoomByCode(try room_code.parseRoomCode("abcd")).?);
}

test "relay core finds reconnect tokens across rooms" {
    const allocator = std.testing.allocator;
    var core: RelayCore = .{};
    defer core.deinit(allocator);

    const host_idx = try core.addPeer(allocator, .{ .peer_id = "host" });
    var room = try relay_lobby.createRoom(allocator, &core.peers.items[host_idx].peer, .{ .player_count = 2 }, .{
        .code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .host_reconnect_token = "host-token",
    });
    room.slots[1].reconnect_token = "guest-token";
    _ = try core.addRoom(allocator, room);

    const mapping = core.findReconnectToken("guest-token").?;
    try std.testing.expectEqual(@as(usize, 0), mapping.room_index);
    try std.testing.expectEqual(@as(i32, 1), mapping.slot_index);
    try std.testing.expect(core.findReconnectToken("missing") == null);
}

test "relay core recipient lookup skips disconnected and missing peers" {
    const allocator = std.testing.allocator;
    var core: RelayCore = .{};
    defer core.deinit(allocator);

    const host_idx = try core.addPeer(allocator, .{ .peer_id = "host" });
    const guest_idx = try core.addPeer(allocator, .{ .peer_id = "guest" });
    var room = try relay_lobby.createRoom(allocator, &core.peers.items[host_idx].peer, .{ .player_count = 4 }, .{
        .code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .host_reconnect_token = "host-token",
    });
    room.slots[1].peer_id = "guest";
    room.slots[2].peer_id = "missing-peer";
    _ = try core.addRoom(allocator, room);

    var recipients = try core.connectedPeerRecipients(allocator, core.rooms.items[0].room, "host");
    defer recipients.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), recipients.items.len);
    try std.testing.expectEqual(guest_idx, recipients.items[0]);
}

test "relay core disconnects peer and removes evicted room" {
    const allocator = std.testing.allocator;
    var core: RelayCore = .{};
    defer core.deinit(allocator);

    const host_idx = try core.addPeer(allocator, .{ .peer_id = "host" });
    const room = try relay_lobby.createRoom(allocator, &core.peers.items[host_idx].peer, .{ .player_count = 1 }, .{
        .code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .host_reconnect_token = "host-token",
    });
    _ = try core.addRoom(allocator, room);

    const result = core.disconnectPeer(host_idx, "timeout", 5000).?;
    try std.testing.expect(result.evict_room);
    try std.testing.expectEqual(@as(i32, 0), result.notice.slot_index);
    try std.testing.expect(core.removeRoom(allocator, 0));
    try std.testing.expectEqual(@as(usize, 0), core.rooms.items.len);
}
