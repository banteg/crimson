const std = @import("std");

const lockstep_protocol = @import("lockstep_protocol.zig");
const relay_protocol = @import("relay_protocol.zig");
const relay_room = @import("relay_room.zig");
const room_code = @import("room_code.zig");
const session_settings = @import("session_settings.zig");

pub const Peer = struct {
    peer_id: []const u8 = "",
    build_id: []const u8 = "",
    peer_name: []const u8 = "",
    room_code: ?room_code.RoomCode = null,
    slot_index: i32 = -1,
    last_seen_ms: i64 = 0,
};

pub const CreateRoomOptions = struct {
    code: room_code.RoomCode,
    session_id: []const u8,
    host_reconnect_token: []const u8,
};

pub const JoinOptions = struct {
    reconnect_slot_index: ?i32 = null,
    reconnect_timeout_ms: i64 = relay_protocol.reconnect_timeout_ms,
    now_ms: i64 = 0,
    host_build_id: []const u8 = "",
    new_reconnect_token: []const u8 = "",
};

pub const JoinResult = struct {
    slot_index: i32,
    reconnect_token: []const u8,
    should_send_room_start: bool,
};

pub const ReadyResult = struct {
    started_now: bool,
};

pub const DisconnectResult = struct {
    notice: relay_protocol.PeerDisconnect,
    evict_room: bool,
};

pub const LobbyError = error{
    AlreadyInRoom,
    RoomFull,
    SlotBusy,
    BuildMismatch,
    NotInRoom,
    BadSlot,
    SlotOwnerMismatch,
};

pub fn createRoom(
    allocator: std.mem.Allocator,
    peer: *Peer,
    message: relay_protocol.RoomCreate,
    options: CreateRoomOptions,
) !relay_room.Room {
    if (peer.room_code != null) return error.AlreadyInRoom;

    const settings = session_settings.fromRoomCreate(message);
    const slots = try relay_room.allocSlots(allocator, settings.player_count);
    errdefer allocator.free(slots);

    slots[0] = .{
        .slot_index = 0,
        .peer_id = peer.peer_id,
        .peer_name = peer.peer_name,
        .ready = true,
        .reconnect_token = options.host_reconnect_token,
    };

    peer.room_code = options.code;
    peer.slot_index = 0;

    return .{
        .room_code = options.code,
        .session_id = options.session_id,
        .settings = settings,
        .status = message.status,
        .slots = slots,
    };
}

pub fn joinRoom(
    room: *relay_room.Room,
    peer: *Peer,
    options: JoinOptions,
) LobbyError!JoinResult {
    if (peer.room_code != null) return error.AlreadyInRoom;

    const slot_index = options.reconnect_slot_index orelse room.nextFreeSlot();
    if (slot_index < 0) return error.RoomFull;
    const idx = relay_room.slotIndex(room.slots, slot_index) orelse return error.BadSlot;
    const slot = &room.slots[idx];

    if (slot.connected() and !std.mem.eql(u8, slot.peer_id, peer.peer_id)) {
        const age = @max(@as(i64, 0), options.now_ms - slot.disconnected_ms);
        if (age < options.reconnect_timeout_ms) return error.SlotBusy;
    }

    if (options.host_build_id.len != 0 and peer.build_id.len != 0) {
        if (!lockstep_protocol.buildsCompatible(peer.build_id, options.host_build_id)) {
            return error.BuildMismatch;
        }
    }

    slot.peer_id = peer.peer_id;
    slot.peer_name = peer.peer_name;
    slot.ready = room.started;
    slot.disconnected_ms = 0;
    if (slot.reconnect_token.len == 0) {
        slot.reconnect_token = options.new_reconnect_token;
    }

    peer.room_code = room.room_code;
    peer.slot_index = slot.slot_index;

    return .{
        .slot_index = slot.slot_index,
        .reconnect_token = slot.reconnect_token,
        .should_send_room_start = room.started,
    };
}

pub fn applyReady(room: *relay_room.Room, peer: Peer, message: relay_protocol.RoomReady, now_ms: i64) LobbyError!ReadyResult {
    if (peer.room_code == null) return error.NotInRoom;
    const idx = relay_room.slotIndex(room.slots, peer.slot_index) orelse return error.BadSlot;
    const slot = &room.slots[idx];
    if (!std.mem.eql(u8, slot.peer_id, peer.peer_id)) return error.SlotOwnerMismatch;

    slot.ready = message.ready;
    if (!room.started and room.allReady()) {
        room.started = true;
        room.seed = startSeed(now_ms);
        room.start_tick = 0;
        return .{ .started_now = true };
    }
    return .{ .started_now = false };
}

pub fn disconnectPeer(room: *relay_room.Room, peer: Peer, reason: []const u8, now_ms: i64) ?DisconnectResult {
    const idx = relay_room.slotIndex(room.slots, peer.slot_index) orelse return null;
    const slot = &room.slots[idx];
    if (!std.mem.eql(u8, slot.peer_id, peer.peer_id)) return null;

    slot.disconnect(now_ms);
    return .{
        .notice = .{
            .slot_index = peer.slot_index,
            .reason = reason,
        },
        .evict_room = room.allDisconnected(),
    };
}

pub fn isTimedOut(peer: Peer, now_ms: i64, link_timeout_ms: i64) bool {
    const timeout = @max(@as(i64, 250), link_timeout_ms);
    return now_ms - peer.last_seen_ms >= timeout;
}

pub fn startSeed(now_ms: i64) i32 {
    const unsigned_now: u64 = @intCast(@max(now_ms, 0));
    const value: u32 = @truncate(unsigned_now *% 1_103_515_245 +% 12_345);
    return @bitCast(value);
}

test "relay lobby creates room with ready host slot" {
    const allocator = std.testing.allocator;
    var host: Peer = .{ .peer_id = "host-id", .build_id = "0.1.0", .peer_name = "host" };
    const code = try room_code.parseRoomCode("ABCD");
    var room = try createRoom(allocator, &host, .{
        .mode_id = 1,
        .player_count = 2,
        .netcode_mode = .rollback,
    }, .{
        .code = code,
        .session_id = "session",
        .host_reconnect_token = "host-token",
    });
    defer allocator.free(room.slots);

    try std.testing.expectEqualStrings("abcd", room_code.roomCodeSlice(&room.room_code));
    try std.testing.expectEqualStrings("session", room.session_id);
    try std.testing.expectEqual(@as(i32, 2), room.settings.player_count);
    try std.testing.expectEqual(@as(i32, 0), host.slot_index);
    try std.testing.expect(host.room_code != null);
    try std.testing.expect(room.slots[0].connected());
    try std.testing.expect(room.slots[0].ready);
    try std.testing.expectEqualStrings("host-token", room.slots[0].reconnect_token);
}

test "relay lobby joins next free slot and waits for ready before start" {
    const allocator = std.testing.allocator;
    var host: Peer = .{ .peer_id = "host-id", .build_id = "0.1.0", .peer_name = "host" };
    var room = try createRoom(allocator, &host, .{ .player_count = 2 }, .{
        .code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .host_reconnect_token = "host-token",
    });
    defer allocator.free(room.slots);

    var guest: Peer = .{ .peer_id = "guest-id", .build_id = "0.1.0", .peer_name = "guest" };
    const joined = try joinRoom(&room, &guest, .{
        .host_build_id = host.build_id,
        .new_reconnect_token = "guest-token",
    });
    try std.testing.expectEqual(@as(i32, 1), joined.slot_index);
    try std.testing.expect(!joined.should_send_room_start);
    try std.testing.expectEqualStrings("guest-token", joined.reconnect_token);
    try std.testing.expectEqual(@as(i32, 1), guest.slot_index);
    try std.testing.expect(!room.slots[1].ready);
    try std.testing.expect(!room.started);

    const ready = try applyReady(&room, guest, .{ .ready = true }, 1004);
    try std.testing.expect(ready.started_now);
    try std.testing.expect(room.started);
    try std.testing.expectEqual(@as(i32, 0), room.start_tick);
    try std.testing.expectEqual(startSeed(1004), room.seed);
}

test "relay lobby reconnect reclaims disconnected started slot" {
    const allocator = std.testing.allocator;
    var host: Peer = .{ .peer_id = "host-id", .build_id = "0.1.0", .peer_name = "host" };
    var room = try createRoom(allocator, &host, .{ .player_count = 2 }, .{
        .code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .host_reconnect_token = "host-token",
    });
    defer allocator.free(room.slots);
    room.started = true;
    room.slots[1] = .{
        .slot_index = 1,
        .peer_id = "",
        .peer_name = "",
        .ready = false,
        .reconnect_token = "guest-token",
        .disconnected_ms = 2200,
    };

    var guest: Peer = .{ .peer_id = "guest-new", .build_id = "0.1.0", .peer_name = "guest" };
    const joined = try joinRoom(&room, &guest, .{
        .reconnect_slot_index = 1,
        .now_ms = 2202,
        .host_build_id = host.build_id,
    });
    try std.testing.expectEqual(@as(i32, 1), joined.slot_index);
    try std.testing.expect(joined.should_send_room_start);
    try std.testing.expectEqualStrings("guest-token", joined.reconnect_token);
    try std.testing.expect(room.slots[1].ready);
    try std.testing.expectEqualStrings("guest-new", room.slots[1].peer_id);
}

test "relay lobby rejects busy reconnect slot and build mismatch" {
    const allocator = std.testing.allocator;
    var host: Peer = .{ .peer_id = "host-id", .build_id = "0.1.0+gabcdef1", .peer_name = "host" };
    var room = try createRoom(allocator, &host, .{ .player_count = 2 }, .{
        .code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .host_reconnect_token = "host-token",
    });
    defer allocator.free(room.slots);
    room.slots[1] = .{
        .slot_index = 1,
        .peer_id = "old-peer",
        .peer_name = "old",
        .ready = false,
        .reconnect_token = "guest-token",
        .disconnected_ms = 1000,
    };

    var guest: Peer = .{ .peer_id = "guest-id", .build_id = "0.1.0+gabcdef1", .peer_name = "guest" };
    try std.testing.expectError(error.SlotBusy, joinRoom(&room, &guest, .{
        .reconnect_slot_index = 1,
        .now_ms = 1200,
        .reconnect_timeout_ms = 500,
        .host_build_id = host.build_id,
    }));

    room.slots[1].disconnect(1000);
    var mismatched: Peer = .{ .peer_id = "guest-id", .build_id = "0.1.0+gabcdef2", .peer_name = "guest" };
    try std.testing.expectError(error.BuildMismatch, joinRoom(&room, &mismatched, .{
        .now_ms = 2000,
        .host_build_id = host.build_id,
    }));
}

test "relay lobby ready rejects wrong owner" {
    const allocator = std.testing.allocator;
    var host: Peer = .{ .peer_id = "host-id" };
    var room = try createRoom(allocator, &host, .{ .player_count = 1 }, .{
        .code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .host_reconnect_token = "host-token",
    });
    defer allocator.free(room.slots);

    const stranger: Peer = .{ .peer_id = "other", .room_code = room.room_code, .slot_index = 0 };
    try std.testing.expectError(error.SlotOwnerMismatch, applyReady(&room, stranger, .{ .ready = true }, 10));
}

test "relay lobby disconnect clears slot and preserves reconnect token" {
    const allocator = std.testing.allocator;
    var host: Peer = .{ .peer_id = "host-id", .peer_name = "host" };
    var room = try createRoom(allocator, &host, .{ .player_count = 2 }, .{
        .code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .host_reconnect_token = "host-token",
    });
    defer allocator.free(room.slots);

    var guest: Peer = .{ .peer_id = "guest-id", .peer_name = "guest" };
    _ = try joinRoom(&room, &guest, .{ .new_reconnect_token = "guest-token" });

    const result = disconnectPeer(&room, guest, "timeout", 2200).?;
    try std.testing.expectEqual(@as(i32, 1), result.notice.slot_index);
    try std.testing.expectEqualStrings("timeout", result.notice.reason);
    try std.testing.expect(!result.evict_room);
    try std.testing.expect(!room.slots[1].connected());
    try std.testing.expect(!room.slots[1].ready);
    try std.testing.expectEqualStrings("", room.slots[1].peer_name);
    try std.testing.expectEqualStrings("guest-token", room.slots[1].reconnect_token);
    try std.testing.expectEqual(@as(i64, 2200), room.slots[1].disconnected_ms);
}

test "relay lobby disconnect signals eviction when last peer leaves" {
    const allocator = std.testing.allocator;
    var host: Peer = .{ .peer_id = "host-id", .peer_name = "host" };
    var room = try createRoom(allocator, &host, .{ .player_count = 1 }, .{
        .code = try room_code.parseRoomCode("ABCD"),
        .session_id = "session",
        .host_reconnect_token = "host-token",
    });
    defer allocator.free(room.slots);

    const result = disconnectPeer(&room, host, "closed", 3000).?;
    try std.testing.expect(result.evict_room);
    try std.testing.expect(room.allDisconnected());
}

test "relay lobby timeout uses python minimum timeout" {
    const peer: Peer = .{ .peer_id = "peer", .last_seen_ms = 1000 };
    try std.testing.expect(!isTimedOut(peer, 1249, 10));
    try std.testing.expect(isTimedOut(peer, 1250, 10));
    try std.testing.expect(!isTimedOut(peer, 5999, relay_protocol.link_timeout_ms));
    try std.testing.expect(isTimedOut(peer, 6000, relay_protocol.link_timeout_ms));
}
