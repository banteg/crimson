const std = @import("std");

const game_cfg = @import("../formats/game_cfg.zig");
const relay_protocol = @import("relay_protocol.zig");
const room_code = @import("room_code.zig");
const session_settings = @import("session_settings.zig");

pub const RoomSlot = struct {
    slot_index: i32,
    peer_id: []const u8 = "",
    peer_name: []const u8 = "",
    ready: bool = false,
    reconnect_token: []const u8 = "",
    disconnected_ms: i64 = 0,

    pub fn connected(self: RoomSlot) bool {
        return self.peer_id.len != 0;
    }

    pub fn toRelaySlot(self: RoomSlot) relay_protocol.RelaySlot {
        return .{
            .slot_index = self.slot_index,
            .connected = self.connected(),
            .ready = self.ready,
            .is_host = self.slot_index == 0,
            .peer_name = self.peer_name,
        };
    }

    pub fn disconnect(self: *RoomSlot, now_ms: i64) void {
        self.peer_id = "";
        self.peer_name = "";
        self.ready = false;
        self.disconnected_ms = now_ms;
    }
};

pub const Room = struct {
    room_code: room_code.RoomCode,
    session_id: []const u8,
    settings: session_settings.RelaySessionSettings,
    status: ?game_cfg.Status = null,
    started: bool = false,
    seed: i32 = 0,
    start_tick: i32 = 0,
    slots: []RoomSlot = &.{},

    pub fn allReady(self: Room) bool {
        for (self.slots) |slot| {
            if (!slot.connected() or !slot.ready) return false;
        }
        return true;
    }

    pub fn allDisconnected(self: Room) bool {
        for (self.slots) |slot| {
            if (slot.connected()) return false;
        }
        return true;
    }

    pub fn nextFreeSlot(self: Room) i32 {
        for (self.slots) |slot| {
            if (!slot.connected()) return slot.slot_index;
        }
        return -1;
    }

    pub fn relaySlots(self: Room, allocator: std.mem.Allocator) ![]relay_protocol.RelaySlot {
        const out = try allocator.alloc(relay_protocol.RelaySlot, self.slots.len);
        for (self.slots, 0..) |slot, idx| out[idx] = slot.toRelaySlot();
        return out;
    }

    pub fn roomState(self: Room, allocator: std.mem.Allocator) !OwnedRoomState {
        const slots = try self.relaySlots(allocator);
        errdefer allocator.free(slots);
        return .{
            .value = session_settings.roomStateFromSettings(self.settings, .{
                .room_code = self.room_code,
                .session_id = self.session_id,
                .slots = slots,
                .all_ready = self.allReady(),
                .started = self.started,
            }),
            .slots = slots,
        };
    }

    pub fn roomStartForSlot(self: Room, slot_index: i32) relay_protocol.RoomStart {
        const reconnect_token = if (slotIndex(self.slots, slot_index)) |idx| self.slots[idx].reconnect_token else "";
        return session_settings.roomStartFromSettings(self.settings, .{
            .room_code = self.room_code,
            .session_id = self.session_id,
            .seed = self.seed,
            .start_tick = self.start_tick,
            .slot_index = slot_index,
            .host_slot_index = 0,
            .reconnect_token = reconnect_token,
            .status = self.status,
        });
    }
};

pub const OwnedRoomState = struct {
    value: relay_protocol.RoomState,
    slots: []relay_protocol.RelaySlot,

    pub fn deinit(self: *OwnedRoomState, allocator: std.mem.Allocator) void {
        allocator.free(self.slots);
        self.* = undefined;
    }
};

pub fn allocSlots(allocator: std.mem.Allocator, player_count: i32) ![]RoomSlot {
    const count: usize = @intCast(std.math.clamp(player_count, 1, session_settings.max_players));
    const slots = try allocator.alloc(RoomSlot, count);
    for (slots, 0..) |*slot, idx| {
        slot.* = .{ .slot_index = @intCast(idx) };
    }
    return slots;
}

pub fn slotIndex(slots: []const RoomSlot, target: i32) ?usize {
    if (target < 0) return null;
    for (slots, 0..) |slot, idx| {
        if (slot.slot_index == target) return idx;
    }
    return null;
}

test "relay room slot mirrors python connected property and relay view" {
    var slot: RoomSlot = .{
        .slot_index = 1,
        .peer_id = "peer",
        .peer_name = "guest",
        .ready = true,
        .reconnect_token = "tok",
    };
    try std.testing.expect(slot.connected());

    const relay_slot = slot.toRelaySlot();
    try std.testing.expectEqual(@as(i32, 1), relay_slot.slot_index);
    try std.testing.expect(relay_slot.connected);
    try std.testing.expect(relay_slot.ready);
    try std.testing.expect(!relay_slot.is_host);
    try std.testing.expectEqualStrings("guest", relay_slot.peer_name);

    slot.disconnect(1234);
    try std.testing.expect(!slot.connected());
    try std.testing.expect(!slot.ready);
    try std.testing.expectEqualStrings("", slot.peer_name);
    try std.testing.expectEqual(@as(i64, 1234), slot.disconnected_ms);
    try std.testing.expectEqualStrings("tok", slot.reconnect_token);
}

test "relay room allocates clamped slot rows" {
    const allocator = std.testing.allocator;
    const slots = try allocSlots(allocator, 99);
    defer allocator.free(slots);

    try std.testing.expectEqual(@as(usize, 4), slots.len);
    for (slots, 0..) |slot, idx| {
        try std.testing.expectEqual(@as(i32, @intCast(idx)), slot.slot_index);
        try std.testing.expect(!slot.connected());
    }
}

test "relay room readiness and free slot mirror python room state" {
    const allocator = std.testing.allocator;
    const slots = try allocSlots(allocator, 2);
    defer allocator.free(slots);
    slots[0].peer_id = "host";
    slots[0].peer_name = "host";
    slots[0].ready = true;

    const code = try room_code.parseRoomCode("ABCD");
    var room: Room = .{
        .room_code = code,
        .session_id = "session",
        .settings = session_settings.forRelay(.{ .mode_id = 1, .player_count = 2 }),
        .slots = slots,
    };

    try std.testing.expect(!room.allReady());
    try std.testing.expectEqual(@as(i32, 1), room.nextFreeSlot());
    try std.testing.expect(!room.allDisconnected());

    slots[1].peer_id = "guest";
    slots[1].peer_name = "guest";
    slots[1].ready = true;
    try std.testing.expect(room.allReady());
    try std.testing.expectEqual(@as(i32, -1), room.nextFreeSlot());
}

test "relay room builds room state and room start messages" {
    const allocator = std.testing.allocator;
    const slots = try allocSlots(allocator, 2);
    defer allocator.free(slots);
    slots[0] = .{ .slot_index = 0, .peer_id = "host", .peer_name = "host", .ready = true, .reconnect_token = "host-token" };
    slots[1] = .{ .slot_index = 1, .peer_id = "guest", .peer_name = "guest", .ready = false, .reconnect_token = "guest-token" };

    var status = std.mem.zeroes(game_cfg.Status);
    status.play_time_ms = 77;
    const code = try room_code.parseRoomCode("WXYZ");
    const room: Room = .{
        .room_code = code,
        .session_id = "session",
        .settings = session_settings.forRelay(.{
            .mode_id = 3,
            .player_count = 2,
            .input_delay_ticks = 2,
            .rollback_max_ticks = 6,
        }),
        .status = status,
        .started = true,
        .seed = 123,
        .start_tick = 9,
        .slots = slots,
    };

    var state = try room.roomState(allocator);
    defer state.deinit(allocator);
    try std.testing.expectEqualStrings("wxyz", room_code.roomCodeSlice(&state.value.room_code));
    try std.testing.expectEqualStrings("session", state.value.session_id);
    try std.testing.expectEqual(@as(usize, 2), state.value.slots.len);
    try std.testing.expect(state.value.slots[0].is_host);
    try std.testing.expectEqualStrings("guest", state.value.slots[1].peer_name);
    try std.testing.expect(!state.value.all_ready);
    try std.testing.expect(state.value.started);

    const start = room.roomStartForSlot(1);
    try std.testing.expectEqualStrings("wxyz", room_code.roomCodeSlice(&start.room_code));
    try std.testing.expectEqual(@as(i32, 123), start.seed);
    try std.testing.expectEqual(@as(i32, 9), start.start_tick);
    try std.testing.expectEqual(@as(i32, 1), start.slot_index);
    try std.testing.expectEqualStrings("guest-token", start.reconnect_token);
    try std.testing.expectEqual(@as(u32, 77), start.status.?.play_time_ms);
}
