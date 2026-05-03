const std = @import("std");

const game_cfg = @import("../formats/game_cfg.zig");
const packed_input = @import("packed_input.zig");
const quest_level = @import("../quest_level.zig");
const relay_protocol = @import("relay_protocol.zig");
const relay_reliable = @import("relay_reliable.zig");
const rollback_runtime = @import("rollback_runtime.zig");
const room_code = @import("room_code.zig");

pub const Role = rollback_runtime.Role;

const ReconnectState = enum {
    idle,
    waiting_for_peer_reconnect,
    self_reconnecting,
};

pub const MatchConfig = struct {
    seed: i32 = 0,
    mode_id: i32 = 0,
    player_count: i32 = 1,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    tick_rate: i32 = relay_protocol.tick_rate,
    input_delay_ticks: i32 = relay_protocol.input_delay_ticks,
    status: ?game_cfg.Status = null,
};

pub const Options = struct {
    role: Role,
    mode_id: i32,
    player_count: i32,
    build_id: []const u8,
    peer_name: []const u8 = "",
    room_code: ?room_code.RoomCode = null,
    reconnect_token: []const u8 = "",
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    input_delay_ticks: i32 = relay_protocol.input_delay_ticks,
    rollback_max_ticks: i32 = relay_protocol.rollback_max_ticks,
    reconnect_timeout_ms: i32 = relay_protocol.reconnect_timeout_ms,
    link_timeout_ms: i32 = relay_protocol.link_timeout_ms,
    status: ?game_cfg.Status = null,
};

pub const PacketOutbox = struct {
    items: std.ArrayList(relay_protocol.RelayPacket) = .empty,

    pub fn deinit(self: *PacketOutbox, allocator: std.mem.Allocator) void {
        clearPacketList(allocator, &self.items);
        self.items.deinit(allocator);
        self.* = undefined;
    }
};

pub const Session = struct {
    options: Options,
    link: relay_reliable.RelayReliableLink = .{},
    runtime: ?rollback_runtime.RuntimeCore = null,
    outbox: PacketOutbox = .{},

    accepted: bool = false,
    sent_hello: bool = false,
    sent_room_request: bool = false,
    sent_ready: bool = false,
    saw_room_state: bool = false,
    started: bool = false,
    local_slot_index: i32 = -1,
    room_code_latest: ?room_code.RoomCode = null,
    room_state_latest: ?relay_protocol.RoomState = null,
    reconnect_token: []const u8 = "",
    match_config: ?MatchConfig = null,
    error_reason: []const u8 = "",
    reconnect_state: ReconnectState = .idle,
    last_seen_ms: i64 = 0,
    last_hello_ms: i64 = 0,
    last_ping_ms: i64 = 0,

    pub fn init(options: Options) Session {
        return .{ .options = options };
    }

    pub fn deinit(self: *Session, allocator: std.mem.Allocator) void {
        self.link.deinit(allocator);
        if (self.runtime) |*runtime| runtime.deinit();
        self.outbox.deinit(allocator);
        self.clearRoomState(allocator);
        if (self.reconnect_token.len != 0) allocator.free(self.reconnect_token);
        if (self.error_reason.len != 0) allocator.free(self.error_reason);
        self.* = undefined;
    }

    pub fn update(self: *Session, allocator: std.mem.Allocator, now_ms: i64) !void {
        if (!self.accepted) {
            if (!self.sent_hello or now_ms - self.last_hello_ms >= 200) {
                try self.send(allocator, .{ .client_hello = .{
                    .protocol_version = relay_protocol.protocol_version,
                    .build_id = self.options.build_id,
                    .peer_name = self.options.peer_name,
                } }, true, now_ms);
                self.sent_hello = true;
                self.last_hello_ms = now_ms;
            }
            return;
        }

        var sent_control = false;
        if (!self.sent_room_request) {
            switch (self.options.role) {
                .host => try self.send(allocator, .{ .room_create = .{
                    .mode_id = self.options.mode_id,
                    .player_count = self.options.player_count,
                    .quest_level = self.options.quest_level,
                    .preserve_bugs = self.options.preserve_bugs,
                    .input_delay_ticks = self.options.input_delay_ticks,
                    .rollback_max_ticks = self.options.rollback_max_ticks,
                    .netcode_mode = relay_protocol.NetcodeMode.rollback,
                    .status = self.options.status,
                } }, true, now_ms),
                .join => try self.send(allocator, .{ .room_join = .{
                    .room_code = self.options.room_code,
                    .reconnect_token = if (self.reconnect_state == .self_reconnecting) self.reconnect_token else self.options.reconnect_token,
                } }, true, now_ms),
            }
            self.sent_room_request = true;
            sent_control = true;
        }

        if (self.saw_room_state and !self.sent_ready) {
            try self.send(allocator, .{ .room_ready = .{ .slot_index = self.local_slot_index, .ready = true } }, true, now_ms);
            self.sent_ready = true;
            sent_control = true;
        }

        if (self.runtime) |*runtime| try runtime.checkReconnectTimeout(now_ms);
        try self.flushRuntimeOutbox(allocator, now_ms);
        try self.checkLinkTimeout(allocator, now_ms);
        if (!self.accepted) return;
        try self.pollLinkResends(allocator, now_ms);
        if (!sent_control) try self.sendPingIfDue(allocator, now_ms);
    }

    pub fn handlePacket(
        self: *Session,
        allocator: std.mem.Allocator,
        packet: relay_protocol.RelayPacket,
        now_ms: i64,
    ) !void {
        self.last_seen_ms = now_ms;
        var delivered = try self.link.ingestPacket(allocator, packet, now_ms);
        defer delivered.deinit(allocator);
        for (delivered.messages.items) |message| {
            try self.handleMessage(allocator, message, now_ms);
        }
    }

    pub fn queueLocalInput(self: *Session, allocator: std.mem.Allocator, input: packed_input.PackedPlayerInput, now_ms: i64) !void {
        const runtime = if (self.runtime) |*runtime| runtime else return;
        try runtime.queueLocalInput(input, now_ms);
        try self.flushRuntimeOutbox(allocator, now_ms);
    }

    pub fn popFrame(self: *Session) ?rollback_runtime.TickFrame {
        const runtime = if (self.runtime) |*runtime| runtime else return null;
        return runtime.popFrame();
    }

    pub fn hostRemoteInputsReady(self: *const Session) bool {
        const runtime = if (self.runtime) |*runtime| runtime else return self.options.role != .host;
        return runtime.hostRemoteInputsReady();
    }

    pub fn clearOutbox(self: *Session, allocator: std.mem.Allocator) void {
        self.outbox.deinit(allocator);
        self.outbox = .{};
    }

    fn handleMessage(self: *Session, allocator: std.mem.Allocator, message: relay_protocol.NetMessage, now_ms: i64) !void {
        switch (message) {
            .client_welcome => |welcome| {
                self.accepted = welcome.accepted;
                if (!welcome.accepted) try self.setError(allocator, if (welcome.reason.len == 0) "rejected" else welcome.reason);
                if (welcome.accepted and self.reconnect_state == .self_reconnecting) self.sent_room_request = false;
            },
            .room_state => |state| {
                self.saw_room_state = true;
                self.room_code_latest = state.room_code;
                try self.storeRoomState(allocator, state);
                if (self.runtime) |*runtime| {
                    if (self.reconnect_state != .idle and roomStateHasConnectedSlot(state, self.local_slot_index)) {
                        runtime.completeReconnect();
                        self.reconnect_state = .idle;
                    }
                }
            },
            .room_start => |start| try self.handleRoomStart(allocator, start),
            .relay_error => |err| try self.setError(allocator, if (err.reason.len == 0) "relay_error" else err.reason),
            .peer_disconnect => |disconnect| {
                const runtime = if (self.runtime) |*runtime| runtime else return;
                try runtime.handleMessage(message, now_ms);
                if (disconnect.slot_index != self.local_slot_index and runtime.paused_for_reconnect) {
                    self.reconnect_state = .waiting_for_peer_reconnect;
                }
            },
            .rb_input_sample,
            .rb_resync_request,
            .rb_resync_begin,
            .rb_resync_chunk,
            .rb_resync_commit,
            => {
                const runtime = if (self.runtime) |*runtime| runtime else return;
                try runtime.handleMessage(message, now_ms);
            },
            else => {},
        }
        try self.flushRuntimeOutbox(allocator, now_ms);
    }

    fn storeRoomState(self: *Session, allocator: std.mem.Allocator, state: relay_protocol.RoomState) !void {
        self.clearRoomState(allocator);
        var message = try relay_protocol.cloneMessage(allocator, .{ .room_state = state });
        errdefer relay_protocol.deinitMessage(allocator, &message);
        self.room_state_latest = message.room_state;
        message = .{ .ping = .{} };
    }

    fn clearRoomState(self: *Session, allocator: std.mem.Allocator) void {
        if (self.room_state_latest) |state| {
            var message: relay_protocol.NetMessage = .{ .room_state = state };
            relay_protocol.deinitMessage(allocator, &message);
            self.room_state_latest = null;
        }
    }

    fn handleRoomStart(self: *Session, allocator: std.mem.Allocator, start: relay_protocol.RoomStart) !void {
        const first_start = !self.started;
        if (first_start) {
            if (self.runtime) |*runtime| runtime.deinit();
            self.runtime = rollback_runtime.RuntimeCore.init(allocator, .{
                .role = self.options.role,
                .player_count = start.player_count,
                .local_slot_index = start.slot_index,
                .input_delay_ticks = start.input_delay_ticks,
                .max_rollback_ticks = start.rollback_max_ticks,
                .reconnect_timeout_ms = self.options.reconnect_timeout_ms,
            });
            if (self.runtime) |*runtime| try runtime.primeInitialDelay();
        } else if (self.runtime) |*runtime| {
            runtime.completeReconnect();
        }
        self.started = true;
        self.local_slot_index = start.slot_index;
        self.room_code_latest = start.room_code;
        try self.setReconnectToken(allocator, start.reconnect_token);
        self.match_config = matchConfigFromRoomStart(start);
        self.sent_ready = true;
        self.reconnect_state = .idle;
    }

    fn flushRuntimeOutbox(self: *Session, allocator: std.mem.Allocator, now_ms: i64) !void {
        const runtime = if (self.runtime) |*runtime| runtime else return;
        defer runtime.clearOutbox();
        for (runtime.outbox.items) |item| {
            try self.send(allocator, item.message, item.reliable, now_ms);
        }
    }

    fn send(
        self: *Session,
        allocator: std.mem.Allocator,
        message: relay_protocol.NetMessage,
        reliable: bool,
        now_ms: i64,
    ) !void {
        const packet = try self.link.buildPacket(allocator, message, reliable, now_ms);
        var owned = try relay_protocol.clonePacket(allocator, packet);
        errdefer relay_protocol.deinitPacket(allocator, &owned);
        try self.outbox.items.append(allocator, owned);
        owned = .{};
    }

    fn setError(self: *Session, allocator: std.mem.Allocator, reason: []const u8) !void {
        if (self.error_reason.len != 0) allocator.free(self.error_reason);
        self.error_reason = if (reason.len == 0) "" else try allocator.dupe(u8, reason);
    }

    fn setReconnectToken(self: *Session, allocator: std.mem.Allocator, token: []const u8) !void {
        if (self.reconnect_token.len != 0) allocator.free(self.reconnect_token);
        self.reconnect_token = if (token.len == 0) "" else try allocator.dupe(u8, token);
    }

    fn pollLinkResends(self: *Session, allocator: std.mem.Allocator, now_ms: i64) !void {
        var packets = try self.link.pollResends(allocator, now_ms);
        defer relay_reliable.deinitPacketList(allocator, &packets);
        for (packets.items) |packet| {
            var owned = try relay_protocol.clonePacket(allocator, packet);
            errdefer relay_protocol.deinitPacket(allocator, &owned);
            try self.outbox.items.append(allocator, owned);
            owned = .{};
        }
    }

    fn sendPingIfDue(self: *Session, allocator: std.mem.Allocator, now_ms: i64) !void {
        if (!self.accepted) return;
        if (self.last_ping_ms > 0 and now_ms - self.last_ping_ms < relay_protocol.ping_interval_ms) return;
        const stamp_ms: i32 = @intCast(std.math.clamp(now_ms, std.math.minInt(i32), std.math.maxInt(i32)));
        try self.send(allocator, .{ .ping = .{ .stamp_ms = stamp_ms } }, false, now_ms);
        self.last_ping_ms = now_ms;
    }

    fn checkLinkTimeout(self: *Session, allocator: std.mem.Allocator, now_ms: i64) !void {
        if (self.last_seen_ms <= 0) return;
        if (now_ms - self.last_seen_ms < @max(@as(i64, 250), self.options.link_timeout_ms)) return;
        if (self.started and self.reconnect_token.len != 0) {
            try self.startSelfReconnect(allocator, now_ms);
            return;
        }
        try self.setError(allocator, "timeout");
    }

    fn startSelfReconnect(self: *Session, allocator: std.mem.Allocator, now_ms: i64) !void {
        if (self.reconnect_state == .self_reconnecting) return;
        self.reconnect_state = .self_reconnecting;
        if (self.runtime) |*runtime| runtime.beginSelfReconnect(now_ms);
        self.accepted = false;
        self.sent_hello = false;
        self.sent_room_request = false;
        self.sent_ready = false;
        self.saw_room_state = false;
        self.last_hello_ms = 0;
        self.last_ping_ms = 0;
        self.link.deinit(allocator);
        self.link = .{};
    }
};

fn matchConfigFromRoomStart(start: relay_protocol.RoomStart) MatchConfig {
    return .{
        .seed = start.seed,
        .mode_id = start.mode_id,
        .player_count = start.player_count,
        .quest_level = start.quest_level,
        .preserve_bugs = start.preserve_bugs,
        .tick_rate = start.tick_rate,
        .input_delay_ticks = start.input_delay_ticks,
        .status = start.status,
    };
}

fn clearPacketList(allocator: std.mem.Allocator, packets: *std.ArrayList(relay_protocol.RelayPacket)) void {
    for (packets.items) |*packet| relay_protocol.deinitPacket(allocator, packet);
    packets.clearRetainingCapacity();
}

fn roomStateHasConnectedSlot(state: relay_protocol.RoomState, slot_index: i32) bool {
    if (slot_index < 0) return false;
    for (state.slots) |slot| {
        if (slot.slot_index == slot_index and slot.connected) return true;
    }
    return false;
}

test "rollback session handshakes host room and starts runtime" {
    const allocator = std.testing.allocator;
    const code = try room_code.parseRoomCode("ABCD");
    var session = Session.init(.{
        .role = .host,
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .peer_name = "host",
        .input_delay_ticks = 0,
    });
    defer session.deinit(allocator);

    try session.update(allocator, 1000);
    try std.testing.expectEqual(@as(usize, 1), session.outbox.items.items.len);
    switch (session.outbox.items.items[0].message) {
        .client_hello => |hello| {
            try std.testing.expectEqual(@as(i32, relay_protocol.protocol_version), hello.protocol_version);
            try std.testing.expectEqualStrings("host", hello.peer_name);
        },
        else => return error.ExpectedClientHello,
    }
    session.clearOutbox(allocator);

    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .client_welcome = .{
        .accepted = true,
        .peer_id = "host-id",
    } }, true, 1001), 1001);
    try session.update(allocator, 1002);
    switch (session.outbox.items.items[0].message) {
        .room_create => |create| {
            try std.testing.expectEqual(@as(i32, 2), create.player_count);
            try std.testing.expectEqual(relay_protocol.NetcodeMode.rollback, create.netcode_mode);
        },
        else => return error.ExpectedRoomCreate,
    }
    session.clearOutbox(allocator);

    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .room_state = .{
        .room_code = code,
        .session_id = "s1",
        .player_count = 2,
    } }, true, 1003), 1003);
    try session.update(allocator, 1004);
    switch (session.outbox.items.items[0].message) {
        .room_ready => |ready| try std.testing.expect(ready.ready),
        else => return error.ExpectedRoomReady,
    }
    session.clearOutbox(allocator);

    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .room_start = .{
        .room_code = code,
        .session_id = "s1",
        .player_count = 2,
        .slot_index = 0,
        .input_delay_ticks = 0,
        .rollback_max_ticks = 8,
        .netcode_mode = relay_protocol.NetcodeMode.rollback,
    } }, true, 1005), 1005);

    try std.testing.expect(session.started);
    try std.testing.expect(session.runtime != null);
    try std.testing.expectEqual(@as(i32, 0), session.local_slot_index);
}

test "rollback session retains latest room state for lobby status" {
    const allocator = std.testing.allocator;
    const code = try room_code.parseRoomCode("ABCD");
    var session = Session.init(.{
        .role = .host,
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
    });
    defer session.deinit(allocator);

    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .room_state = .{
        .room_code = code,
        .session_id = "s1",
        .player_count = 2,
        .slots = &[_]relay_protocol.RelaySlot{
            .{ .slot_index = 0, .connected = true, .ready = true, .is_host = true, .peer_name = "host" },
            .{ .slot_index = 1, .connected = true, .ready = false, .is_host = false, .peer_name = "guest" },
        },
    } }, true, 1000), 1000);

    const state = session.room_state_latest orelse return error.ExpectedRoomState;
    try std.testing.expectEqualStrings("s1", state.session_id);
    try std.testing.expectEqual(@as(usize, 2), state.slots.len);
    try std.testing.expectEqualStrings("guest", state.slots[1].peer_name);
    try std.testing.expectEqualStrings("abcd", room_code.roomCodeSlice(&state.room_code));
}

test "rollback session packetizes local input through runtime core" {
    const allocator = std.testing.allocator;
    const code = try room_code.parseRoomCode("ABCD");
    var session = Session.init(.{
        .role = .host,
        .mode_id = 2,
        .player_count = 1,
        .build_id = "0.1.0",
        .input_delay_ticks = 0,
    });
    defer session.deinit(allocator);

    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .room_start = .{
        .room_code = code,
        .session_id = "s1",
        .player_count = 1,
        .slot_index = 0,
        .input_delay_ticks = 0,
        .rollback_max_ticks = 8,
        .netcode_mode = relay_protocol.NetcodeMode.rollback,
    } }, true, 1000), 1000);

    try session.queueLocalInput(allocator, .{ .flags = 7 }, 1001);
    try std.testing.expectEqual(@as(usize, 1), session.outbox.items.items.len);
    switch (session.outbox.items.items[0].message) {
        .rb_input_sample => |batch| {
            try std.testing.expectEqual(@as(i32, 0), batch.slot_index);
            try std.testing.expectEqual(@as(usize, 1), batch.samples.len);
            try std.testing.expectEqual(@as(u32, 7), batch.samples[0].packed_input.flags);
        },
        else => return error.ExpectedInputBatch,
    }

    const frame = session.popFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqual(@as(i32, 0), frame.tick_index);
    try std.testing.expectEqual(@as(u32, 7), frame.input(0).flags);
}

test "rollback session sends reconnect token on join" {
    const allocator = std.testing.allocator;
    var session = Session.init(.{
        .role = .join,
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .room_code = null,
        .reconnect_token = "guest-token",
    });
    defer session.deinit(allocator);

    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .client_welcome = .{
        .accepted = true,
        .peer_id = "guest-id",
    } }, true, 1000), 1000);
    try session.update(allocator, 1001);

    try std.testing.expectEqual(@as(usize, 1), session.outbox.items.items.len);
    switch (session.outbox.items.items[0].message) {
        .room_join => |join| {
            try std.testing.expect(join.room_code == null);
            try std.testing.expectEqualStrings("guest-token", join.reconnect_token);
        },
        else => return error.ExpectedRoomJoin,
    }
}

test "rollback session stores reconnect token and resumes after room state reconnect" {
    const allocator = std.testing.allocator;
    const code = try room_code.parseRoomCode("ABCD");
    var session = Session.init(.{
        .role = .host,
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .input_delay_ticks = 0,
        .reconnect_timeout_ms = 500,
    });
    defer session.deinit(allocator);
    session.accepted = true;

    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .room_start = .{
        .room_code = code,
        .session_id = "s1",
        .player_count = 2,
        .slot_index = 0,
        .input_delay_ticks = 0,
        .rollback_max_ticks = 8,
        .netcode_mode = relay_protocol.NetcodeMode.rollback,
        .reconnect_token = "host-token",
    } }, true, 1000), 1000);
    try std.testing.expectEqualStrings("host-token", session.reconnect_token);

    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .peer_disconnect = .{ .slot_index = 1, .reason = "timeout" } }, true, 1100), 1100);
    try std.testing.expect(session.runtime.?.paused_for_reconnect);
    try std.testing.expectEqual(@as(i32, 1), session.runtime.?.reconnect_count);
    try std.testing.expect(!session.hostRemoteInputsReady());

    try session.update(allocator, 1599);
    try std.testing.expectEqualStrings("", session.runtime.?.error_reason);

    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .room_state = .{
        .room_code = code,
        .session_id = "s1",
        .player_count = 2,
        .slots = &[_]relay_protocol.RelaySlot{
            .{ .slot_index = 0, .connected = true, .ready = true, .is_host = true },
            .{ .slot_index = 1, .connected = true, .ready = true, .is_host = false },
        },
        .all_ready = true,
        .started = true,
    } }, true, 1601), 1601);
    try std.testing.expect(!session.runtime.?.paused_for_reconnect);
    try std.testing.expectEqual(@as(i64, 0), session.runtime.?.reconnect_deadline_ms);

    try session.queueLocalInput(allocator, .{ .flags = 7 }, 1602);
    const frame = session.popFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqual(@as(u32, 7), frame.input(0).flags);
}

test "rollback session self reconnects with token and keeps runtime state" {
    const allocator = std.testing.allocator;
    const code = try room_code.parseRoomCode("ABCD");
    var session = Session.init(.{
        .role = .join,
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .room_code = code,
        .input_delay_ticks = 0,
        .reconnect_timeout_ms = 1000,
        .link_timeout_ms = 500,
    });
    defer session.deinit(allocator);
    session.accepted = true;
    session.sent_room_request = true;
    session.sent_ready = true;

    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .room_start = .{
        .room_code = code,
        .session_id = "s1",
        .player_count = 2,
        .slot_index = 1,
        .input_delay_ticks = 0,
        .rollback_max_ticks = 8,
        .netcode_mode = relay_protocol.NetcodeMode.rollback,
        .reconnect_token = "guest-token",
    } }, true, 1000), 1000);

    try session.queueLocalInput(allocator, .{ .flags = 7 }, 1001);
    const first_frame = session.popFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqual(@as(i32, 0), first_frame.tick_index);
    session.clearOutbox(allocator);

    try session.update(allocator, 1500);
    try std.testing.expectEqual(ReconnectState.self_reconnecting, session.reconnect_state);
    try std.testing.expect(!session.accepted);
    try std.testing.expect(session.runtime.?.paused_for_reconnect);
    try std.testing.expectEqual(@as(i32, 1), session.runtime.?.reconnect_count);

    try session.update(allocator, 1501);
    switch (session.outbox.items.items[0].message) {
        .client_hello => {},
        else => return error.ExpectedClientHello,
    }
    session.clearOutbox(allocator);

    var reconnect_link: relay_reliable.RelayReliableLink = .{};
    defer reconnect_link.deinit(allocator);
    try session.handlePacket(allocator, try reconnect_link.buildPacket(allocator, .{ .client_welcome = .{
        .accepted = true,
        .peer_id = "guest-new",
    } }, true, 1502), 1502);
    try session.update(allocator, 1503);
    switch (session.outbox.items.items[0].message) {
        .room_join => |join| {
            try std.testing.expectEqualStrings("guest-token", join.reconnect_token);
        },
        else => return error.ExpectedRoomJoin,
    }
    session.clearOutbox(allocator);

    try session.handlePacket(allocator, try reconnect_link.buildPacket(allocator, .{ .room_start = .{
        .room_code = code,
        .session_id = "s1",
        .player_count = 2,
        .slot_index = 1,
        .input_delay_ticks = 0,
        .rollback_max_ticks = 8,
        .netcode_mode = relay_protocol.NetcodeMode.rollback,
        .reconnect_token = "guest-token",
    } }, true, 1504), 1504);
    try std.testing.expectEqual(ReconnectState.idle, session.reconnect_state);
    try std.testing.expect(!session.runtime.?.paused_for_reconnect);

    try session.queueLocalInput(allocator, .{ .flags = 8 }, 1505);
    const resumed_frame = session.popFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqual(@as(i32, 1), resumed_frame.tick_index);
    try std.testing.expectEqual(@as(u32, 8), resumed_frame.input(1).flags);
}

test "rollback session routes remote input into runtime core" {
    const allocator = std.testing.allocator;
    const code = try room_code.parseRoomCode("ABCD");
    var session = Session.init(.{
        .role = .host,
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .input_delay_ticks = 0,
    });
    defer session.deinit(allocator);

    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .room_start = .{
        .room_code = code,
        .session_id = "s1",
        .player_count = 2,
        .slot_index = 0,
        .input_delay_ticks = 0,
        .rollback_max_ticks = 8,
        .netcode_mode = relay_protocol.NetcodeMode.rollback,
    } }, true, 1000), 1000);

    try session.queueLocalInput(allocator, .{}, 1001);
    _ = session.popFrame();
    session.clearOutbox(allocator);

    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .rb_input_sample = .{
        .slot_index = 1,
        .samples = &[_]relay_protocol.RbInputSample{.{ .tick_index = 0, .packed_input = .{ .flags = 9 } }},
    } }, false, 1002), 1002);

    const runtime = &session.runtime.?;
    try std.testing.expectEqual(@as(i32, 1), runtime.prediction_mismatches);
    try std.testing.expectEqual(@as(i32, 1), runtime.resync_count);
    try std.testing.expect(runtime.paused_for_resync);
}

test "rollback session primes initial delay frames at room start" {
    const allocator = std.testing.allocator;
    var session = Session.init(.{
        .role = .host,
        .mode_id = 2,
        .player_count = 1,
        .build_id = "test",
    });
    defer session.deinit(allocator);

    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    try session.handlePacket(allocator, try server_link.buildPacket(allocator, .{ .room_start = .{
        .room_code = try room_code.parseRoomCode("ABCD"),
        .session_id = "s1",
        .mode_id = 2,
        .player_count = 1,
        .slot_index = 0,
        .input_delay_ticks = 1,
        .rollback_max_ticks = 8,
        .netcode_mode = relay_protocol.NetcodeMode.rollback,
    } }, true, 1000), 1000);

    const frame = session.popFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqual(@as(i32, 0), frame.tick_index);
    try std.testing.expectEqual(@as(u32, 0), frame.input(0).flags);
    try std.testing.expect(session.popFrame() == null);
}
