const std = @import("std");

const relay_core = @import("relay_core.zig");
const relay_forward = @import("relay_forward.zig");
const relay_lobby = @import("relay_lobby.zig");
const relay_protocol = @import("relay_protocol.zig");
const relay_room = @import("relay_room.zig");
const room_code = @import("room_code.zig");

pub const Outbound = struct {
    peer_index: usize,
    message: relay_protocol.NetMessage,
    reliable: bool,
    slots: ?[]relay_protocol.RelaySlot = null,

    pub fn deinit(self: *Outbound, allocator: std.mem.Allocator) void {
        if (self.slots) |slots| allocator.free(slots);
        self.* = undefined;
    }
};

pub const Outbox = struct {
    items: std.ArrayList(Outbound) = .empty,

    pub fn deinit(self: *Outbox, allocator: std.mem.Allocator) void {
        for (self.items.items) |*item| item.deinit(allocator);
        self.items.deinit(allocator);
        self.* = undefined;
    }
};

pub const DispatchOptions = struct {
    now_ms: i64 = 0,
    room_code: room_code.RoomCode = .{ .bytes = .{ 'a', 'a', 'a', 'a' } },
    session_id: []const u8 = "",
    reconnect_token: []const u8 = "",
    reconnect_timeout_ms: i64 = relay_protocol.reconnect_timeout_ms,
    max_rooms: usize = 2048,
};

pub fn handleClientHello(
    allocator: std.mem.Allocator,
    core: *relay_core.RelayCore,
    peer_index: usize,
    message: relay_protocol.ClientHello,
    now_ms: i64,
) !Outbox {
    var outbox: Outbox = .{};
    errdefer outbox.deinit(allocator);
    const accepted = message.protocol_version == relay_protocol.protocol_version;
    if (peer_index < core.peers.items.len) {
        const peer = &core.peers.items[peer_index].peer;
        peer.build_id = message.build_id;
        peer.peer_name = message.peer_name;
        peer.last_seen_ms = now_ms;
    }
    try outbox.items.append(allocator, .{
        .peer_index = peer_index,
        .message = .{ .client_welcome = .{
            .accepted = accepted,
            .reason = if (accepted) "" else "protocol_mismatch_v5_required",
            .protocol_version = relay_protocol.protocol_version,
            .build_id = message.build_id,
            .peer_id = if (peer_index < core.peers.items.len) core.peers.items[peer_index].peer.peer_id else "",
        } },
        .reliable = true,
    });
    return outbox;
}

pub fn handleMessage(
    allocator: std.mem.Allocator,
    core: *relay_core.RelayCore,
    peer_index: usize,
    message: relay_protocol.NetMessage,
    options: DispatchOptions,
) !Outbox {
    var outbox: Outbox = .{};
    errdefer outbox.deinit(allocator);
    if (peer_index >= core.peers.items.len) return outbox;

    switch (message) {
        .ping => |ping| try appendMessage(allocator, &outbox, peer_index, .{ .pong = .{ .stamp_ms = ping.stamp_ms } }, false),
        .room_create => |create| try handleRoomCreate(allocator, core, peer_index, create, options, &outbox),
        .room_join => |join| try handleRoomJoin(allocator, core, peer_index, join, options, &outbox),
        .room_ready => |ready| try handleRoomReady(allocator, core, peer_index, ready, options, &outbox),
        .rb_input_sample,
        .rb_resync_request,
        .rb_resync_begin,
        .rb_resync_chunk,
        .rb_resync_commit,
        .lockstep_state_input_batch,
        .lockstep_state_tick_frame,
        .lockstep_state_control,
        => try handleForward(allocator, core, peer_index, message, &outbox),
        else => {},
    }
    return outbox;
}

pub fn handleDisconnect(
    allocator: std.mem.Allocator,
    core: *relay_core.RelayCore,
    peer_index: usize,
    reason: []const u8,
    now_ms: i64,
) !Outbox {
    var outbox: Outbox = .{};
    errdefer outbox.deinit(allocator);
    if (peer_index >= core.peers.items.len) return outbox;

    const peer = core.peers.items[peer_index].peer;
    const code = peer.room_code orelse return outbox;
    const room_index = core.findRoomByCode(code) orelse return outbox;
    const result = core.disconnectPeer(peer_index, reason, now_ms) orelse return outbox;

    try appendRoomState(allocator, core, room_index, &outbox);
    const room = core.rooms.items[room_index].room;
    for (room.slots) |slot| {
        if (!slot.connected()) continue;
        const dst_idx = core.findPeerById(slot.peer_id) orelse continue;
        try appendMessage(allocator, &outbox, dst_idx, .{ .peer_disconnect = result.notice }, true);
    }

    if (result.evict_room) {
        _ = core.removeRoom(allocator, room_index);
    }
    return outbox;
}

fn handleRoomCreate(
    allocator: std.mem.Allocator,
    core: *relay_core.RelayCore,
    peer_index: usize,
    message: relay_protocol.RoomCreate,
    options: DispatchOptions,
    outbox: *Outbox,
) !void {
    if (core.rooms.items.len >= options.max_rooms) {
        try appendMessage(allocator, outbox, peer_index, .{ .relay_error = .{ .reason = "room_capacity" } }, true);
        return;
    }

    const peer = &core.peers.items[peer_index].peer;
    const room = relay_lobby.createRoom(allocator, peer, message, .{
        .code = options.room_code,
        .session_id = options.session_id,
        .host_reconnect_token = options.reconnect_token,
    }) catch |err| {
        switch (err) {
            error.OutOfMemory => return err,
            error.AlreadyInRoom => |lobby_err| {
                try appendMessage(allocator, outbox, peer_index, .{ .relay_error = .{ .reason = lobbyErrorReason(lobby_err) } }, true);
                return;
            },
        }
    };
    const room_index = try core.addRoom(allocator, room);
    try appendRoomState(allocator, core, room_index, outbox);
}

fn handleRoomJoin(
    allocator: std.mem.Allocator,
    core: *relay_core.RelayCore,
    peer_index: usize,
    message: relay_protocol.RoomJoin,
    options: DispatchOptions,
    outbox: *Outbox,
) !void {
    var room_index: ?usize = null;
    var reconnect_slot_index: ?i32 = null;
    if (message.reconnect_token.len != 0) {
        if (core.findReconnectToken(message.reconnect_token)) |mapping| {
            room_index = mapping.room_index;
            reconnect_slot_index = mapping.slot_index;
        }
    }
    if (room_index == null) {
        const code = message.room_code orelse {
            try appendMessage(allocator, outbox, peer_index, .{ .relay_error = .{ .reason = "room_not_found" } }, true);
            return;
        };
        room_index = core.findRoomByCode(code);
    }
    if (room_index == null) {
        try appendMessage(allocator, outbox, peer_index, .{ .relay_error = .{ .reason = "room_not_found" } }, true);
        return;
    }

    const room = &core.rooms.items[room_index.?].room;
    const host_build_id = hostBuildId(core, room.*);
    const joined = relay_lobby.joinRoom(room, &core.peers.items[peer_index].peer, .{
        .reconnect_slot_index = reconnect_slot_index,
        .reconnect_timeout_ms = options.reconnect_timeout_ms,
        .now_ms = options.now_ms,
        .host_build_id = host_build_id,
        .new_reconnect_token = options.reconnect_token,
    }) catch |err| {
        try appendMessage(allocator, outbox, peer_index, .{ .relay_error = .{ .reason = lobbyErrorReason(err) } }, true);
        return;
    };
    try appendRoomState(allocator, core, room_index.?, outbox);
    if (joined.should_send_room_start) {
        try appendMessage(allocator, outbox, peer_index, .{ .room_start = room.roomStartForSlot(joined.slot_index) }, true);
    }
}

fn handleRoomReady(
    allocator: std.mem.Allocator,
    core: *relay_core.RelayCore,
    peer_index: usize,
    message: relay_protocol.RoomReady,
    options: DispatchOptions,
    outbox: *Outbox,
) !void {
    const peer = core.peers.items[peer_index].peer;
    const code = peer.room_code orelse {
        try appendMessage(allocator, outbox, peer_index, .{ .relay_error = .{ .reason = "not_in_room" } }, true);
        return;
    };
    const room_index = core.findRoomByCode(code) orelse {
        try appendMessage(allocator, outbox, peer_index, .{ .relay_error = .{ .reason = "not_in_room" } }, true);
        return;
    };
    const room = &core.rooms.items[room_index].room;
    const ready = relay_lobby.applyReady(room, peer, message, options.now_ms) catch |err| {
        try appendMessage(allocator, outbox, peer_index, .{ .relay_error = .{ .reason = lobbyErrorReason(err) } }, true);
        return;
    };
    if (ready.started_now) {
        for (room.slots) |slot| {
            if (!slot.connected()) continue;
            if (core.findPeerById(slot.peer_id)) |dst_idx| {
                try appendMessage(allocator, outbox, dst_idx, .{ .room_start = room.roomStartForSlot(slot.slot_index) }, true);
            }
        }
    }
    try appendRoomState(allocator, core, room_index, outbox);
}

fn handleForward(
    allocator: std.mem.Allocator,
    core: *relay_core.RelayCore,
    peer_index: usize,
    message: relay_protocol.NetMessage,
    outbox: *Outbox,
) !void {
    const peer = core.peers.items[peer_index].peer;
    const code = peer.room_code orelse {
        try appendMessage(allocator, outbox, peer_index, .{ .relay_error = .{ .reason = "not_in_room" } }, true);
        return;
    };
    const room_index = core.findRoomByCode(code) orelse {
        try appendMessage(allocator, outbox, peer_index, .{ .relay_error = .{ .reason = "not_in_room" } }, true);
        return;
    };
    const room = core.rooms.items[room_index].room;
    switch (relay_forward.decide(room, peer.slot_index, message)) {
        .reject => |reason| try appendMessage(allocator, outbox, peer_index, .{ .relay_error = .{ .reason = reason } }, true),
        .forward => |plan| {
            var recipients = try core.connectedPeerRecipients(allocator, room, peer.peer_id);
            defer recipients.deinit(allocator);
            for (recipients.items) |dst_idx| {
                try appendMessage(allocator, outbox, dst_idx, message, plan.reliable);
            }
        },
    }
}

fn appendRoomState(allocator: std.mem.Allocator, core: *relay_core.RelayCore, room_index: usize, outbox: *Outbox) !void {
    const room = core.rooms.items[room_index].room;
    for (room.slots) |slot| {
        if (!slot.connected()) continue;
        const dst_idx = core.findPeerById(slot.peer_id) orelse continue;
        var state = try room.roomState(allocator);
        errdefer state.deinit(allocator);
        try outbox.items.append(allocator, .{
            .peer_index = dst_idx,
            .message = .{ .room_state = state.value },
            .reliable = true,
            .slots = state.slots,
        });
    }
}

fn appendMessage(allocator: std.mem.Allocator, outbox: *Outbox, peer_index: usize, message: relay_protocol.NetMessage, reliable: bool) !void {
    try outbox.items.append(allocator, .{
        .peer_index = peer_index,
        .message = message,
        .reliable = reliable,
    });
}

fn hostBuildId(core: *const relay_core.RelayCore, room: relay_room.Room) []const u8 {
    if (room.slots.len == 0) return "";
    const host_peer_id = room.slots[0].peer_id;
    if (core.findPeerById(host_peer_id)) |idx| return core.peers.items[idx].peer.build_id;
    return "";
}

fn lobbyErrorReason(err: relay_lobby.LobbyError) []const u8 {
    return switch (err) {
        error.AlreadyInRoom => "already_in_room",
        error.RoomFull => "room_full",
        error.SlotBusy => "slot_busy",
        error.BuildMismatch => "build_mismatch",
        error.NotInRoom => "not_in_room",
        error.BadSlot => "bad_slot",
        error.SlotOwnerMismatch => "slot_owner_mismatch",
    };
}

test "relay dispatch accepts client hello and updates peer" {
    const allocator = std.testing.allocator;
    var core: relay_core.RelayCore = .{};
    defer core.deinit(allocator);
    const peer_idx = try core.addPeer(allocator, .{ .peer_id = "peer-1" });

    var outbox = try handleClientHello(allocator, &core, peer_idx, .{
        .protocol_version = relay_protocol.protocol_version,
        .build_id = "0.1.0",
        .peer_name = "host",
    }, 1000);
    defer outbox.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), outbox.items.items.len);
    try std.testing.expect(outbox.items.items[0].reliable);
    switch (outbox.items.items[0].message) {
        .client_welcome => |welcome| {
            try std.testing.expect(welcome.accepted);
            try std.testing.expectEqualStrings("peer-1", welcome.peer_id);
        },
        else => return error.TestExpectedEqual,
    }
    try std.testing.expectEqualStrings("0.1.0", core.peers.items[peer_idx].peer.build_id);
    try std.testing.expectEqualStrings("host", core.peers.items[peer_idx].peer.peer_name);
    try std.testing.expectEqual(@as(i64, 1000), core.peers.items[peer_idx].peer.last_seen_ms);
}

test "relay dispatch creates joins readies and starts room" {
    const allocator = std.testing.allocator;
    var core: relay_core.RelayCore = .{};
    defer core.deinit(allocator);
    const host_idx = try core.addPeer(allocator, .{ .peer_id = "host", .build_id = "0.1.0" });
    const guest_idx = try core.addPeer(allocator, .{ .peer_id = "guest", .build_id = "0.1.0" });
    const code = try room_code.parseRoomCode("ABCD");

    var created = try handleMessage(allocator, &core, host_idx, .{ .room_create = .{ .mode_id = 2, .player_count = 2 } }, .{
        .room_code = code,
        .session_id = "session",
        .reconnect_token = "host-token",
    });
    defer created.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), core.rooms.items.len);
    try std.testing.expectEqual(@as(usize, 1), created.items.items.len);
    switch (created.items.items[0].message) {
        .room_state => |state| try std.testing.expectEqual(@as(usize, 2), state.slots.len),
        else => return error.TestExpectedEqual,
    }

    var joined = try handleMessage(allocator, &core, guest_idx, .{ .room_join = .{ .room_code = code } }, .{
        .now_ms = 1003,
        .reconnect_token = "guest-token",
    });
    defer joined.deinit(allocator);
    try std.testing.expectEqual(@as(i32, 1), core.peers.items[guest_idx].peer.slot_index);
    try std.testing.expectEqual(@as(usize, 2), joined.items.items.len);

    var ready = try handleMessage(allocator, &core, guest_idx, .{ .room_ready = .{ .slot_index = 1, .ready = true } }, .{ .now_ms = 1004 });
    defer ready.deinit(allocator);
    try std.testing.expect(core.rooms.items[0].room.started);
    var room_start_count: usize = 0;
    for (ready.items.items) |item| {
        if (item.message == .room_start) room_start_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), room_start_count);
}

test "relay dispatch applies reconnect timeout option" {
    const allocator = std.testing.allocator;
    var core: relay_core.RelayCore = .{};
    defer core.deinit(allocator);
    const host_idx = try core.addPeer(allocator, .{ .peer_id = "host", .build_id = "0.1.0" });
    const guest_idx = try core.addPeer(allocator, .{ .peer_id = "guest", .build_id = "0.1.0" });
    const intruder_idx = try core.addPeer(allocator, .{ .peer_id = "intruder", .build_id = "0.1.0" });
    const code = try room_code.parseRoomCode("ABCD");

    var created = try handleMessage(allocator, &core, host_idx, .{ .room_create = .{ .player_count = 2 } }, .{
        .room_code = code,
        .session_id = "session",
        .reconnect_token = "host-token",
    });
    defer created.deinit(allocator);
    var joined = try handleMessage(allocator, &core, guest_idx, .{ .room_join = .{ .room_code = code } }, .{
        .now_ms = 1000,
        .reconnect_token = "guest-token",
    });
    defer joined.deinit(allocator);

    var busy = try handleMessage(allocator, &core, intruder_idx, .{ .room_join = .{ .reconnect_token = "guest-token" } }, .{
        .now_ms = 1200,
        .reconnect_timeout_ms = 2000,
        .reconnect_token = "intruder-token",
    });
    defer busy.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), busy.items.items.len);
    switch (busy.items.items[0].message) {
        .relay_error => |err| try std.testing.expectEqualStrings("slot_busy", err.reason),
        else => return error.TestExpectedEqual,
    }

    var expired = try handleMessage(allocator, &core, intruder_idx, .{ .room_join = .{ .reconnect_token = "guest-token" } }, .{
        .now_ms = 2000,
        .reconnect_timeout_ms = 500,
        .reconnect_token = "intruder-token",
    });
    defer expired.deinit(allocator);
    try std.testing.expectEqual(@as(i32, 1), core.peers.items[intruder_idx].peer.slot_index);
    try std.testing.expectEqualStrings("intruder", core.rooms.items[0].room.slots[1].peer_id);
    try std.testing.expectEqual(@as(usize, 2), expired.items.items.len);
}

test "relay dispatch forwards resync request to host and rejects bad sender" {
    const allocator = std.testing.allocator;
    var core: relay_core.RelayCore = .{};
    defer core.deinit(allocator);
    const host_idx = try core.addPeer(allocator, .{ .peer_id = "host" });
    const guest_idx = try core.addPeer(allocator, .{ .peer_id = "guest" });
    const code = try room_code.parseRoomCode("ABCD");

    var created = try handleMessage(allocator, &core, host_idx, .{ .room_create = .{ .player_count = 2 } }, .{
        .room_code = code,
        .session_id = "session",
        .reconnect_token = "host-token",
    });
    defer created.deinit(allocator);
    var joined = try handleMessage(allocator, &core, guest_idx, .{ .room_join = .{ .room_code = code } }, .{
        .reconnect_token = "guest-token",
    });
    defer joined.deinit(allocator);

    var forwarded = try handleMessage(allocator, &core, guest_idx, .{ .rb_resync_request = .{ .request_id = "rq" } }, .{});
    defer forwarded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), forwarded.items.items.len);
    try std.testing.expectEqual(host_idx, forwarded.items.items[0].peer_index);
    try std.testing.expect(forwarded.items.items[0].reliable);
    switch (forwarded.items.items[0].message) {
        .rb_resync_request => |request| try std.testing.expectEqualStrings("rq", request.request_id),
        else => return error.TestExpectedEqual,
    }

    var rejected = try handleMessage(allocator, &core, host_idx, .{ .rb_resync_request = .{ .request_id = "bad" } }, .{});
    defer rejected.deinit(allocator);
    switch (rejected.items.items[0].message) {
        .relay_error => |err| try std.testing.expectEqualStrings("invalid_resync_sender", err.reason),
        else => return error.TestExpectedEqual,
    }
}

test "relay dispatch disconnect broadcasts state and evicts empty room" {
    const allocator = std.testing.allocator;
    var core: relay_core.RelayCore = .{};
    defer core.deinit(allocator);
    const host_idx = try core.addPeer(allocator, .{ .peer_id = "host" });
    const guest_idx = try core.addPeer(allocator, .{ .peer_id = "guest" });
    const code = try room_code.parseRoomCode("ABCD");

    var created = try handleMessage(allocator, &core, host_idx, .{ .room_create = .{ .player_count = 2 } }, .{
        .room_code = code,
        .session_id = "session",
        .reconnect_token = "host-token",
    });
    defer created.deinit(allocator);
    var joined = try handleMessage(allocator, &core, guest_idx, .{ .room_join = .{ .room_code = code } }, .{
        .reconnect_token = "guest-token",
    });
    defer joined.deinit(allocator);

    var guest_left = try handleDisconnect(allocator, &core, guest_idx, "timeout", 5000);
    defer guest_left.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), core.rooms.items.len);
    try std.testing.expectEqualStrings("", core.rooms.items[0].room.slots[1].peer_id);
    try std.testing.expectEqual(@as(usize, 2), guest_left.items.items.len);
    try std.testing.expectEqual(host_idx, guest_left.items.items[0].peer_index);
    try std.testing.expectEqual(host_idx, guest_left.items.items[1].peer_index);
    switch (guest_left.items.items[0].message) {
        .room_state => |state| {
            try std.testing.expectEqual(@as(usize, 2), state.slots.len);
            try std.testing.expect(!state.slots[1].connected);
        },
        else => return error.TestExpectedEqual,
    }
    switch (guest_left.items.items[1].message) {
        .peer_disconnect => |notice| {
            try std.testing.expectEqual(@as(i32, 1), notice.slot_index);
            try std.testing.expectEqualStrings("timeout", notice.reason);
        },
        else => return error.TestExpectedEqual,
    }

    var host_left = try handleDisconnect(allocator, &core, host_idx, "timeout", 6000);
    defer host_left.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), host_left.items.items.len);
    try std.testing.expectEqual(@as(usize, 0), core.rooms.items.len);
}
