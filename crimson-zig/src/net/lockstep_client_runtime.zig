const std = @import("std");

const game_cfg = @import("../formats/game_cfg.zig");
const lockstep_lobby = @import("lockstep_lobby.zig");
const lockstep_outbox = @import("lockstep_outbox.zig");
const lockstep_protocol = @import("lockstep_protocol.zig");
const lockstep_reliable = @import("lockstep_reliable.zig");
const lockstep_state = @import("lockstep_state.zig");
const lockstep_transport = @import("lockstep_transport.zig");
const packed_input = @import("packed_input.zig");
const quest_level = @import("../quest_level.zig");
const session_settings = @import("session_settings.zig");

pub const PeerAddr = lockstep_transport.PeerAddr;
pub const Outbox = lockstep_outbox.Outbox;

pub const ClientRuntimeOptions = struct {
    mode_id: i32,
    player_count: i32,
    build_id: []const u8,
    host_addr: PeerAddr,
    tick_rate: i32 = lockstep_protocol.tick_rate,
    input_delay_ticks: i32 = lockstep_protocol.input_delay_ticks,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
};

pub const ClientRuntime = struct {
    lobby: lockstep_lobby.ClientLobby,
    link: lockstep_reliable.LockstepReliableLink = .{},
    host_addr: PeerAddr,
    lockstep: ?lockstep_state.ClientLockstepState = null,
    pause_state: ?lockstep_protocol.PauseState = null,
    started: bool = false,
    error_reason: []const u8 = "",
    mode_id: i32,
    player_count: i32,
    tick_rate: i32,
    input_delay_ticks: i32,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    seen_tick_frame: bool = false,
    last_seen_ms: i64 = 0,

    pub fn init(options: ClientRuntimeOptions) ClientRuntime {
        const settings = session_settings.forLockstep(.{
            .mode_id = options.mode_id,
            .player_count = options.player_count,
            .quest_level = options.quest_level,
            .preserve_bugs = options.preserve_bugs,
            .tick_rate = options.tick_rate,
            .input_delay_ticks = options.input_delay_ticks,
        });
        const hello = session_settings.helloFromSettings(settings, .{
            .protocol_version = lockstep_protocol.protocol_version,
            .build_id = options.build_id,
            .host = false,
        });
        return .{
            .lobby = .{ .build_id = options.build_id, .hello = hello },
            .host_addr = options.host_addr,
            .mode_id = settings.mode_id,
            .player_count = settings.player_count,
            .tick_rate = settings.tick_rate,
            .input_delay_ticks = settings.input_delay_ticks,
            .quest_level = settings.quest_level,
            .preserve_bugs = settings.preserve_bugs,
        };
    }

    pub fn deinit(self: *ClientRuntime, allocator: std.mem.Allocator) void {
        deinitOwnedLobby(allocator, &self.lobby);
        self.link.deinit(allocator);
        if (self.lockstep) |*lockstep| lockstep.deinit(allocator);
        if (self.pause_state) |pause| {
            var message: lockstep_protocol.NetMessage = .{ .pause_state = pause };
            lockstep_protocol.deinitMessage(allocator, &message);
        }
        if (self.error_reason.len != 0) allocator.free(self.error_reason);
        self.* = undefined;
    }

    pub fn sendHello(
        self: *ClientRuntime,
        allocator: std.mem.Allocator,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        try self.send(allocator, .{ .hello = self.lobby.hello }, true, now_ms, outbox);
    }

    pub fn handlePacket(
        self: *ClientRuntime,
        allocator: std.mem.Allocator,
        addr: PeerAddr,
        packet: lockstep_protocol.LockstepPacket,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        if (!addr.eql(self.host_addr)) return;
        self.last_seen_ms = now_ms;
        var result = try self.link.ingestPacket(allocator, packet, now_ms);
        defer result.deinit(allocator);

        for (result.messages.items) |message| {
            try self.handleMessage(allocator, message, now_ms, outbox);
            if (self.error_reason.len != 0) return;
        }
    }

    pub fn queueLocalInput(
        self: *ClientRuntime,
        allocator: std.mem.Allocator,
        input: packed_input.PackedPlayerInput,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        const lockstep = if (self.lockstep) |*lockstep| lockstep else return;
        var batch = try lockstep.queueLocalInput(allocator, input);
        defer lockstep_state.deinitInputBatch(allocator, &batch);
        try self.send(allocator, .{ .input_batch = batch }, false, now_ms, outbox);
    }

    pub fn popCanonicalFrame(self: *ClientRuntime) ?lockstep_protocol.TickFrame {
        const lockstep = if (self.lockstep) |*lockstep| lockstep else return null;
        return lockstep.popCanonicalFrame();
    }

    pub fn pollResends(
        self: *ClientRuntime,
        allocator: std.mem.Allocator,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        var packets = try self.link.pollResends(allocator, now_ms);
        defer lockstep_reliable.deinitPacketList(allocator, &packets);
        for (packets.items) |packet| {
            try outbox.appendPacket(allocator, self.host_addr, packet);
        }
    }

    fn handleMessage(
        self: *ClientRuntime,
        allocator: std.mem.Allocator,
        message: lockstep_protocol.NetMessage,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        switch (message) {
            .keep_alive => {},
            .welcome => |welcome| try self.handleWelcome(allocator, welcome, now_ms, outbox),
            .lobby_state => |state| try self.storeLobbyState(allocator, state),
            .match_start => |start| try self.handleMatchStart(allocator, start),
            .tick_frame => |frame| {
                self.seen_tick_frame = true;
                const lockstep = if (self.lockstep) |*lockstep| lockstep else return;
                try lockstep.ingestTickFrame(allocator, frame, now_ms);
            },
            .pause_state => |pause| try self.storePauseState(allocator, pause),
            .disconnect => |disconnect| try self.setError(allocator, if (disconnect.reason.len == 0) "disconnect" else disconnect.reason),
            else => {},
        }
    }

    fn handleWelcome(
        self: *ClientRuntime,
        allocator: std.mem.Allocator,
        welcome: lockstep_protocol.Welcome,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        try self.storeWelcome(allocator, welcome);
        if (!welcome.accepted) {
            try self.setError(allocator, if (welcome.reason.len == 0) "rejected" else welcome.reason);
            return;
        }

        const settings = session_settings.fromWelcome(welcome);
        self.mode_id = settings.mode_id;
        self.player_count = settings.player_count;
        self.tick_rate = settings.tick_rate;
        self.input_delay_ticks = settings.input_delay_ticks;
        self.quest_level = settings.quest_level;
        self.preserve_bugs = settings.preserve_bugs;

        try self.send(allocator, .{ .ready = .{
            .slot_index = welcome.slot_index,
            .ready = true,
        } }, true, now_ms, outbox);
    }

    fn handleMatchStart(
        self: *ClientRuntime,
        allocator: std.mem.Allocator,
        start: lockstep_protocol.MatchStart,
    ) !void {
        if (start.status == null) {
            try self.setError(allocator, "match_start_missing_status");
            return;
        }
        if (self.lobby.welcome) |welcome| {
            if (welcome.session_id.len != 0 and !std.mem.eql(u8, welcome.session_id, start.session_id)) {
                try self.setError(allocator, "session_id_mismatch");
                return;
            }
        }

        const expected = session_settings.forLockstep(.{
            .mode_id = self.mode_id,
            .player_count = self.player_count,
            .quest_level = self.quest_level,
            .preserve_bugs = self.preserve_bugs,
            .tick_rate = self.tick_rate,
            .input_delay_ticks = self.input_delay_ticks,
        });
        const actual = session_settings.fromMatchStart(start, .{
            .tick_rate = expected.tick_rate,
            .input_delay_ticks = expected.input_delay_ticks,
        });
        if (!settingsEqual(expected, actual)) {
            try self.setError(allocator, "match_start_mismatch");
            return;
        }

        try self.storeMatchStart(allocator, start);
        if (self.lockstep) |*existing| existing.deinit(allocator);
        self.lockstep = .{
            .local_slot_index = self.lobby.slotIndex(),
            .input_delay_ticks = self.input_delay_ticks,
        };
        self.started = true;
        self.seen_tick_frame = false;
        self.clearPauseState(allocator);
    }

    fn send(
        self: *ClientRuntime,
        allocator: std.mem.Allocator,
        message: lockstep_protocol.NetMessage,
        reliable: bool,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        const packet = try self.link.buildPacket(allocator, message, reliable, now_ms);
        try outbox.appendPacket(allocator, self.host_addr, packet);
    }

    fn storeWelcome(self: *ClientRuntime, allocator: std.mem.Allocator, welcome: lockstep_protocol.Welcome) !void {
        if (self.lobby.welcome) |old| {
            var old_message: lockstep_protocol.NetMessage = .{ .welcome = old };
            lockstep_protocol.deinitMessage(allocator, &old_message);
            self.lobby.welcome = null;
        }
        var message = try lockstep_protocol.cloneMessage(allocator, .{ .welcome = welcome });
        errdefer lockstep_protocol.deinitMessage(allocator, &message);
        self.lobby.ingestWelcome(message.welcome);
        message = .{ .keep_alive = .{} };
    }

    fn storeLobbyState(self: *ClientRuntime, allocator: std.mem.Allocator, state: lockstep_protocol.LobbyState) !void {
        if (self.lobby.lobby_state_latest) |old| {
            var old_message: lockstep_protocol.NetMessage = .{ .lobby_state = old };
            lockstep_protocol.deinitMessage(allocator, &old_message);
            self.lobby.lobby_state_latest = null;
        }
        var message = try lockstep_protocol.cloneMessage(allocator, .{ .lobby_state = state });
        errdefer lockstep_protocol.deinitMessage(allocator, &message);
        self.lobby.ingestLobbyState(message.lobby_state);
        message = .{ .keep_alive = .{} };
    }

    fn storeMatchStart(self: *ClientRuntime, allocator: std.mem.Allocator, start: lockstep_protocol.MatchStart) !void {
        if (self.lobby.match_start) |old| {
            var old_message: lockstep_protocol.NetMessage = .{ .match_start = old };
            lockstep_protocol.deinitMessage(allocator, &old_message);
            self.lobby.match_start = null;
        }
        var message = try lockstep_protocol.cloneMessage(allocator, .{ .match_start = start });
        errdefer lockstep_protocol.deinitMessage(allocator, &message);
        self.lobby.ingestMatchStart(message.match_start);
        message = .{ .keep_alive = .{} };
    }

    fn storePauseState(self: *ClientRuntime, allocator: std.mem.Allocator, pause: lockstep_protocol.PauseState) !void {
        self.clearPauseState(allocator);
        var message = try lockstep_protocol.cloneMessage(allocator, .{ .pause_state = pause });
        errdefer lockstep_protocol.deinitMessage(allocator, &message);
        self.pause_state = message.pause_state;
        message = .{ .keep_alive = .{} };
    }

    fn clearPauseState(self: *ClientRuntime, allocator: std.mem.Allocator) void {
        if (self.pause_state) |old| {
            var message: lockstep_protocol.NetMessage = .{ .pause_state = old };
            lockstep_protocol.deinitMessage(allocator, &message);
            self.pause_state = null;
        }
    }

    fn setError(self: *ClientRuntime, allocator: std.mem.Allocator, reason: []const u8) !void {
        if (self.error_reason.len != 0) {
            allocator.free(self.error_reason);
            self.error_reason = "";
        }
        self.error_reason = try allocator.dupe(u8, reason);
    }
};

fn deinitOwnedLobby(allocator: std.mem.Allocator, lobby: *lockstep_lobby.ClientLobby) void {
    if (lobby.welcome) |welcome| {
        var message: lockstep_protocol.NetMessage = .{ .welcome = welcome };
        lockstep_protocol.deinitMessage(allocator, &message);
        lobby.welcome = null;
    }
    if (lobby.lobby_state_latest) |state| {
        var message: lockstep_protocol.NetMessage = .{ .lobby_state = state };
        lockstep_protocol.deinitMessage(allocator, &message);
        lobby.lobby_state_latest = null;
    }
    if (lobby.match_start) |start| {
        var message: lockstep_protocol.NetMessage = .{ .match_start = start };
        lockstep_protocol.deinitMessage(allocator, &message);
        lobby.match_start = null;
    }
}

fn settingsEqual(a: session_settings.LockstepSessionSettings, b: session_settings.LockstepSessionSettings) bool {
    return a.mode_id == b.mode_id and
        a.player_count == b.player_count and
        questLevelEqual(a.quest_level, b.quest_level) and
        a.preserve_bugs == b.preserve_bugs and
        a.tick_rate == b.tick_rate and
        a.input_delay_ticks == b.input_delay_ticks and
        a.netcode_mode.value == b.netcode_mode.value;
}

fn questLevelEqual(a: ?quest_level.QuestLevel, b: ?quest_level.QuestLevel) bool {
    if (a == null or b == null) return a == null and b == null;
    return a.?.major == b.?.major and a.?.minor == b.?.minor;
}

fn buildWelcome(
    allocator: std.mem.Allocator,
    link: *lockstep_reliable.LockstepReliableLink,
    session_id: []const u8,
    slot_index: i32,
    now_ms: i64,
) !lockstep_protocol.LockstepPacket {
    return link.buildPacket(allocator, .{ .welcome = .{
        .accepted = true,
        .session_id = session_id,
        .build_id = "0.1.0",
        .mode_id = 2,
        .player_count = 2,
        .slot_index = slot_index,
    } }, true, now_ms);
}

test "lockstep client runtime sends reliable hello" {
    const allocator = std.testing.allocator;
    const host_addr = PeerAddr.loopback(31993);
    var client = ClientRuntime.init(.{
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .host_addr = host_addr,
    });
    defer client.deinit(allocator);

    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);
    try client.sendHello(allocator, 10, &outbox);

    try std.testing.expectEqual(@as(usize, 1), outbox.packets.items.len);
    try std.testing.expect(outbox.packets.items[0].packet.reliable);
    switch (outbox.packets.items[0].packet.message) {
        .hello => |hello| {
            try std.testing.expectEqualStrings("0.1.0", hello.build_id);
            try std.testing.expectEqual(@as(i32, 2), hello.mode_id);
            try std.testing.expect(!hello.host);
        },
        else => return error.TestExpectedEqual,
    }
}

test "lockstep client runtime accepts welcome and sends ready" {
    const allocator = std.testing.allocator;
    const host_addr = PeerAddr.loopback(31993);
    var client = ClientRuntime.init(.{
        .mode_id = 0,
        .player_count = 1,
        .build_id = "0.1.0",
        .host_addr = host_addr,
    });
    defer client.deinit(allocator);
    var host_link: lockstep_reliable.LockstepReliableLink = .{};
    defer host_link.deinit(allocator);

    const packet = try buildWelcome(allocator, &host_link, "session", 1, 10);
    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);
    try client.handlePacket(allocator, host_addr, packet, 10, &outbox);

    try std.testing.expect(client.lobby.joined());
    try std.testing.expectEqual(@as(i32, 1), client.lobby.slotIndex());
    try std.testing.expectEqual(@as(i32, 2), client.mode_id);
    try std.testing.expectEqual(@as(i32, 2), client.player_count);
    try std.testing.expectEqual(@as(usize, 1), outbox.packets.items.len);
    switch (outbox.packets.items[0].packet.message) {
        .ready => |ready| {
            try std.testing.expectEqual(@as(i32, 1), ready.slot_index);
            try std.testing.expect(ready.ready);
        },
        else => return error.TestExpectedEqual,
    }
    try std.testing.expectEqual(@as(i32, 1), outbox.packets.items[0].packet.ack);
}

test "lockstep client runtime retains lobby state payloads" {
    const allocator = std.testing.allocator;
    const host_addr = PeerAddr.loopback(31993);
    var client = ClientRuntime.init(.{
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .host_addr = host_addr,
    });
    defer client.deinit(allocator);
    var host_link: lockstep_reliable.LockstepReliableLink = .{};
    defer host_link.deinit(allocator);

    const slots = [_]lockstep_protocol.LobbySlot{
        .{ .slot_index = 0, .connected = true, .ready = true, .is_host = true, .peer_name = "host" },
        .{ .slot_index = 1, .connected = true, .ready = false, .is_host = false, .peer_name = "joiner" },
    };
    const encoded = try lockstep_protocol.encodePacket(allocator, try host_link.buildPacket(allocator, .{ .lobby_state = .{
        .session_id = "session",
        .mode_id = 2,
        .player_count = 2,
        .slots = slots[0..],
    } }, true, 20));
    defer allocator.free(encoded);

    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);
    {
        const decoded = try lockstep_protocol.decodePacket(allocator, encoded);
        defer decoded.deinit();
        try client.handlePacket(allocator, host_addr, decoded.value, 20, &outbox);
    }

    const state = client.lobby.lobby_state_latest.?;
    try std.testing.expectEqualStrings("session", state.session_id);
    try std.testing.expectEqualStrings("joiner", state.slots[1].peer_name);
}

test "lockstep client runtime starts and queues local input" {
    const allocator = std.testing.allocator;
    const host_addr = PeerAddr.loopback(31993);
    var status = std.mem.zeroes(game_cfg.Status);
    status.game_sequence_id = 88;
    var client = ClientRuntime.init(.{
        .mode_id = 0,
        .player_count = 1,
        .build_id = "0.1.0",
        .host_addr = host_addr,
    });
    defer client.deinit(allocator);
    var host_link: lockstep_reliable.LockstepReliableLink = .{};
    defer host_link.deinit(allocator);
    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);

    try client.handlePacket(allocator, host_addr, try buildWelcome(allocator, &host_link, "session", 1, 10), 10, &outbox);
    const start = try host_link.buildPacket(allocator, .{ .match_start = .{
        .session_id = "session",
        .mode_id = 2,
        .player_count = 2,
        .seed = 123,
        .status = status,
    } }, true, 20);
    try client.handlePacket(allocator, host_addr, start, 20, &outbox);

    try std.testing.expect(client.started);
    try std.testing.expect(client.lockstep != null);
    try std.testing.expectEqual(@as(i32, 1), client.lockstep.?.local_slot_index);

    try client.queueLocalInput(allocator, .{ .flags = 7 }, 30, &outbox);
    const sent = outbox.packets.items[outbox.packets.items.len - 1].packet;
    try std.testing.expect(!sent.reliable);
    switch (sent.message) {
        .input_batch => |batch| {
            try std.testing.expectEqual(@as(i32, 1), batch.slot_index);
            try std.testing.expectEqual(@as(usize, 1), batch.samples.len);
            try std.testing.expectEqual(@as(u32, 7), batch.samples[0].packed_input.flags);
        },
        else => return error.TestExpectedEqual,
    }
}

test "lockstep client runtime stores tick frames for consumption" {
    const allocator = std.testing.allocator;
    const host_addr = PeerAddr.loopback(31993);
    const status = std.mem.zeroes(game_cfg.Status);
    var client = ClientRuntime.init(.{
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .host_addr = host_addr,
    });
    defer client.deinit(allocator);
    var host_link: lockstep_reliable.LockstepReliableLink = .{};
    defer host_link.deinit(allocator);
    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);

    try client.handlePacket(allocator, host_addr, try buildWelcome(allocator, &host_link, "session", 1, 10), 10, &outbox);
    try client.handlePacket(allocator, host_addr, try host_link.buildPacket(allocator, .{ .match_start = .{
        .session_id = "session",
        .mode_id = 2,
        .player_count = 2,
        .seed = 123,
        .status = status,
    } }, true, 20), 20, &outbox);

    const inputs = [_]packed_input.PackedPlayerInput{
        .{ .flags = 1 },
        .{ .flags = 2 },
    };
    const commands = [_]lockstep_protocol.GameCommand{
        .{ .typo_char = .{ .player_index = 1, .ch = "z" } },
    };
    try client.handlePacket(allocator, host_addr, try host_link.buildPacket(allocator, .{ .tick_frame = .{
        .tick_index = 0,
        .frame_inputs = inputs[0..],
        .commands = commands[0..],
    } }, true, 30), 30, &outbox);

    try std.testing.expect(client.seen_tick_frame);
    var frame = client.popCanonicalFrame().?;
    defer lockstep_state.deinitTickFrame(allocator, &frame);
    try std.testing.expectEqual(@as(i32, 0), frame.tick_index);
    try std.testing.expectEqual(@as(u32, 2), frame.frame_inputs[1].flags);
    switch (frame.commands[0]) {
        .typo_char => |command| try std.testing.expectEqualStrings("z", command.ch),
        else => return error.TestExpectedEqual,
    }
}

test "lockstep client runtime records disconnect error" {
    const allocator = std.testing.allocator;
    const host_addr = PeerAddr.loopback(31993);
    var client = ClientRuntime.init(.{
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .host_addr = host_addr,
    });
    defer client.deinit(allocator);
    var host_link: lockstep_reliable.LockstepReliableLink = .{};
    defer host_link.deinit(allocator);
    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);

    try client.handlePacket(allocator, host_addr, try host_link.buildPacket(allocator, .{ .disconnect = .{
        .reason = "peer_timeout",
    } }, true, 10), 10, &outbox);

    try std.testing.expectEqualStrings("peer_timeout", client.error_reason);
}
