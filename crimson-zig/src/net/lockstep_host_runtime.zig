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

const host_max_capture_lead_ticks: i32 = 1;

pub const PeerAddr = lockstep_transport.PeerAddr;
pub const Outbox = lockstep_outbox.Outbox;

pub const HostRuntimeOptions = struct {
    mode_id: i32,
    player_count: i32,
    build_id: []const u8,
    session_id: []const u8,
    tick_rate: i32 = lockstep_protocol.tick_rate,
    input_delay_ticks: i32 = lockstep_protocol.input_delay_ticks,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    seed: i32 = 0,
    start_tick: i32 = 0,
    status: ?game_cfg.Status = null,
    host_ready: bool = true,
};

pub const HostRuntime = struct {
    lobby: lockstep_lobby.HostLobby,
    peers: std.ArrayList(HostPeerLink) = .empty,
    lockstep: ?lockstep_state.HostLockstepState = null,
    seed: i32 = 0,
    start_tick: i32 = 0,
    status: ?game_cfg.Status = null,
    host_capture_tick: i32 = 0,
    started: bool = false,

    pub fn init(options: HostRuntimeOptions) HostRuntime {
        return .{
            .lobby = lockstep_lobby.HostLobby.init(.{
                .mode_id = options.mode_id,
                .player_count = options.player_count,
                .build_id = options.build_id,
                .tick_rate = options.tick_rate,
                .input_delay_ticks = options.input_delay_ticks,
                .quest_level = options.quest_level,
                .preserve_bugs = options.preserve_bugs,
                .session_id = options.session_id,
                .host_ready = options.host_ready,
            }),
            .seed = options.seed,
            .start_tick = options.start_tick,
            .status = options.status,
        };
    }

    pub fn deinit(self: *HostRuntime, allocator: std.mem.Allocator) void {
        self.lobby.deinit(allocator);
        for (self.peers.items) |*peer| peer.deinit(allocator);
        self.peers.deinit(allocator);
        if (self.lockstep) |*lockstep| lockstep.deinit(allocator);
        self.* = undefined;
    }

    pub fn peerCount(self: HostRuntime) usize {
        return self.peers.items.len;
    }

    pub fn handlePacket(
        self: *HostRuntime,
        allocator: std.mem.Allocator,
        addr: PeerAddr,
        packet: lockstep_protocol.LockstepPacket,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        const peer_idx = self.peerIndex(addr);
        if (peer_idx == null) {
            switch (packet.message) {
                .hello => |hello| try self.handleHello(allocator, addr, packet, hello, now_ms, outbox),
                else => {},
            }
            return;
        }

        const idx = peer_idx.?;
        self.peers.items[idx].last_seen_ms = now_ms;
        var result = try self.peers.items[idx].link.ingestPacket(allocator, packet, now_ms);
        defer result.deinit(allocator);

        for (result.messages.items) |message| {
            try self.handlePeerMessage(allocator, addr, message, now_ms, outbox);
        }
    }

    pub fn submitLocalInput(
        self: *HostRuntime,
        allocator: std.mem.Allocator,
        input: packed_input.PackedPlayerInput,
    ) !void {
        const lockstep = if (self.lockstep) |*lockstep| lockstep else return;
        const max_capture_tick = lockstep.next_emit_tick + host_max_capture_lead_ticks;
        if (self.host_capture_tick > max_capture_tick) self.host_capture_tick = max_capture_tick;
        const target_tick = self.host_capture_tick + self.lobby.input_delay_ticks;
        try lockstep.submitInputSample(allocator, 0, target_tick, input);
        self.host_capture_tick += 1;
    }

    pub fn popReadyFrames(
        self: *HostRuntime,
        allocator: std.mem.Allocator,
        now_ms: i64,
    ) !std.ArrayList(lockstep_state.HostReadyTick) {
        const lockstep = if (self.lockstep) |*lockstep| lockstep else return .empty;
        return lockstep.popReadyFrames(allocator, now_ms);
    }

    pub fn broadcastTickFrame(
        self: *HostRuntime,
        allocator: std.mem.Allocator,
        frame: lockstep_protocol.TickFrame,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        try self.broadcast(allocator, .{ .tick_frame = frame }, true, now_ms, outbox);
    }

    pub fn pollResends(
        self: *HostRuntime,
        allocator: std.mem.Allocator,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        for (self.peers.items) |*peer| {
            var packets = try peer.link.pollResends(allocator, now_ms);
            defer lockstep_reliable.deinitPacketList(allocator, &packets);
            for (packets.items) |packet| {
                try outbox.appendPacket(allocator, peer.addr, packet);
            }
        }
    }

    fn handleHello(
        self: *HostRuntime,
        allocator: std.mem.Allocator,
        addr: PeerAddr,
        packet: lockstep_protocol.LockstepPacket,
        hello: lockstep_protocol.Hello,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        var key_buf: [32]u8 = undefined;
        const key = peerKey(&key_buf, addr);
        const welcome = try self.lobby.processHello(allocator, key, hello);

        if (welcome.accepted) {
            const peer = try self.ensurePeer(allocator, addr, now_ms);
            if (packet.reliable and packet.seq > 0) peer.link.primeRecvSeq(packet.seq);
        }

        try self.sendToPeer(allocator, addr, .{ .welcome = welcome }, true, now_ms, welcome.accepted, outbox);
        try self.broadcastLobbyState(allocator, now_ms, outbox);
    }

    fn handlePeerMessage(
        self: *HostRuntime,
        allocator: std.mem.Allocator,
        addr: PeerAddr,
        message: lockstep_protocol.NetMessage,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        switch (message) {
            .keep_alive => {},
            .hello => |hello| try self.handleHello(allocator, addr, .{ .message = .{ .hello = hello } }, hello, now_ms, outbox),
            .ready => |ready| {
                var key_buf: [32]u8 = undefined;
                self.lobby.processReady(peerKey(&key_buf, addr), ready);
                try self.broadcastLobbyState(allocator, now_ms, outbox);
                try self.startIfReady(allocator, now_ms, outbox);
            },
            .disconnect => {},
            .input_batch => |batch| {
                if (self.lockstep == null) return;
                var key_buf: [32]u8 = undefined;
                const mapped_slot = self.lobby.slotForAddr(peerKey(&key_buf, addr)) orelse return;
                const mapped: lockstep_protocol.InputBatch = .{
                    .slot_index = mapped_slot,
                    .samples = batch.samples,
                };
                try self.lockstep.?.submitInputBatch(allocator, mapped);
            },
            .debug_log_batch => {},
            else => {},
        }
    }

    pub fn startIfReady(
        self: *HostRuntime,
        allocator: std.mem.Allocator,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        if (self.started or !self.lobby.allReady()) return;
        const event = self.lobby.startMatch(.{
            .seed = self.seed,
            .start_tick = self.start_tick,
            .status = self.status,
        });
        self.started = true;
        try self.initLockstep(allocator, event, now_ms);
        try self.broadcast(allocator, .{ .match_start = event }, true, now_ms, outbox);
    }

    fn initLockstep(
        self: *HostRuntime,
        allocator: std.mem.Allocator,
        event: lockstep_protocol.MatchStart,
        now_ms: i64,
    ) !void {
        if (self.lockstep) |*existing| existing.deinit(allocator);
        self.lockstep = .{
            .player_count = event.player_count,
            .input_delay_ticks = self.lobby.input_delay_ticks,
            .last_progress_ms = now_ms,
        };
        self.host_capture_tick = 0;

        const delay = @max(0, self.lobby.input_delay_ticks);
        var tick: i32 = 0;
        while (tick < delay) : (tick += 1) {
            var slot: i32 = 0;
            while (slot < event.player_count) : (slot += 1) {
                try self.lockstep.?.submitInputSample(allocator, slot, tick, .{});
            }
        }
    }

    fn broadcastLobbyState(
        self: *HostRuntime,
        allocator: std.mem.Allocator,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        const state = try self.lobby.lobbyState(allocator);
        defer allocator.free(state.slots);
        try self.broadcast(allocator, .{ .lobby_state = state }, true, now_ms, outbox);
    }

    fn broadcast(
        self: *HostRuntime,
        allocator: std.mem.Allocator,
        message: lockstep_protocol.NetMessage,
        reliable: bool,
        now_ms: i64,
        outbox: *Outbox,
    ) !void {
        for (self.peers.items) |peer| {
            try self.sendToPeer(allocator, peer.addr, message, reliable, now_ms, true, outbox);
        }
    }

    fn sendToPeer(
        self: *HostRuntime,
        allocator: std.mem.Allocator,
        addr: PeerAddr,
        message: lockstep_protocol.NetMessage,
        reliable: bool,
        now_ms: i64,
        track_peer: bool,
        outbox: *Outbox,
    ) !void {
        if (self.peerIndex(addr)) |idx| {
            const packet = try self.peers.items[idx].link.buildPacket(allocator, message, reliable, now_ms);
            try outbox.appendPacket(allocator, addr, packet);
            return;
        }

        if (track_peer) {
            const peer = try self.ensurePeer(allocator, addr, now_ms);
            const packet = try peer.link.buildPacket(allocator, message, reliable, now_ms);
            try outbox.appendPacket(allocator, addr, packet);
            return;
        }

        var temp_link: lockstep_reliable.LockstepReliableLink = .{};
        defer temp_link.deinit(allocator);
        const packet = try temp_link.buildPacket(allocator, message, reliable, now_ms);
        try outbox.appendPacket(allocator, addr, packet);
    }

    fn ensurePeer(self: *HostRuntime, allocator: std.mem.Allocator, addr: PeerAddr, now_ms: i64) !*HostPeerLink {
        if (self.peerIndex(addr)) |idx| {
            self.peers.items[idx].last_seen_ms = now_ms;
            return &self.peers.items[idx];
        }

        const key = try allocPeerKey(allocator, addr);
        errdefer allocator.free(key);
        try self.peers.append(allocator, .{
            .addr = addr,
            .key = key,
            .last_seen_ms = now_ms,
        });
        return &self.peers.items[self.peers.items.len - 1];
    }

    fn peerIndex(self: HostRuntime, addr: PeerAddr) ?usize {
        for (self.peers.items, 0..) |peer, idx| {
            if (peer.addr.eql(addr)) return idx;
        }
        return null;
    }
};

pub const HostPeerLink = struct {
    addr: PeerAddr,
    key: []const u8,
    link: lockstep_reliable.LockstepReliableLink = .{},
    last_seen_ms: i64 = 0,

    fn deinit(self: *HostPeerLink, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        self.link.deinit(allocator);
        self.* = undefined;
    }
};

fn allocPeerKey(allocator: std.mem.Allocator, addr: PeerAddr) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "{d}.{d}.{d}.{d}:{d}",
        .{ addr.host[0], addr.host[1], addr.host[2], addr.host[3], addr.port },
    );
}

fn peerKey(buf: []u8, addr: PeerAddr) []const u8 {
    return std.fmt.bufPrint(
        buf,
        "{d}.{d}.{d}.{d}:{d}",
        .{ addr.host[0], addr.host[1], addr.host[2], addr.host[3], addr.port },
    ) catch unreachable;
}

test "lockstep host runtime accepts hello and emits welcome plus lobby state" {
    const allocator = std.testing.allocator;
    const peer = PeerAddr.loopback(42001);

    var host = HostRuntime.init(.{
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0+gabcdef1",
        .session_id = "session",
    });
    defer host.deinit(allocator);

    var client_link: lockstep_reliable.LockstepReliableLink = .{};
    defer client_link.deinit(allocator);
    const hello = try client_link.buildPacket(allocator, .{ .hello = .{
        .build_id = "abcdef1",
        .mode_id = 2,
        .player_count = 2,
    } }, true, 100);

    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);
    try host.handlePacket(allocator, peer, hello, 100, &outbox);

    try std.testing.expectEqual(@as(usize, 1), host.peerCount());
    try std.testing.expectEqual(@as(usize, 2), outbox.packets.items.len);
    switch (outbox.packets.items[0].packet.message) {
        .welcome => |welcome| {
            try std.testing.expect(welcome.accepted);
            try std.testing.expectEqual(@as(i32, 1), welcome.slot_index);
            try std.testing.expectEqualStrings("session", welcome.session_id);
        },
        else => return error.TestExpectedEqual,
    }
    switch (outbox.packets.items[1].packet.message) {
        .lobby_state => |state| {
            try std.testing.expectEqual(@as(usize, 2), state.slots.len);
            try std.testing.expect(state.slots[1].connected);
        },
        else => return error.TestExpectedEqual,
    }
}

test "lockstep host runtime ignores unknown non-hello packets" {
    const allocator = std.testing.allocator;
    var host = HostRuntime.init(.{
        .mode_id = 1,
        .player_count = 2,
        .build_id = "0.1.0",
        .session_id = "session",
    });
    defer host.deinit(allocator);

    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);
    try host.handlePacket(allocator, PeerAddr.loopback(42002), .{
        .seq = 1,
        .reliable = true,
        .message = .{ .disconnect = .{ .reason = "x" } },
    }, 0, &outbox);

    try std.testing.expectEqual(@as(usize, 0), host.peerCount());
    try std.testing.expectEqual(@as(usize, 0), outbox.packets.items.len);
}

test "lockstep host runtime starts once peer is ready" {
    const allocator = std.testing.allocator;
    const peer = PeerAddr.loopback(42003);
    var status = std.mem.zeroes(game_cfg.Status);
    status.play_time_ms = 77;

    var host = HostRuntime.init(.{
        .mode_id = 3,
        .player_count = 2,
        .build_id = "0.1.0",
        .session_id = "session",
        .seed = 123,
        .status = status,
    });
    defer host.deinit(allocator);

    var client_link: lockstep_reliable.LockstepReliableLink = .{};
    defer client_link.deinit(allocator);
    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);

    const hello = try client_link.buildPacket(allocator, .{ .hello = .{ .build_id = "0.1.0" } }, true, 10);
    try host.handlePacket(allocator, peer, hello, 10, &outbox);

    const ready = try client_link.buildPacket(allocator, .{ .ready = .{ .slot_index = 1, .ready = true } }, true, 20);
    try host.handlePacket(allocator, peer, ready, 20, &outbox);

    try std.testing.expect(host.started);
    try std.testing.expect(host.lockstep != null);
    var saw_start = false;
    for (outbox.packets.items) |packet| {
        switch (packet.packet.message) {
            .match_start => |start| {
                saw_start = true;
                try std.testing.expectEqual(@as(i32, 123), start.seed);
                try std.testing.expectEqual(@as(u32, 77), start.status.?.play_time_ms);
            },
            else => {},
        }
    }
    try std.testing.expect(saw_start);
}

test "lockstep host runtime starts single player when polled" {
    const allocator = std.testing.allocator;
    var status = std.mem.zeroes(game_cfg.Status);
    status.play_time_ms = 78;

    var host = HostRuntime.init(.{
        .mode_id = 3,
        .player_count = 1,
        .build_id = "0.1.0",
        .session_id = "solo",
        .seed = 456,
        .status = status,
    });
    defer host.deinit(allocator);

    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);

    try host.startIfReady(allocator, 10, &outbox);
    try std.testing.expect(host.started);
    try std.testing.expect(host.lockstep != null);
    try std.testing.expectEqual(@as(usize, 0), outbox.packets.items.len);
}

test "lockstep host runtime combines local and peer input into ready frames" {
    const allocator = std.testing.allocator;
    const peer = PeerAddr.loopback(42004);

    var host = HostRuntime.init(.{
        .mode_id = 1,
        .player_count = 2,
        .build_id = "0.1.0",
        .session_id = "session",
        .input_delay_ticks = 0,
    });
    defer host.deinit(allocator);

    var client_link: lockstep_reliable.LockstepReliableLink = .{};
    defer client_link.deinit(allocator);
    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);

    const hello = try client_link.buildPacket(allocator, .{ .hello = .{ .build_id = "0.1.0" } }, true, 10);
    try host.handlePacket(allocator, peer, hello, 10, &outbox);
    const ready = try client_link.buildPacket(allocator, .{ .ready = .{ .slot_index = 1, .ready = true } }, true, 20);
    try host.handlePacket(allocator, peer, ready, 20, &outbox);

    try host.submitLocalInput(allocator, .{ .flags = 3 });
    const samples = [_]lockstep_protocol.InputSample{
        .{ .tick_index = 0, .packed_input = .{ .flags = 9 } },
    };
    const input_batch = try client_link.buildPacket(allocator, .{ .input_batch = .{
        .slot_index = 1,
        .samples = samples[0..],
    } }, false, 30);
    try host.handlePacket(allocator, peer, input_batch, 30, &outbox);

    var frames = try host.popReadyFrames(allocator, 30);
    defer lockstep_state.deinitHostReadyTicks(allocator, &frames);
    try std.testing.expectEqual(@as(usize, 1), frames.items.len);
    try std.testing.expectEqual(@as(i32, 0), frames.items[0].tick_index);
    try std.testing.expectEqual(@as(u32, 3), frames.items[0].frame_inputs[0].flags);
    try std.testing.expectEqual(@as(u32, 9), frames.items[0].frame_inputs[1].flags);
}

test "lockstep host runtime broadcasts tick frames through reliable peer links" {
    const allocator = std.testing.allocator;
    const peer = PeerAddr.loopback(42005);

    var host = HostRuntime.init(.{
        .mode_id = 1,
        .player_count = 2,
        .build_id = "0.1.0",
        .session_id = "session",
    });
    defer host.deinit(allocator);

    var client_link: lockstep_reliable.LockstepReliableLink = .{};
    defer client_link.deinit(allocator);
    var outbox: Outbox = .{};
    defer outbox.deinit(allocator);

    const hello = try client_link.buildPacket(allocator, .{ .hello = .{ .build_id = "0.1.0" } }, true, 10);
    try host.handlePacket(allocator, peer, hello, 10, &outbox);

    const inputs = [_]packed_input.PackedPlayerInput{
        .{ .flags = 1 },
        .{ .flags = 2 },
    };
    const commands = [_]lockstep_protocol.GameCommand{
        .{ .typo_char = .{ .player_index = 1, .ch = "x" } },
    };
    try host.broadcastTickFrame(allocator, .{
        .tick_index = 4,
        .frame_inputs = inputs[0..],
        .commands = commands[0..],
    }, 40, &outbox);

    const sent = outbox.packets.items[outbox.packets.items.len - 1].packet;
    try std.testing.expect(sent.reliable);
    switch (sent.message) {
        .tick_frame => |frame| {
            try std.testing.expectEqual(@as(i32, 4), frame.tick_index);
            try std.testing.expectEqual(@as(usize, 2), frame.frame_inputs.len);
            switch (frame.commands[0]) {
                .typo_char => |command| try std.testing.expectEqualStrings("x", command.ch),
                else => return error.TestExpectedEqual,
            }
        },
        else => return error.TestExpectedEqual,
    }

    var resends: Outbox = .{};
    defer resends.deinit(allocator);
    try host.pollResends(allocator, 80, &resends);
    try std.testing.expect(resends.packets.items.len >= 1);
}
