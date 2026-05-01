const std = @import("std");

const game_cfg = @import("../formats/game_cfg.zig");
const lockstep_protocol = @import("lockstep_protocol.zig");
const quest_level = @import("../quest_level.zig");
const session_settings = @import("session_settings.zig");

pub const PeerAddr = []const u8;

pub const HostPeer = struct {
    addr: PeerAddr,
    slot_index: i32,
    ready: bool = false,
    peer_name: []const u8 = "",

    fn deinit(self: HostPeer, allocator: std.mem.Allocator) void {
        allocator.free(self.addr);
    }
};

pub const HostLobbyOptions = struct {
    mode_id: i32,
    player_count: i32,
    build_id: []const u8,
    tick_rate: i32 = lockstep_protocol.tick_rate,
    input_delay_ticks: i32 = lockstep_protocol.input_delay_ticks,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    session_id: []const u8,
    host_ready: bool = true,
};

pub const MatchStartOptions = struct {
    seed: i32,
    start_tick: i32 = 0,
    status: ?game_cfg.Status = null,
};

pub const HostLobby = struct {
    mode_id: i32,
    player_count: i32,
    build_id: []const u8,
    tick_rate: i32,
    input_delay_ticks: i32,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    session_id: []const u8,
    started: bool = false,
    host_ready: bool = true,
    peers: std.ArrayList(HostPeer) = .empty,

    pub fn init(options: HostLobbyOptions) HostLobby {
        return .{
            .mode_id = options.mode_id,
            .player_count = std.math.clamp(options.player_count, @as(i32, 1), session_settings.max_players),
            .build_id = options.build_id,
            .tick_rate = @max(options.tick_rate, 1),
            .input_delay_ticks = @max(options.input_delay_ticks, 0),
            .quest_level = options.quest_level,
            .preserve_bugs = options.preserve_bugs,
            .session_id = options.session_id,
            .host_ready = options.host_ready,
        };
    }

    pub fn deinit(self: *HostLobby, allocator: std.mem.Allocator) void {
        for (self.peers.items) |peer| peer.deinit(allocator);
        self.peers.deinit(allocator);
        self.* = undefined;
    }

    pub fn sessionSettings(self: HostLobby) session_settings.LockstepSessionSettings {
        return session_settings.forLockstep(.{
            .mode_id = self.mode_id,
            .player_count = self.player_count,
            .quest_level = self.quest_level,
            .preserve_bugs = self.preserve_bugs,
            .tick_rate = self.tick_rate,
            .input_delay_ticks = self.input_delay_ticks,
        });
    }

    pub fn processHello(
        self: *HostLobby,
        allocator: std.mem.Allocator,
        addr: PeerAddr,
        hello: lockstep_protocol.Hello,
    ) !lockstep_protocol.Welcome {
        if (self.started) return rejectedWelcome("match_already_started");
        if (hello.protocol_version != lockstep_protocol.protocol_version) return rejectedWelcome("protocol_mismatch");
        if (!lockstep_protocol.buildsCompatible(hello.build_id, self.build_id)) return rejectedWelcome("build_mismatch");
        if (hello.host) return rejectedWelcome("hello_host_flag");

        const slot_index = if (self.peerIndex(addr)) |idx|
            self.peers.items[idx].slot_index
        else blk: {
            const slot = self.nextFreeSlot() orelse return rejectedWelcome("lobby_full");
            const addr_owned = try allocator.dupe(u8, addr);
            errdefer allocator.free(addr_owned);
            try self.peers.append(allocator, .{ .addr = addr_owned, .slot_index = slot });
            break :blk slot;
        };

        return session_settings.welcomeFromSettings(self.sessionSettings(), .{
            .accepted = true,
            .session_id = self.session_id,
            .protocol_version = lockstep_protocol.protocol_version,
            .build_id = self.build_id,
            .slot_index = slot_index,
            .host_slot_index = 0,
            .seed = 0,
            .started = self.started,
        });
    }

    pub fn processReady(self: *HostLobby, addr: PeerAddr, ready: lockstep_protocol.Ready) void {
        const idx = self.peerIndex(addr) orelse return;
        const peer = &self.peers.items[idx];
        if (ready.slot_index != peer.slot_index) return;
        peer.ready = ready.ready;
    }

    pub fn allConnected(self: HostLobby) bool {
        if (self.player_count <= 1) return true;
        return self.peers.items.len >= @as(usize, @intCast(self.player_count - 1));
    }

    pub fn allReady(self: HostLobby) bool {
        if (!self.host_ready or !self.allConnected()) return false;
        for (self.peers.items) |peer| {
            if (!peer.ready) return false;
        }
        return true;
    }

    pub fn slotForAddr(self: HostLobby, addr: PeerAddr) ?i32 {
        const idx = self.peerIndex(addr) orelse return null;
        return self.peers.items[idx].slot_index;
    }

    pub fn lobbyState(self: HostLobby, allocator: std.mem.Allocator) !lockstep_protocol.LobbyState {
        const slots = try allocator.alloc(lockstep_protocol.LobbySlot, @intCast(self.player_count));
        errdefer allocator.free(slots);

        for (slots, 0..) |*slot, idx| {
            const slot_index: i32 = @intCast(idx);
            if (slot_index == 0) {
                slot.* = .{
                    .slot_index = 0,
                    .connected = true,
                    .ready = self.host_ready,
                    .is_host = true,
                    .peer_name = "host",
                };
            } else if (self.peerForSlot(slot_index)) |peer| {
                slot.* = .{
                    .slot_index = slot_index,
                    .connected = true,
                    .ready = peer.ready,
                    .is_host = false,
                    .peer_name = peer.peer_name,
                };
            } else {
                slot.* = .{
                    .slot_index = slot_index,
                    .connected = false,
                    .ready = false,
                    .is_host = false,
                    .peer_name = "",
                };
            }
        }

        return .{
            .session_id = self.session_id,
            .mode_id = self.mode_id,
            .player_count = self.player_count,
            .slots = slots,
            .all_ready = self.allReady(),
            .started = self.started,
            .quest_level = self.quest_level,
        };
    }

    pub fn startMatch(self: *HostLobby, options: MatchStartOptions) lockstep_protocol.MatchStart {
        self.started = true;
        return session_settings.matchStartFromSettings(self.sessionSettings(), .{
            .session_id = self.session_id,
            .seed = options.seed,
            .start_tick = options.start_tick,
            .status = options.status,
        });
    }

    fn nextFreeSlot(self: HostLobby) ?i32 {
        var slot: i32 = 1;
        while (slot < self.player_count) : (slot += 1) {
            if (self.peerForSlot(slot) == null) return slot;
        }
        return null;
    }

    fn peerIndex(self: HostLobby, addr: PeerAddr) ?usize {
        for (self.peers.items, 0..) |peer, idx| {
            if (std.mem.eql(u8, peer.addr, addr)) return idx;
        }
        return null;
    }

    fn peerForSlot(self: HostLobby, slot_index: i32) ?HostPeer {
        for (self.peers.items) |peer| {
            if (peer.slot_index == slot_index) return peer;
        }
        return null;
    }
};

pub const ClientLobby = struct {
    build_id: []const u8,
    hello: lockstep_protocol.Hello,
    welcome: ?lockstep_protocol.Welcome = null,
    lobby_state_latest: ?lockstep_protocol.LobbyState = null,
    match_start: ?lockstep_protocol.MatchStart = null,

    pub fn slotIndex(self: ClientLobby) i32 {
        return if (self.welcome) |welcome| welcome.slot_index else -1;
    }

    pub fn joined(self: ClientLobby) bool {
        return if (self.welcome) |welcome| welcome.accepted else false;
    }

    pub fn started(self: ClientLobby) bool {
        return self.match_start != null;
    }

    pub fn ingestWelcome(self: *ClientLobby, welcome: lockstep_protocol.Welcome) void {
        self.welcome = welcome;
    }

    pub fn ingestLobbyState(self: *ClientLobby, state: lockstep_protocol.LobbyState) void {
        self.lobby_state_latest = state;
    }

    pub fn ingestMatchStart(self: *ClientLobby, event: lockstep_protocol.MatchStart) void {
        self.match_start = event;
    }
};

fn rejectedWelcome(reason: []const u8) lockstep_protocol.Welcome {
    return .{ .accepted = false, .reason = reason };
}

test "lockstep host lobby accepts hello and waits for ready" {
    const allocator = std.testing.allocator;
    var lobby = HostLobby.init(.{
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0+gabcdef1",
        .session_id = "session",
    });
    defer lobby.deinit(allocator);

    const welcome = try lobby.processHello(allocator, "127.0.0.1:40000", .{
        .protocol_version = lockstep_protocol.protocol_version,
        .build_id = "abcdef1",
    });
    try std.testing.expect(welcome.accepted);
    try std.testing.expectEqual(@as(i32, 1), welcome.slot_index);
    try std.testing.expectEqualStrings("session", welcome.session_id);
    try std.testing.expectEqual(@as(i32, 2), welcome.mode_id);
    try std.testing.expect(!lobby.allReady());

    lobby.processReady("127.0.0.1:40000", .{ .slot_index = 1, .ready = true });
    try std.testing.expect(lobby.allConnected());
    try std.testing.expect(lobby.allReady());

    const state = try lobby.lobbyState(allocator);
    defer allocator.free(state.slots);
    try std.testing.expectEqual(@as(usize, 2), state.slots.len);
    try std.testing.expect(state.all_ready);
    try std.testing.expect(state.slots[0].is_host);
    try std.testing.expect(state.slots[1].connected);
    try std.testing.expect(state.slots[1].ready);
}

test "lockstep host lobby rejects invalid hello and full lobby" {
    const allocator = std.testing.allocator;
    var lobby = HostLobby.init(.{
        .mode_id = 1,
        .player_count = 2,
        .build_id = "0.1.0+gabcdef1",
        .session_id = "session",
    });
    defer lobby.deinit(allocator);

    const host_flag = try lobby.processHello(allocator, "peer-host", .{ .host = true, .build_id = lobby.build_id });
    try std.testing.expect(!host_flag.accepted);
    try std.testing.expectEqualStrings("hello_host_flag", host_flag.reason);

    const mismatch = try lobby.processHello(allocator, "peer-mismatch", .{ .build_id = "0.1.0+gabcdef2" });
    try std.testing.expect(!mismatch.accepted);
    try std.testing.expectEqualStrings("build_mismatch", mismatch.reason);

    const first = try lobby.processHello(allocator, "peer-one", .{ .build_id = lobby.build_id });
    try std.testing.expect(first.accepted);

    const full = try lobby.processHello(allocator, "peer-two", .{ .build_id = lobby.build_id });
    try std.testing.expect(!full.accepted);
    try std.testing.expectEqualStrings("lobby_full", full.reason);
}

test "lockstep host lobby start match mirrors session settings" {
    const allocator = std.testing.allocator;
    var status = std.mem.zeroes(game_cfg.Status);
    status.game_sequence_id = 77;
    var lobby = HostLobby.init(.{
        .mode_id = 3,
        .player_count = 1,
        .build_id = "0.1.0",
        .session_id = "session",
        .quest_level = try quest_level.QuestLevel.parse("4.2"),
        .preserve_bugs = true,
    });
    defer lobby.deinit(allocator);

    const start = lobby.startMatch(.{ .seed = 123, .start_tick = 9, .status = status });
    try std.testing.expect(lobby.started);
    try std.testing.expectEqualStrings("session", start.session_id);
    try std.testing.expectEqual(@as(i32, 3), start.mode_id);
    try std.testing.expectEqual(@as(i32, 4), start.quest_level.?.major);
    try std.testing.expectEqual(@as(i32, 2), start.quest_level.?.minor);
    try std.testing.expect(start.preserve_bugs);
    try std.testing.expectEqual(@as(i32, 123), start.seed);
    try std.testing.expectEqual(@as(i32, 9), start.start_tick);
    try std.testing.expectEqual(@as(u32, 77), start.status.?.game_sequence_id);
}

test "lockstep client lobby tracks welcome state and match start" {
    var client: ClientLobby = .{
        .build_id = "0.1.0",
        .hello = .{ .build_id = "0.1.0" },
    };

    try std.testing.expectEqual(@as(i32, -1), client.slotIndex());
    try std.testing.expect(!client.joined());
    try std.testing.expect(!client.started());

    client.ingestWelcome(.{ .accepted = true, .slot_index = 2, .session_id = "session" });
    try std.testing.expect(client.joined());
    try std.testing.expectEqual(@as(i32, 2), client.slotIndex());

    client.ingestLobbyState(.{ .session_id = "session", .started = false });
    try std.testing.expect(client.lobby_state_latest != null);

    client.ingestMatchStart(.{ .session_id = "session", .seed = 12 });
    try std.testing.expect(client.started());
    try std.testing.expectEqual(@as(i32, 12), client.match_start.?.seed);
}
