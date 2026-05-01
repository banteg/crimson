const std = @import("std");

const live_runner = @import("../runtime/live_runner.zig");
const packed_input = @import("packed_input.zig");
const relay_reliable = @import("relay_reliable.zig");
const relay_protocol = @import("relay_protocol.zig");
const relay_service = @import("relay_service.zig");
const relay_transport = @import("relay_transport.zig");
const rollback_live_bridge = @import("rollback_live_bridge.zig");
const rollback_runtime = @import("rollback_runtime.zig");
const rollback_session = @import("rollback_session.zig");
const room_code = @import("room_code.zig");

const Io = std.Io;
const max_players: usize = @intCast(relay_protocol.max_players);
const runner_snapshot_keep_ticks: i32 = 64;

pub const LiveSessionError = rollback_live_bridge.BridgeError || live_runner.LiveRunnerError || error{OutOfMemory};

pub const StepSummary = struct {
    frames_advanced: usize = 0,
    ticks_advanced: usize = 0,
    last_tick_index: ?i32 = null,
    last_player_count: usize = 0,
    last_input_flags: [max_players]u32 = [_]u32{0} ** max_players,
    last_update: ?live_runner.FrameUpdate = null,
};

pub const Options = struct {
    session: rollback_session.Options,
    server_addr: relay_transport.PeerAddr,
    bind_host: []const u8 = "0.0.0.0",
    bind_port: u16 = 0,
    max_packets_per_update: usize = 64,
};

pub const LiveSession = struct {
    transport: relay_transport.UdpTransport,
    server_addr: relay_transport.PeerAddr,
    session: rollback_session.Session,
    runner: ?live_runner.LiveRunner = null,
    runner_snapshots: std.ArrayList(LiveRunnerSnapshotEntry) = .empty,
    max_packets_per_update: usize,

    pub fn init(options: Options) LiveSession {
        return .{
            .transport = .{
                .bind_host = options.bind_host,
                .bind_port = options.bind_port,
            },
            .server_addr = options.server_addr,
            .session = rollback_session.Session.init(options.session),
            .max_packets_per_update = @max(@as(usize, 1), options.max_packets_per_update),
        };
    }

    pub fn deinit(self: *LiveSession, allocator: std.mem.Allocator, io: Io) void {
        self.close(io);
        self.runner_snapshots.deinit(allocator);
        self.session.deinit(allocator);
        self.* = undefined;
    }

    pub fn open(self: *LiveSession, io: Io) !void {
        try self.transport.open(io);
    }

    pub fn close(self: *LiveSession, io: Io) void {
        self.transport.close(io);
    }

    pub fn boundPort(self: LiveSession) u16 {
        return self.transport.boundPort();
    }

    pub fn update(self: *LiveSession, allocator: std.mem.Allocator, io: Io, now_ms: i64) !void {
        try self.open(io);
        try self.drainIncoming(allocator, io, now_ms);
        try self.session.update(allocator, now_ms);
        try self.flushSessionOutbox(allocator, io);
    }

    pub fn queueLocalInput(
        self: *LiveSession,
        allocator: std.mem.Allocator,
        io: Io,
        input: packed_input.PackedPlayerInput,
        now_ms: i64,
    ) !void {
        try self.session.queueLocalInput(allocator, input, now_ms);
        try self.flushSessionOutbox(allocator, io);
    }

    pub fn popFrame(self: *LiveSession) ?rollback_runtime.TickFrame {
        return self.session.popFrame();
    }

    pub fn ensureLiveRunner(self: *LiveSession) LiveSessionError!bool {
        if (self.runner != null) return false;
        const match_config = self.session.match_config orelse return false;
        self.runner = try live_runner.LiveRunner.init(try rollback_live_bridge.liveConfigFromMatchConfig(match_config));
        return true;
    }

    pub fn stepFrames(self: *LiveSession, allocator: std.mem.Allocator) LiveSessionError!StepSummary {
        _ = try self.ensureLiveRunner();
        if (self.runner == null) return .{};

        self.applyPendingRollback();

        var summary: StepSummary = .{};
        while (self.popFrame()) |frame| {
            const update_result = try rollback_live_bridge.stepFrame(&self.runner.?, frame);
            try self.rememberRunnerSnapshot(allocator, frame.tick_index);
            if (self.session.runtime) |*runtime| {
                try runtime.markLocalRollbackSnapshot(frame.tick_index);
            }
            summary.frames_advanced += 1;
            summary.ticks_advanced += update_result.ticks_advanced;
            summary.last_tick_index = frame.tick_index;
            const captured = captureInputFlags(frame);
            summary.last_player_count = captured.player_count;
            summary.last_input_flags = captured.flags;
            summary.last_update = update_result;
        }
        return summary;
    }

    fn drainIncoming(self: *LiveSession, allocator: std.mem.Allocator, io: Io, now_ms: i64) !void {
        var packets = try self.transport.recvPackets(allocator, io, self.max_packets_per_update, 0);
        defer packets.deinit(allocator);
        for (packets.items.items) |*received| {
            if (!received.addr.eql(self.server_addr)) continue;
            try self.session.handlePacket(allocator, received.packet(), now_ms);
        }
    }

    fn flushSessionOutbox(self: *LiveSession, allocator: std.mem.Allocator, io: Io) !void {
        defer self.session.clearOutbox(allocator);
        for (self.session.outbox.items.items) |packet| {
            try self.transport.sendPacket(allocator, io, self.server_addr, packet);
        }
    }

    fn applyPendingRollback(self: *LiveSession) void {
        const runtime = if (self.session.runtime) |*runtime| runtime else return;
        while (runtime.drainRollbackFrom()) |from_tick| {
            if (from_tick <= 0) continue;
            self.restoreRunnerSnapshotAtOrBefore(from_tick - 1);
        }
    }

    fn rememberRunnerSnapshot(self: *LiveSession, allocator: std.mem.Allocator, tick_index: i32) !void {
        const runner = if (self.runner) |*runner| runner else return;
        for (self.runner_snapshots.items) |*entry| {
            if (entry.tick_index == tick_index) {
                entry.snapshot = runner.captureSnapshot();
                return;
            }
        }
        try self.runner_snapshots.append(allocator, .{
            .tick_index = tick_index,
            .snapshot = runner.captureSnapshot(),
        });
        self.pruneRunnerSnapshots(tick_index - runner_snapshot_keep_ticks);
    }

    fn restoreRunnerSnapshotAtOrBefore(self: *LiveSession, tick_index: i32) void {
        var best_idx: ?usize = null;
        for (self.runner_snapshots.items, 0..) |entry, idx| {
            if (entry.tick_index <= tick_index and (best_idx == null or entry.tick_index > self.runner_snapshots.items[best_idx.?].tick_index)) {
                best_idx = idx;
            }
        }
        if (best_idx) |idx| {
            self.runner.?.restoreSnapshot(&self.runner_snapshots.items[idx].snapshot);
        }
    }

    fn pruneRunnerSnapshots(self: *LiveSession, keep_from: i32) void {
        var idx: usize = 0;
        while (idx < self.runner_snapshots.items.len) {
            if (self.runner_snapshots.items[idx].tick_index >= keep_from) {
                idx += 1;
                continue;
            }
            _ = self.runner_snapshots.orderedRemove(idx);
        }
    }
};

const LiveRunnerSnapshotEntry = struct {
    tick_index: i32,
    snapshot: live_runner.LiveRunnerSnapshot,
};

const CapturedInputFlags = struct {
    player_count: usize = 0,
    flags: [max_players]u32 = [_]u32{0} ** max_players,
};

fn captureInputFlags(frame: rollback_runtime.TickFrame) CapturedInputFlags {
    var captured: CapturedInputFlags = .{};
    captured.player_count = @min(frame.player_count, captured.flags.len);
    for (frame.frame_inputs[0..captured.player_count], 0..) |input, idx| {
        captured.flags[idx] = input.flags;
    }
    return captured;
}

fn serviceAddrFromTransport(addr: relay_transport.PeerAddr) relay_service.PeerAddr {
    return .{ .host = addr.host, .port = addr.port };
}

fn transportAddrFromService(addr: relay_service.PeerAddr) relay_transport.PeerAddr {
    return .{ .host = addr.host, .port = addr.port };
}

fn pumpRelayService(
    allocator: std.mem.Allocator,
    io: Io,
    server: relay_transport.UdpTransport,
    service: *relay_service.RelayService,
    now_ms: i64,
) !usize {
    var packets = try server.recvPackets(allocator, io, 64, 10);
    defer packets.deinit(allocator);

    var sent: usize = 0;
    for (packets.items.items) |*received| {
        var outbox = try service.receivePacket(
            allocator,
            serviceAddrFromTransport(received.addr),
            received.packet(),
            .{ .dispatch = .{ .now_ms = now_ms } },
        );
        defer outbox.deinit(allocator);

        for (outbox.items.items) |item| {
            try server.sendPacket(allocator, io, transportAddrFromService(item.addr), item.packet);
            sent += 1;
        }
    }
    return sent;
}

fn driveRollbackHostUntilRoomCode(
    allocator: std.mem.Allocator,
    io: Io,
    server: relay_transport.UdpTransport,
    service: *relay_service.RelayService,
    host: *LiveSession,
    start_ms: i64,
) !room_code.RoomCode {
    for (0..16) |step| {
        const now_ms = start_ms + @as(i64, @intCast(step));
        try host.update(allocator, io, now_ms);
        _ = try pumpRelayService(allocator, io, server, service, now_ms);
        if (host.session.room_code_latest) |code| return code;
    }
    return error.ExpectedRoomCode;
}

fn driveRollbackPairUntilStarted(
    allocator: std.mem.Allocator,
    io: Io,
    server: relay_transport.UdpTransport,
    service: *relay_service.RelayService,
    host: *LiveSession,
    guest: *LiveSession,
    start_ms: i64,
) !void {
    for (0..32) |step| {
        if (host.session.started and guest.session.started) return;
        const now_ms = start_ms + @as(i64, @intCast(step));
        try host.update(allocator, io, now_ms);
        _ = try pumpRelayService(allocator, io, server, service, now_ms);
        try guest.update(allocator, io, now_ms);
        _ = try pumpRelayService(allocator, io, server, service, now_ms);
    }
    return error.ExpectedRoomStart;
}

test "rollback live session sends hello to relay endpoint" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var relay_receiver: relay_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try relay_receiver.open(io);
    defer relay_receiver.close(io);

    var live = LiveSession.init(.{
        .server_addr = relay_transport.PeerAddr.loopback(relay_receiver.boundPort()),
        .bind_host = "127.0.0.1",
        .session = .{
            .role = .host,
            .mode_id = 2,
            .player_count = 2,
            .build_id = "0.1.0",
            .peer_name = "host",
        },
    });
    defer live.deinit(allocator, io);

    try live.update(allocator, io, 1000);

    var packets = try relay_receiver.recvPackets(allocator, io, 4, 100);
    defer packets.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), packets.items.items.len);
    switch (packets.items.items[0].packet().message) {
        .client_hello => |hello| {
            try std.testing.expectEqualStrings("0.1.0", hello.build_id);
            try std.testing.expectEqualStrings("host", hello.peer_name);
        },
        else => return error.ExpectedClientHello,
    }
}

test "rollback live session receives room start and packetizes local input" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var relay_sender: relay_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try relay_sender.open(io);
    defer relay_sender.close(io);

    var relay_receiver: relay_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try relay_receiver.open(io);
    defer relay_receiver.close(io);

    var live = LiveSession.init(.{
        .server_addr = relay_transport.PeerAddr.loopback(relay_sender.boundPort()),
        .bind_host = "127.0.0.1",
        .session = .{
            .role = .host,
            .mode_id = 2,
            .player_count = 1,
            .build_id = "0.1.0",
            .input_delay_ticks = 0,
        },
    });
    defer live.deinit(allocator, io);
    try live.open(io);

    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    const code = try room_code.parseRoomCode("ABCD");
    try relay_sender.sendPacket(allocator, io, relay_transport.PeerAddr.loopback(live.boundPort()), try server_link.buildPacket(allocator, .{ .room_start = .{
        .room_code = code,
        .session_id = "s1",
        .player_count = 1,
        .slot_index = 0,
        .input_delay_ticks = 0,
        .rollback_max_ticks = 8,
    } }, true, 1000));

    try live.update(allocator, io, 1001);
    try std.testing.expect(live.session.started);
    try live.queueLocalInput(allocator, io, .{ .flags = 7 }, 1002);

    var packets = try relay_sender.recvPackets(allocator, io, 8, 100);
    defer packets.deinit(allocator);
    var saw_input = false;
    for (packets.items.items) |*received| {
        switch (received.packet().message) {
            .rb_input_sample => |batch| {
                saw_input = true;
                try std.testing.expectEqual(@as(i32, 0), batch.slot_index);
                try std.testing.expectEqual(@as(u32, 7), batch.samples[0].packed_input.flags);
            },
            else => {},
        }
    }
    try std.testing.expect(saw_input);

    const frame = live.popFrame() orelse return error.ExpectedFrame;
    try std.testing.expectEqual(@as(u32, 7), frame.input(0).flags);
}

test "rollback live session creates runner and steps local frames after room start" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var relay_sender: relay_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try relay_sender.open(io);
    defer relay_sender.close(io);

    var live = LiveSession.init(.{
        .server_addr = relay_transport.PeerAddr.loopback(relay_sender.boundPort()),
        .bind_host = "127.0.0.1",
        .session = .{
            .role = .host,
            .mode_id = 2,
            .player_count = 1,
            .build_id = "0.1.0",
            .input_delay_ticks = 0,
        },
    });
    defer live.deinit(allocator, io);
    try live.open(io);

    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    const code = try room_code.parseRoomCode("ABCD");
    try relay_sender.sendPacket(allocator, io, relay_transport.PeerAddr.loopback(live.boundPort()), try server_link.buildPacket(allocator, .{ .room_start = .{
        .room_code = code,
        .session_id = "s1",
        .seed = 1234,
        .mode_id = 2,
        .player_count = 1,
        .slot_index = 0,
        .input_delay_ticks = 0,
        .rollback_max_ticks = 8,
    } }, true, 1000));

    try live.update(allocator, io, 1001);
    try std.testing.expect(try live.ensureLiveRunner());
    try std.testing.expect(!try live.ensureLiveRunner());
    try std.testing.expectEqual(@as(u32, 1234), live.runner.?.seed);

    try live.queueLocalInput(allocator, io, .{ .flags = 7 }, 1002);
    const summary = try live.stepFrames(allocator);
    try std.testing.expectEqual(@as(usize, 1), summary.frames_advanced);
    try std.testing.expectEqual(@as(?i32, 0), summary.last_tick_index);
    try std.testing.expectEqual(@as(usize, 1), summary.last_player_count);
    try std.testing.expectEqual(@as(u32, 7), summary.last_input_flags[0]);
    try std.testing.expect(summary.last_update != null);
}

test "rollback live session restores runner snapshot for local rollback" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var relay_sender: relay_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try relay_sender.open(io);
    defer relay_sender.close(io);

    var live = LiveSession.init(.{
        .server_addr = relay_transport.PeerAddr.loopback(relay_sender.boundPort()),
        .bind_host = "127.0.0.1",
        .session = .{
            .role = .host,
            .mode_id = 2,
            .player_count = 2,
            .build_id = "0.1.0",
            .input_delay_ticks = 0,
        },
    });
    defer live.deinit(allocator, io);
    try live.open(io);

    var server_link: relay_reliable.RelayReliableLink = .{};
    defer server_link.deinit(allocator);
    const code = try room_code.parseRoomCode("ABCD");
    try relay_sender.sendPacket(allocator, io, relay_transport.PeerAddr.loopback(live.boundPort()), try server_link.buildPacket(allocator, .{ .room_start = .{
        .room_code = code,
        .session_id = "s1",
        .seed = 1234,
        .mode_id = 2,
        .player_count = 2,
        .slot_index = 0,
        .input_delay_ticks = 0,
        .rollback_max_ticks = 8,
    } }, true, 1000));

    try live.update(allocator, io, 1001);
    try live.queueLocalInput(allocator, io, .{ .flags = 1 }, 1002);
    _ = try live.stepFrames(allocator);
    try live.queueLocalInput(allocator, io, .{ .flags = 3 }, 1003);
    _ = try live.stepFrames(allocator);
    try std.testing.expectEqual(@as(usize, 2), live.runner.?.session.tick_index);

    try live.session.runtime.?.handleMessage(.{ .rb_input_sample = .{
        .slot_index = 1,
        .samples = &[_]relay_protocol.RbInputSample{.{ .tick_index = 1, .packed_input = .{ .flags = 9 } }},
    } }, 1004);

    const runtime = &live.session.runtime.?;
    try std.testing.expectEqual(@as(i32, 1), runtime.rollback_count);
    try std.testing.expect(!runtime.paused_for_resync);

    const summary = try live.stepFrames(allocator);
    try std.testing.expectEqual(@as(usize, 1), summary.frames_advanced);
    try std.testing.expectEqual(@as(?i32, 1), summary.last_tick_index);
    try std.testing.expectEqual(@as(u32, 9), summary.last_input_flags[1]);
    try std.testing.expectEqual(@as(usize, 2), live.runner.?.session.tick_index);
}

test "rollback live sessions handshake and exchange input through relay service" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var server: relay_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try server.open(io);
    defer server.close(io);

    var service: relay_service.RelayService = .{};
    defer service.deinit(allocator);

    var host = LiveSession.init(.{
        .server_addr = relay_transport.PeerAddr.loopback(server.boundPort()),
        .bind_host = "127.0.0.1",
        .session = .{
            .role = .host,
            .mode_id = 2,
            .player_count = 2,
            .build_id = "0.1.0",
            .peer_name = "host",
            .input_delay_ticks = 0,
        },
    });
    defer host.deinit(allocator, io);

    const code = try driveRollbackHostUntilRoomCode(allocator, io, server, &service, &host, 1000);

    var guest = LiveSession.init(.{
        .server_addr = relay_transport.PeerAddr.loopback(server.boundPort()),
        .bind_host = "127.0.0.1",
        .session = .{
            .role = .join,
            .mode_id = 2,
            .player_count = 2,
            .build_id = "0.1.0",
            .peer_name = "guest",
            .room_code = code,
            .input_delay_ticks = 0,
        },
    });
    defer guest.deinit(allocator, io);

    try driveRollbackPairUntilStarted(allocator, io, server, &service, &host, &guest, 1020);

    try std.testing.expect(host.session.started);
    try std.testing.expect(guest.session.started);
    try std.testing.expectEqual(@as(i32, 0), host.session.local_slot_index);
    try std.testing.expectEqual(@as(i32, 1), guest.session.local_slot_index);

    try host.queueLocalInput(allocator, io, .{ .flags = 1 }, 1100);
    _ = host.popFrame();
    try guest.queueLocalInput(allocator, io, .{ .flags = 2 }, 1100);
    _ = guest.popFrame();

    _ = try pumpRelayService(allocator, io, server, &service, 1101);
    try host.update(allocator, io, 1102);
    try guest.update(allocator, io, 1102);

    const host_runtime = &(host.session.runtime orelse return error.ExpectedRuntime);
    const guest_runtime = &(guest.session.runtime orelse return error.ExpectedRuntime);
    try std.testing.expectEqual(@as(i32, 1), host_runtime.prediction_mismatches);
    try std.testing.expectEqual(@as(i32, 1), guest_runtime.prediction_mismatches);
    try std.testing.expect(host_runtime.paused_for_resync);
    try std.testing.expect(guest_runtime.paused_for_resync);
}
