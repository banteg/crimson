const std = @import("std");

const game_cfg = @import("../formats/game_cfg.zig");
const lockstep_client_runtime = @import("lockstep_client_runtime.zig");
const lockstep_host_runtime = @import("lockstep_host_runtime.zig");
const lockstep_outbox = @import("lockstep_outbox.zig");
const lockstep_protocol = @import("lockstep_protocol.zig");
const lockstep_pump = @import("lockstep_pump.zig");
const lockstep_state = @import("lockstep_state.zig");
const lockstep_transport = @import("lockstep_transport.zig");
const packed_input = @import("packed_input.zig");
const quest_level = @import("../quest_level.zig");

const Io = std.Io;

pub const PeerAddr = lockstep_transport.PeerAddr;

pub const UpdateStats = struct {
    received: usize = 0,
    sent: usize = 0,
};

pub const HostSessionOptions = struct {
    bind_host: []const u8 = "0.0.0.0",
    bind_port: u16 = lockstep_protocol.default_port,
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
    pump_options: lockstep_pump.PumpOptions = .{},
};

pub const ClientSessionOptions = struct {
    bind_host: []const u8 = "0.0.0.0",
    bind_port: u16 = 0,
    mode_id: i32,
    player_count: i32,
    build_id: []const u8,
    host_addr: PeerAddr,
    tick_rate: i32 = lockstep_protocol.tick_rate,
    input_delay_ticks: i32 = lockstep_protocol.input_delay_ticks,
    quest_level: ?quest_level.QuestLevel = null,
    preserve_bugs: bool = false,
    pump_options: lockstep_pump.PumpOptions = .{},
};

pub const HostSession = struct {
    transport: lockstep_transport.UdpTransport,
    runtime: lockstep_host_runtime.HostRuntime,
    outbox: lockstep_outbox.Outbox = .{},
    pump_options: lockstep_pump.PumpOptions = .{},

    pub fn init(options: HostSessionOptions) HostSession {
        return .{
            .transport = .{
                .bind_host = options.bind_host,
                .bind_port = options.bind_port,
            },
            .runtime = lockstep_host_runtime.HostRuntime.init(.{
                .mode_id = options.mode_id,
                .player_count = options.player_count,
                .build_id = options.build_id,
                .session_id = options.session_id,
                .tick_rate = options.tick_rate,
                .input_delay_ticks = options.input_delay_ticks,
                .quest_level = options.quest_level,
                .preserve_bugs = options.preserve_bugs,
                .seed = options.seed,
                .start_tick = options.start_tick,
                .status = options.status,
                .host_ready = options.host_ready,
            }),
            .pump_options = options.pump_options,
        };
    }

    pub fn deinit(self: *HostSession, allocator: std.mem.Allocator, io: Io) void {
        self.transport.close(io);
        self.outbox.deinit(allocator);
        self.runtime.deinit(allocator);
        self.* = undefined;
    }

    pub fn open(self: *HostSession, io: Io) !void {
        try self.transport.open(io);
    }

    pub fn close(self: *HostSession, io: Io) void {
        self.transport.close(io);
    }

    pub fn boundPort(self: HostSession) u16 {
        return self.transport.boundPort();
    }

    pub fn update(self: *HostSession, allocator: std.mem.Allocator, io: Io, now_ms: i64) !UpdateStats {
        const received = try lockstep_pump.drainHost(
            allocator,
            io,
            self.transport,
            &self.runtime,
            now_ms,
            &self.outbox,
            self.pump_options,
        );
        try self.runtime.pollResends(allocator, now_ms, &self.outbox);
        const sent = try lockstep_pump.flushOutbox(allocator, io, self.transport, &self.outbox);
        return .{ .received = received, .sent = sent };
    }

    pub fn submitLocalInput(
        self: *HostSession,
        allocator: std.mem.Allocator,
        input: packed_input.PackedPlayerInput,
    ) !void {
        try self.runtime.submitLocalInput(allocator, input);
    }

    pub fn popReadyFrames(
        self: *HostSession,
        allocator: std.mem.Allocator,
        now_ms: i64,
    ) !std.ArrayList(lockstep_state.HostReadyTick) {
        return self.runtime.popReadyFrames(allocator, now_ms);
    }

    pub fn broadcastTickFrame(
        self: *HostSession,
        allocator: std.mem.Allocator,
        frame: lockstep_protocol.TickFrame,
        now_ms: i64,
    ) !void {
        try self.runtime.broadcastTickFrame(allocator, frame, now_ms, &self.outbox);
    }
};

pub const ClientSession = struct {
    transport: lockstep_transport.UdpTransport,
    runtime: lockstep_client_runtime.ClientRuntime,
    outbox: lockstep_outbox.Outbox = .{},
    pump_options: lockstep_pump.PumpOptions = .{},

    pub fn init(options: ClientSessionOptions) ClientSession {
        return .{
            .transport = .{
                .bind_host = options.bind_host,
                .bind_port = options.bind_port,
            },
            .runtime = lockstep_client_runtime.ClientRuntime.init(.{
                .mode_id = options.mode_id,
                .player_count = options.player_count,
                .build_id = options.build_id,
                .host_addr = options.host_addr,
                .tick_rate = options.tick_rate,
                .input_delay_ticks = options.input_delay_ticks,
                .quest_level = options.quest_level,
                .preserve_bugs = options.preserve_bugs,
            }),
            .pump_options = options.pump_options,
        };
    }

    pub fn deinit(self: *ClientSession, allocator: std.mem.Allocator, io: Io) void {
        self.transport.close(io);
        self.outbox.deinit(allocator);
        self.runtime.deinit(allocator);
        self.* = undefined;
    }

    pub fn open(self: *ClientSession, io: Io) !void {
        try self.transport.open(io);
    }

    pub fn close(self: *ClientSession, io: Io) void {
        self.transport.close(io);
    }

    pub fn boundPort(self: ClientSession) u16 {
        return self.transport.boundPort();
    }

    pub fn update(self: *ClientSession, allocator: std.mem.Allocator, io: Io, now_ms: i64) !UpdateStats {
        const received = try lockstep_pump.drainClient(
            allocator,
            io,
            self.transport,
            &self.runtime,
            now_ms,
            &self.outbox,
            self.pump_options,
        );
        try self.runtime.pollResends(allocator, now_ms, &self.outbox);
        const sent = try lockstep_pump.flushOutbox(allocator, io, self.transport, &self.outbox);
        return .{ .received = received, .sent = sent };
    }

    pub fn sendHello(self: *ClientSession, allocator: std.mem.Allocator, now_ms: i64) !void {
        try self.runtime.sendHello(allocator, now_ms, &self.outbox);
    }

    pub fn queueLocalInput(
        self: *ClientSession,
        allocator: std.mem.Allocator,
        input: packed_input.PackedPlayerInput,
        now_ms: i64,
    ) !void {
        try self.runtime.queueLocalInput(allocator, input, now_ms, &self.outbox);
    }

    pub fn popCanonicalFrame(self: *ClientSession) ?lockstep_protocol.TickFrame {
        return self.runtime.popCanonicalFrame();
    }
};

test "lockstep sessions handshake over udp" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var status = std.mem.zeroes(game_cfg.Status);
    status.game_sequence_id = 42;
    var host = HostSession.init(.{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .session_id = "session",
        .input_delay_ticks = 0,
        .status = status,
        .pump_options = .{ .first_timeout_ms = 100 },
    });
    try host.open(io);
    defer host.deinit(allocator, io);

    var client = ClientSession.init(.{
        .bind_host = "127.0.0.1",
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .host_addr = PeerAddr.loopback(host.boundPort()),
        .input_delay_ticks = 0,
        .pump_options = .{ .first_timeout_ms = 100 },
    });
    try client.open(io);
    defer client.deinit(allocator, io);

    try client.sendHello(allocator, 10);
    try std.testing.expectEqual(@as(usize, 1), (try client.update(allocator, io, 10)).sent);

    const host_hello = try host.update(allocator, io, 20);
    try std.testing.expectEqual(@as(usize, 1), host_hello.received);
    try std.testing.expect(host_hello.sent >= 2);
    try std.testing.expectEqual(@as(usize, 1), host.runtime.peerCount());

    const client_welcome = try client.update(allocator, io, 30);
    try std.testing.expect(client_welcome.received >= 2);
    try std.testing.expectEqual(@as(usize, 1), client_welcome.sent);
    try std.testing.expect(client.runtime.lobby.joined());

    const host_ready = try host.update(allocator, io, 40);
    try std.testing.expectEqual(@as(usize, 1), host_ready.received);
    try std.testing.expect(host.runtime.started);
    try std.testing.expect(host_ready.sent >= 1);

    const client_start = try client.update(allocator, io, 50);
    try std.testing.expect(client_start.received >= 1);
    try std.testing.expect(client.runtime.started);
    try std.testing.expect(client.runtime.lockstep != null);
}

test "lockstep sessions exchange input and canonical tick frame" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var status = std.mem.zeroes(game_cfg.Status);
    status.game_sequence_id = 43;
    var host = HostSession.init(.{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .session_id = "session",
        .input_delay_ticks = 0,
        .status = status,
        .pump_options = .{ .first_timeout_ms = 100 },
    });
    try host.open(io);
    defer host.deinit(allocator, io);

    var client = ClientSession.init(.{
        .bind_host = "127.0.0.1",
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .host_addr = PeerAddr.loopback(host.boundPort()),
        .input_delay_ticks = 0,
        .pump_options = .{ .first_timeout_ms = 100 },
    });
    try client.open(io);
    defer client.deinit(allocator, io);

    try startSession(allocator, io, &host, &client);

    try client.queueLocalInput(allocator, .{ .flags = 7 }, 60);
    try std.testing.expectEqual(@as(usize, 1), (try client.update(allocator, io, 60)).sent);
    try host.submitLocalInput(allocator, .{ .flags = 3 });
    try std.testing.expectEqual(@as(usize, 1), (try host.update(allocator, io, 70)).received);

    var ready_frames = try host.popReadyFrames(allocator, 80);
    defer lockstep_state.deinitHostReadyTicks(allocator, &ready_frames);
    try std.testing.expectEqual(@as(usize, 1), ready_frames.items.len);
    const ready = ready_frames.items[0];
    try std.testing.expectEqual(@as(i32, 0), ready.tick_index);
    try std.testing.expectEqual(@as(u32, 3), ready.frame_inputs[0].flags);
    try std.testing.expectEqual(@as(u32, 7), ready.frame_inputs[1].flags);

    try host.broadcastTickFrame(allocator, .{
        .tick_index = ready.tick_index,
        .frame_inputs = ready.frame_inputs,
        .commands = &.{},
    }, 90);
    try std.testing.expectEqual(@as(usize, 1), (try host.update(allocator, io, 90)).sent);

    try std.testing.expect((try client.update(allocator, io, 100)).received >= 1);
    var frame = client.popCanonicalFrame() orelse return error.TestExpectedEqual;
    defer lockstep_state.deinitTickFrame(allocator, &frame);
    try std.testing.expectEqual(@as(i32, 0), frame.tick_index);
    try std.testing.expectEqual(@as(usize, 2), frame.frame_inputs.len);
    try std.testing.expectEqual(@as(u32, 3), frame.frame_inputs[0].flags);
    try std.testing.expectEqual(@as(u32, 7), frame.frame_inputs[1].flags);
}

fn startSession(
    allocator: std.mem.Allocator,
    io: Io,
    host: *HostSession,
    client: *ClientSession,
) !void {
    try client.sendHello(allocator, 10);
    _ = try client.update(allocator, io, 10);
    _ = try host.update(allocator, io, 20);
    _ = try client.update(allocator, io, 30);
    _ = try host.update(allocator, io, 40);
    _ = try client.update(allocator, io, 50);
    try std.testing.expect(host.runtime.started);
    try std.testing.expect(client.runtime.started);
}
