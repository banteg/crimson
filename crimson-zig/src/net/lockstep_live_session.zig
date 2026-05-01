const std = @import("std");

const live_runner = @import("../runtime/live_runner.zig");
const lockstep_live_bridge = @import("lockstep_live_bridge.zig");
const lockstep_protocol = @import("lockstep_protocol.zig");
const lockstep_session = @import("lockstep_session.zig");
const lockstep_state = @import("lockstep_state.zig");
const packed_input = @import("packed_input.zig");

const Io = std.Io;

pub const HostLiveSessionError = lockstep_live_bridge.BridgeError || live_runner.LiveRunnerError;
pub const ClientLiveSessionError = lockstep_live_bridge.BridgeError || live_runner.LiveRunnerError;
pub const ClientLiveStepError = lockstep_live_bridge.StepCanonicalFrameError || error{MatchNotStarted};

pub const HostStepSummary = struct {
    frames_advanced: usize = 0,
    ticks_advanced: usize = 0,
    last_update: ?live_runner.FrameUpdate = null,
};

pub const ClientStepSummary = struct {
    frames_advanced: usize = 0,
    ticks_advanced: usize = 0,
    last_update: ?live_runner.FrameUpdate = null,
};

pub const HostLiveSession = struct {
    session: lockstep_session.HostSession,
    runner: live_runner.LiveRunner,

    pub fn init(options: lockstep_session.HostSessionOptions) HostLiveSessionError!HostLiveSession {
        const session = lockstep_session.HostSession.init(options);
        return .{
            .session = session,
            .runner = try live_runner.LiveRunner.init(try lockstep_live_bridge.liveConfigFromHostRuntime(session.runtime)),
        };
    }

    pub fn deinit(self: *HostLiveSession, allocator: std.mem.Allocator, io: Io) void {
        self.session.deinit(allocator, io);
        self.* = undefined;
    }

    pub fn open(self: *HostLiveSession, io: Io) !void {
        try self.session.open(io);
    }

    pub fn close(self: *HostLiveSession, io: Io) void {
        self.session.close(io);
    }

    pub fn update(self: *HostLiveSession, allocator: std.mem.Allocator, io: Io, now_ms: i64) !lockstep_session.UpdateStats {
        return self.session.update(allocator, io, now_ms);
    }

    pub fn submitLocalInput(self: *HostLiveSession, allocator: std.mem.Allocator, input: packed_input.PackedPlayerInput) !void {
        try self.session.submitLocalInput(allocator, input);
    }

    pub fn stepReadyFrames(self: *HostLiveSession, allocator: std.mem.Allocator, now_ms: i64) !HostStepSummary {
        var ready_frames = try self.session.popReadyFrames(allocator, now_ms);
        defer lockstep_state.deinitHostReadyTicks(allocator, &ready_frames);

        var summary: HostStepSummary = .{};
        for (ready_frames.items) |ready| {
            const update_result = try lockstep_live_bridge.stepHostReadyTick(&self.runner, ready);
            summary.frames_advanced += 1;
            summary.ticks_advanced += update_result.ticks_advanced;
            summary.last_update = update_result;
            try self.session.broadcastTickFrame(allocator, .{
                .tick_index = ready.tick_index,
                .frame_inputs = ready.frame_inputs,
                .commands = &.{},
            }, now_ms);
        }
        return summary;
    }
};

pub const ClientLiveSession = struct {
    session: lockstep_session.ClientSession,
    runner: ?live_runner.LiveRunner = null,

    pub fn init(options: lockstep_session.ClientSessionOptions) ClientLiveSession {
        return .{
            .session = lockstep_session.ClientSession.init(options),
        };
    }

    pub fn deinit(self: *ClientLiveSession, allocator: std.mem.Allocator, io: Io) void {
        self.session.deinit(allocator, io);
        self.* = undefined;
    }

    pub fn open(self: *ClientLiveSession, io: Io) !void {
        try self.session.open(io);
    }

    pub fn close(self: *ClientLiveSession, io: Io) void {
        self.session.close(io);
    }

    pub fn update(self: *ClientLiveSession, allocator: std.mem.Allocator, io: Io, now_ms: i64) !lockstep_session.UpdateStats {
        return self.session.update(allocator, io, now_ms);
    }

    pub fn sendHello(self: *ClientLiveSession, allocator: std.mem.Allocator, now_ms: i64) !void {
        try self.session.sendHello(allocator, now_ms);
    }

    pub fn queueLocalInput(
        self: *ClientLiveSession,
        allocator: std.mem.Allocator,
        input: packed_input.PackedPlayerInput,
        now_ms: i64,
    ) !void {
        try self.session.queueLocalInput(allocator, input, now_ms);
    }

    pub fn ensureLiveRunner(self: *ClientLiveSession) ClientLiveSessionError!bool {
        if (self.runner != null) return false;
        const config = try (lockstep_live_bridge.liveConfigFromClientRuntime(self.session.runtime) orelse return false);
        self.runner = try live_runner.LiveRunner.init(config);
        return true;
    }

    pub fn stepCanonicalFrames(self: *ClientLiveSession, allocator: std.mem.Allocator) ClientLiveStepError!ClientStepSummary {
        if (self.runner == null) return error.MatchNotStarted;

        var summary: ClientStepSummary = .{};
        while (self.session.popCanonicalFrame()) |frame_value| {
            var frame = frame_value;
            defer lockstep_state.deinitTickFrame(allocator, &frame);
            const update_result = try lockstep_live_bridge.stepCanonicalFrame(&self.runner.?, frame);
            summary.frames_advanced += 1;
            summary.ticks_advanced += update_result.ticks_advanced;
            summary.last_update = update_result;
        }
        return summary;
    }
};

test "host live session starts live runner from host settings" {
    var host = try HostLiveSession.init(.{
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .session_id = "session",
        .seed = 1234,
        .input_delay_ticks = 0,
    });
    defer host.deinit(std.testing.allocator, std.Io.Threaded.global_single_threaded.io());

    try std.testing.expectEqual(@as(u32, 1234), host.runner.seed);
    try std.testing.expectEqual(@as(usize, 2), host.runner.session.players().len);
}

test "client live session creates runner after match start" {
    var client = ClientLiveSession.init(.{
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .host_addr = lockstep_session.PeerAddr.loopback(lockstep_protocol.default_port),
        .input_delay_ticks = 0,
    });
    defer {
        client.session.runtime.lobby.match_start = null;
        client.deinit(std.testing.allocator, std.Io.Threaded.global_single_threaded.io());
    }

    try std.testing.expect(!try client.ensureLiveRunner());
    client.session.runtime.lobby.ingestMatchStart(.{
        .session_id = "session",
        .mode_id = 2,
        .player_count = 2,
        .seed = 4321,
    });

    try std.testing.expect(try client.ensureLiveRunner());
    try std.testing.expect(!try client.ensureLiveRunner());
    try std.testing.expectEqual(@as(u32, 4321), client.runner.?.seed);
}
