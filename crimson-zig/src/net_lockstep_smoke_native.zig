const std = @import("std");

const game_cfg = @import("formats/game_cfg.zig");
const lockstep_live_bridge = @import("net/lockstep_live_bridge.zig");
const lockstep_session = @import("net/lockstep_session.zig");
const lockstep_state = @import("net/lockstep_state.zig");
const live_runner = @import("runtime/live_runner.zig");
const verify_native = @import("verify_native.zig");

const Io = std.Io;

pub const CommandOutput = verify_native.CommandOutput;

const OutputFormat = enum {
    human,
    json,
};

const Request = struct {
    output_format: OutputFormat = .human,
};

const ParseOutcome = union(enum) {
    ok: Request,
    help,
    invalid: []const u8,
};

const SmokePayload = struct {
    schema_version: i32 = 1,
    status: []const u8 = "ok",
    runtime_supported: bool = true,
    player_count: i32 = 2,
    host_port: u16,
    client_port: u16,
    host_received: usize,
    client_received: usize,
    packets_sent: usize,
    tick_index: i32,
    host_input_flags: u32,
    client_input_flags: u32,
    live_ticks_advanced: usize,
    live_tick_index: usize,
};

pub fn runLockstepSmoke(
    allocator: std.mem.Allocator,
    io: Io,
    args: []const []const u8,
) !CommandOutput {
    switch (parseArgs(args)) {
        .ok => |request| {
            const payload = runSmoke(allocator, io) catch |err| return buildFailureOutput(allocator, @errorName(err));
            return buildSmokeOutput(allocator, request.output_format, payload);
        },
        .help => return buildUsageOutput(allocator, 0, ""),
        .invalid => |detail| return buildUsageOutput(allocator, 2, detail),
    }
}

fn runSmoke(allocator: std.mem.Allocator, io: Io) !SmokePayload {
    var status = std.mem.zeroes(game_cfg.Status);
    status.game_sequence_id = 101;

    var host = lockstep_session.HostSession.init(.{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .session_id = "smoke",
        .input_delay_ticks = 0,
        .status = status,
        .pump_options = .{ .first_timeout_ms = 100 },
    });
    try host.open(io);
    defer host.deinit(allocator, io);

    var client = lockstep_session.ClientSession.init(.{
        .bind_host = "127.0.0.1",
        .mode_id = 2,
        .player_count = 2,
        .build_id = "0.1.0",
        .host_addr = lockstep_session.PeerAddr.loopback(host.boundPort()),
        .input_delay_ticks = 0,
        .pump_options = .{ .first_timeout_ms = 100 },
    });
    try client.open(io);
    defer client.deinit(allocator, io);

    var host_received: usize = 0;
    var client_received: usize = 0;
    var packets_sent: usize = 0;

    try client.sendHello(allocator, 10);
    var stats = try client.update(allocator, io, 10);
    client_received += stats.received;
    packets_sent += stats.sent;

    stats = try host.update(allocator, io, 20);
    host_received += stats.received;
    packets_sent += stats.sent;

    stats = try client.update(allocator, io, 30);
    client_received += stats.received;
    packets_sent += stats.sent;

    stats = try host.update(allocator, io, 40);
    host_received += stats.received;
    packets_sent += stats.sent;

    stats = try client.update(allocator, io, 50);
    client_received += stats.received;
    packets_sent += stats.sent;

    if (!host.runtime.started or !client.runtime.started) return error.LockstepHandshakeFailed;

    try client.queueLocalInput(allocator, .{ .flags = 7 }, 60);
    stats = try client.update(allocator, io, 60);
    client_received += stats.received;
    packets_sent += stats.sent;

    try host.submitLocalInput(allocator, .{ .flags = 3 });
    stats = try host.update(allocator, io, 70);
    host_received += stats.received;
    packets_sent += stats.sent;

    var ready_frames = try host.popReadyFrames(allocator, 80);
    defer lockstep_state.deinitHostReadyTicks(allocator, &ready_frames);
    if (ready_frames.items.len != 1) return error.LockstepFrameNotReady;
    const ready = ready_frames.items[0];

    try host.broadcastTickFrame(allocator, .{
        .tick_index = ready.tick_index,
        .frame_inputs = ready.frame_inputs,
        .commands = &.{},
    }, 90);
    stats = try host.update(allocator, io, 90);
    host_received += stats.received;
    packets_sent += stats.sent;

    stats = try client.update(allocator, io, 100);
    client_received += stats.received;
    packets_sent += stats.sent;

    var frame = client.popCanonicalFrame() orelse return error.LockstepCanonicalFrameMissing;
    defer lockstep_state.deinitTickFrame(allocator, &frame);
    if (frame.frame_inputs.len != 2) return error.LockstepCanonicalFrameMismatch;

    const match_start = client.runtime.lobby.match_start orelse return error.LockstepMatchStartMissing;
    var runner = try live_runner.LiveRunner.init(try lockstep_live_bridge.liveConfigFromMatchStart(match_start, .{
        .tick_rate = client.runtime.tick_rate,
        .input_delay_ticks = client.runtime.input_delay_ticks,
    }));
    const live_update = try lockstep_live_bridge.stepCanonicalFrame(&runner, frame);
    if (live_update.ticks_advanced != 1) return error.LockstepLiveFrameNotAdvanced;

    return .{
        .host_port = host.boundPort(),
        .client_port = client.boundPort(),
        .host_received = host_received,
        .client_received = client_received,
        .packets_sent = packets_sent,
        .tick_index = frame.tick_index,
        .host_input_flags = frame.frame_inputs[0].flags,
        .client_input_flags = frame.frame_inputs[1].flags,
        .live_ticks_advanced = live_update.ticks_advanced,
        .live_tick_index = runner.session.tick_index,
    };
}

fn parseArgs(args: []const []const u8) ParseOutcome {
    var request: Request = .{};
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return .help;
        if (takeValue(args, &idx, arg, "--format")) |value| {
            request.output_format = parseOutputFormat(value) orelse return .{ .invalid = "invalid --format value" };
        } else if (std.mem.eql(u8, arg, "--json")) {
            request.output_format = .json;
        } else {
            return .{ .invalid = arg };
        }
    }
    return .{ .ok = request };
}

fn buildSmokeOutput(allocator: std.mem.Allocator, format: OutputFormat, payload: SmokePayload) !CommandOutput {
    const stdout = switch (format) {
        .json => try buildSmokeJson(allocator, payload),
        .human => try buildSmokeHuman(allocator, payload),
    };
    errdefer allocator.free(stdout);
    return .{
        .stdout = stdout,
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = 0,
    };
}

fn buildSmokeJson(allocator: std.mem.Allocator, payload: SmokePayload) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try std.json.Stringify.value(payload, .{ .whitespace = .indent_2 }, &writer.writer);
    try writer.writer.writeByte('\n');
    return writer.toOwnedSlice();
}

fn buildSmokeHuman(allocator: std.mem.Allocator, payload: SmokePayload) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "lockstep smoke ok players={d} host_port={d} client_port={d} tick={d} host_flags={d} client_flags={d} live_ticks={d} packets_sent={d}\n",
        .{
            payload.player_count,
            payload.host_port,
            payload.client_port,
            payload.tick_index,
            payload.host_input_flags,
            payload.client_input_flags,
            payload.live_ticks_advanced,
            payload.packets_sent,
        },
    );
}

fn buildFailureOutput(allocator: std.mem.Allocator, detail: []const u8) !CommandOutput {
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try std.fmt.allocPrint(allocator, "lockstep smoke failed: {s}\n", .{detail}),
        .exit_code = 1,
    };
}

fn buildUsageOutput(allocator: std.mem.Allocator, exit_code: u8, detail: []const u8) !CommandOutput {
    const stdout = try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);
    const stderr = if (detail.len == 0)
        try allocator.dupe(u8, usage)
    else
        try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ detail, usage });
    return .{ .stdout = stdout, .stderr = stderr, .exit_code = exit_code };
}

fn takeValue(args: []const []const u8, idx: *usize, arg: []const u8, flag: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, arg, flag)) {
        idx.* += 1;
        if (idx.* >= args.len) return "";
        return args[idx.*];
    }
    if (std.mem.startsWith(u8, arg, flag) and arg.len > flag.len and arg[flag.len] == '=') {
        return arg[flag.len + 1 ..];
    }
    return null;
}

fn parseOutputFormat(value: []const u8) ?OutputFormat {
    const text = std.mem.trim(u8, value, " \t\r\n");
    if (std.ascii.eqlIgnoreCase(text, "human")) return .human;
    if (std.ascii.eqlIgnoreCase(text, "json")) return .json;
    return null;
}

const usage =
    \\Usage:
    \\  crimson-zig net smoke-lockstep [--format human|json]
    \\
    \\Options:
    \\  --format human|json
    \\
;

test "lockstep smoke command reports json success" {
    const output = try runLockstepSmoke(std.testing.allocator, std.Io.Threaded.global_single_threaded.io(), &.{"--json"});
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"runtime_supported\": true") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"tick_index\": 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"host_input_flags\": 3") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"client_input_flags\": 7") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"live_ticks_advanced\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"live_tick_index\": 1") != null);
}

test "lockstep smoke command reports human success" {
    const output = try runLockstepSmoke(std.testing.allocator, std.Io.Threaded.global_single_threaded.io(), &.{});
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "lockstep smoke ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "host_flags=3") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "client_flags=7") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "live_ticks=1") != null);
}

test "lockstep smoke command validates args" {
    const output = try runLockstepSmoke(std.testing.allocator, std.testing.io, &.{ "--format", "xml" });
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 2), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "invalid --format value") != null);
}
