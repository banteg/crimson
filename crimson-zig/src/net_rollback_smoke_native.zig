const std = @import("std");

const relay_service = @import("net/relay_service.zig");
const relay_transport = @import("net/relay_transport.zig");
const rollback_live_session = @import("net/rollback_live_session.zig");
const room_code = @import("net/room_code.zig");
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
    relay_port: u16,
    host_port: u16,
    guest_port: u16,
    room_code: room_code.RoomCode,
    packets_sent: usize,
    host_tick_index: i32,
    guest_tick_index: i32,
    host_input_flags: u32,
    guest_input_flags: u32,
    host_live_ticks_advanced: usize,
    guest_live_ticks_advanced: usize,
    host_live_tick_index: usize,
    guest_live_tick_index: usize,
    host_resync_count: i32,
    guest_resync_count: i32,
    guest_rollback_count: i32,
};

pub fn runRollbackSmoke(
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
    var server: relay_transport.UdpTransport = .{ .bind_host = "127.0.0.1", .bind_port = 0 };
    try server.open(io);
    defer server.close(io);

    var service: relay_service.RelayService = .{};
    defer service.deinit(allocator);

    var host = rollback_live_session.LiveSession.init(.{
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

    const code = try driveHostUntilRoomCode(allocator, io, server, &service, &host, 1000);

    var guest = rollback_live_session.LiveSession.init(.{
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

    var packets_sent = try drivePairUntilStarted(allocator, io, server, &service, &host, &guest, 1020);
    if (!host.session.started or !guest.session.started) return error.RollbackHandshakeFailed;
    if (!host.session.hostRemoteInputsReady()) {
        packets_sent += try exchangeNeutralStartupTick(allocator, io, server, &service, &host, &guest, 1100);
    }
    if (!host.session.hostRemoteInputsReady()) return error.RollbackHostNotReady;

    try guest.queueLocalInput(allocator, io, .{ .flags = 7 }, 1200);
    packets_sent += try pumpRelayService(allocator, io, server, &service, 1201);
    try host.update(allocator, io, 1202);

    try host.queueLocalInput(allocator, io, .{ .flags = 3 }, 1203);
    const host_step = try host.stepFrames(allocator);
    packets_sent += try pumpRelayService(allocator, io, server, &service, 1204);
    try guest.update(allocator, io, 1205);
    const guest_step = try guest.stepFrames(allocator);

    if (host_step.frames_advanced == 0) return error.RollbackHostFrameMissing;
    if (guest_step.frames_advanced == 0) return error.RollbackGuestFrameMissing;
    if (host_step.last_player_count != 2 or guest_step.last_player_count != 2) return error.RollbackFrameMismatch;
    if (host_step.last_input_flags[0] != 3 or host_step.last_input_flags[1] != 7) return error.RollbackHostInputMismatch;
    if (guest_step.last_input_flags[0] != 3 or guest_step.last_input_flags[1] != 7) return error.RollbackGuestInputMismatch;

    const host_runtime = &(host.session.runtime orelse return error.RollbackRuntimeMissing);
    const guest_runtime = &(guest.session.runtime orelse return error.RollbackRuntimeMissing);
    if (host_runtime.paused_for_resync or guest_runtime.paused_for_resync) return error.RollbackUnexpectedResyncPause;

    return .{
        .relay_port = server.boundPort(),
        .host_port = host.boundPort(),
        .guest_port = guest.boundPort(),
        .room_code = code,
        .packets_sent = packets_sent,
        .host_tick_index = host_step.last_tick_index orelse return error.RollbackHostFrameMissing,
        .guest_tick_index = guest_step.last_tick_index orelse return error.RollbackGuestFrameMissing,
        .host_input_flags = guest_step.last_input_flags[0],
        .guest_input_flags = guest_step.last_input_flags[1],
        .host_live_ticks_advanced = host_step.ticks_advanced,
        .guest_live_ticks_advanced = guest_step.ticks_advanced,
        .host_live_tick_index = host.runner.?.session.tick_index,
        .guest_live_tick_index = guest.runner.?.session.tick_index,
        .host_resync_count = host_runtime.resync_count,
        .guest_resync_count = guest_runtime.resync_count,
        .guest_rollback_count = guest_runtime.rollback_count,
    };
}

fn exchangeNeutralStartupTick(
    allocator: std.mem.Allocator,
    io: Io,
    server: relay_transport.UdpTransport,
    service: *relay_service.RelayService,
    host: *rollback_live_session.LiveSession,
    guest: *rollback_live_session.LiveSession,
    now_ms: i64,
) !usize {
    try guest.queueLocalInput(allocator, io, .{}, now_ms);
    var sent = try pumpRelayService(allocator, io, server, service, now_ms + 1);
    try host.update(allocator, io, now_ms + 2);
    try host.queueLocalInput(allocator, io, .{}, now_ms + 3);
    sent += try pumpRelayService(allocator, io, server, service, now_ms + 4);
    try guest.update(allocator, io, now_ms + 5);
    const host_step = try host.stepFrames(allocator);
    const guest_step = try guest.stepFrames(allocator);
    if (host_step.frames_advanced == 0 or guest_step.frames_advanced == 0) return error.RollbackInitialFrameMissing;
    return sent;
}

fn driveHostUntilRoomCode(
    allocator: std.mem.Allocator,
    io: Io,
    server: relay_transport.UdpTransport,
    service: *relay_service.RelayService,
    host: *rollback_live_session.LiveSession,
    start_ms: i64,
) !room_code.RoomCode {
    for (0..16) |step| {
        const now_ms = start_ms + @as(i64, @intCast(step));
        try host.update(allocator, io, now_ms);
        _ = try pumpRelayService(allocator, io, server, service, now_ms);
        if (host.session.room_code_latest) |code| return code;
    }
    return error.RollbackRoomCodeMissing;
}

fn drivePairUntilStarted(
    allocator: std.mem.Allocator,
    io: Io,
    server: relay_transport.UdpTransport,
    service: *relay_service.RelayService,
    host: *rollback_live_session.LiveSession,
    guest: *rollback_live_session.LiveSession,
    start_ms: i64,
) !usize {
    var packets_sent: usize = 0;
    for (0..32) |step| {
        if (host.session.started and guest.session.started) return packets_sent;
        const now_ms = start_ms + @as(i64, @intCast(step));
        try host.update(allocator, io, now_ms);
        packets_sent += try pumpRelayService(allocator, io, server, service, now_ms);
        try guest.update(allocator, io, now_ms);
        packets_sent += try pumpRelayService(allocator, io, server, service, now_ms);
    }
    return error.RollbackRoomStartMissing;
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

fn serviceAddrFromTransport(addr: relay_transport.PeerAddr) relay_service.PeerAddr {
    return .{ .host = addr.host, .port = addr.port };
}

fn transportAddrFromService(addr: relay_service.PeerAddr) relay_transport.PeerAddr {
    return .{ .host = addr.host, .port = addr.port };
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
        "rollback smoke ok players={d} relay_port={d} room={s} tick={d} host_flags={d} guest_flags={d} host_live_ticks={d} guest_live_ticks={d} packets_sent={d}\n",
        .{
            payload.player_count,
            payload.relay_port,
            room_code.roomCodeSlice(&payload.room_code),
            payload.guest_tick_index,
            payload.host_input_flags,
            payload.guest_input_flags,
            payload.host_live_ticks_advanced,
            payload.guest_live_ticks_advanced,
            payload.packets_sent,
        },
    );
}

fn buildFailureOutput(allocator: std.mem.Allocator, detail: []const u8) !CommandOutput {
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try std.fmt.allocPrint(allocator, "rollback smoke failed: {s}\n", .{detail}),
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
    \\  crimson-zig net smoke-rollback [--format human|json]
    \\
    \\Options:
    \\  --format human|json
    \\
;

test "rollback smoke command reports json success" {
    const output = try runRollbackSmoke(std.testing.allocator, std.Io.Threaded.global_single_threaded.io(), &.{"--json"});
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"runtime_supported\": true") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"host_input_flags\": 3") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"guest_input_flags\": 7") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"host_resync_count\": 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"guest_resync_count\": 0") != null);
}

test "rollback smoke command reports human success" {
    const output = try runRollbackSmoke(std.testing.allocator, std.Io.Threaded.global_single_threaded.io(), &.{});
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "rollback smoke ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "host_flags=3") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "guest_flags=7") != null);
}

test "rollback smoke command validates args" {
    const output = try runRollbackSmoke(std.testing.allocator, std.testing.io, &.{ "--format", "xml" });
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 2), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "invalid --format value") != null);
}
