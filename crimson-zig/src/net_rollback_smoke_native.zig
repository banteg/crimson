const std = @import("std");

const relay_service = @import("net/relay_service.zig");
const relay_protocol = @import("net/relay_protocol.zig");
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

const Impairment = enum {
    none,
    delay_first_guest_input,
    reorder_first_guest_input,
    drop_first_guest_input,
    force_guest_resync,

    fn label(self: Impairment) []const u8 {
        return switch (self) {
            .none => "none",
            .delay_first_guest_input => "delay-first-guest-input",
            .reorder_first_guest_input => "reorder-first-guest-input",
            .drop_first_guest_input => "drop-first-guest-input",
            .force_guest_resync => "force-guest-resync",
        };
    }
};

const Request = struct {
    output_format: OutputFormat = .human,
    impairment: Impairment = .none,
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
    impairment: []const u8,
    packets_sent: usize,
    delayed_packets: usize,
    released_packets: usize,
    dropped_packets: usize,
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
    resync_snapshot_tick: i32,
    host_paused_for_resync: bool,
    guest_paused_for_resync: bool,
    host_rollback_count: i32,
    guest_rollback_count: i32,
    host_prediction_mismatches: i32,
    guest_prediction_mismatches: i32,
};

pub fn runRollbackSmoke(
    allocator: std.mem.Allocator,
    io: Io,
    args: []const []const u8,
) !CommandOutput {
    switch (parseArgs(args)) {
        .ok => |request| {
            const payload = runSmoke(allocator, io, request.impairment) catch |err| return buildFailureOutput(allocator, @errorName(err));
            return buildSmokeOutput(allocator, request.output_format, payload);
        },
        .help => return buildUsageOutput(allocator, 0, ""),
        .invalid => |detail| return buildUsageOutput(allocator, 2, detail),
    }
}

fn runSmoke(allocator: std.mem.Allocator, io: Io, impairment: Impairment) !SmokePayload {
    const force_guest_resync = impairment == .force_guest_resync;
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
            .rollback_max_ticks = if (force_guest_resync) 2 else relay_protocol.rollback_max_ticks,
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

    var packet_impairment: PacketImpairment = .{
        .mode = impairment,
        .target_port = if (force_guest_resync) guest.boundPort() else host.boundPort(),
        .source_slot_index = if (force_guest_resync) host.session.local_slot_index else guest.session.local_slot_index,
    };
    defer packet_impairment.deinit(allocator);

    if (force_guest_resync) {
        return runGuestResyncSmoke(
            allocator,
            io,
            server,
            &service,
            &host,
            &guest,
            code,
            packets_sent,
            &packet_impairment,
        );
    }

    try guest.queueLocalInput(allocator, io, .{ .flags = 7 }, 1200);
    packets_sent += try pumpRelayService(allocator, io, server, &service, 1201, &packet_impairment);
    try host.update(allocator, io, 1202);

    try host.queueLocalInput(allocator, io, .{ .flags = 3 }, 1203);
    var host_step = try host.stepFrames(allocator);
    var expected_host_flags: u32 = 3;
    var expected_guest_flags: u32 = 7;
    var final_exchange_ms: i64 = 1205;
    switch (impairment) {
        .none => {},
        .delay_first_guest_input => {
            if (host_step.last_input_flags[1] != 0) return error.RollbackImpairmentDidNotForcePrediction;
            packets_sent += try packet_impairment.releaseDelayed(allocator, io, server);
            try host.update(allocator, io, 1204);
            host_step = try host.stepFrames(allocator);
        },
        .reorder_first_guest_input, .drop_first_guest_input => {
            if (host_step.last_input_flags[1] != 0) return error.RollbackImpairmentDidNotForcePrediction;
            try guest.queueLocalInput(allocator, io, .{ .flags = 5 }, 1204);
            packets_sent += try pumpRelayService(allocator, io, server, &service, 1205, &packet_impairment);
            if (impairment == .reorder_first_guest_input) {
                packets_sent += try packet_impairment.releaseDelayed(allocator, io, server);
            }
            try host.update(allocator, io, 1206);
            host_step = try host.stepFrames(allocator);
            if (host_step.last_input_flags[1] != 7) return error.RollbackImpairedInputNotRecovered;
            try host.queueLocalInput(allocator, io, .{ .flags = 4 }, 1207);
            host_step = try host.stepFrames(allocator);
            expected_host_flags = 4;
            expected_guest_flags = 5;
            final_exchange_ms = 1208;
        },
        .force_guest_resync => unreachable,
    }
    packets_sent += try pumpRelayService(allocator, io, server, &service, final_exchange_ms, &packet_impairment);
    try guest.update(allocator, io, final_exchange_ms);
    const guest_step = try guest.stepFrames(allocator);

    if (host_step.frames_advanced == 0) return error.RollbackHostFrameMissing;
    if (guest_step.frames_advanced == 0) return error.RollbackGuestFrameMissing;
    if (host_step.last_player_count != 2 or guest_step.last_player_count != 2) return error.RollbackFrameMismatch;
    if (host_step.last_input_flags[0] != expected_host_flags or host_step.last_input_flags[1] != expected_guest_flags) return error.RollbackHostInputMismatch;
    if (guest_step.last_input_flags[0] != expected_host_flags or guest_step.last_input_flags[1] != expected_guest_flags) return error.RollbackGuestInputMismatch;

    const host_runtime = &(host.session.runtime orelse return error.RollbackRuntimeMissing);
    const guest_runtime = &(guest.session.runtime orelse return error.RollbackRuntimeMissing);
    if (host_runtime.paused_for_resync or guest_runtime.paused_for_resync) return error.RollbackUnexpectedResyncPause;
    if (impairment == .delay_first_guest_input or impairment == .reorder_first_guest_input) {
        if (packet_impairment.delayed_packets != 1 or packet_impairment.released_packets != 1) return error.RollbackImpairmentNotApplied;
        if (host_runtime.rollback_count == 0) return error.RollbackHostCorrectionMissing;
    }
    if (impairment == .drop_first_guest_input) {
        if (packet_impairment.dropped_packets != 1 or packet_impairment.delayed_packets != 0 or packet_impairment.released_packets != 0) return error.RollbackImpairmentNotApplied;
        if (host_runtime.rollback_count == 0) return error.RollbackHostCorrectionMissing;
    }

    return .{
        .relay_port = server.boundPort(),
        .host_port = host.boundPort(),
        .guest_port = guest.boundPort(),
        .room_code = code,
        .impairment = impairment.label(),
        .packets_sent = packets_sent,
        .delayed_packets = packet_impairment.delayed_packets,
        .released_packets = packet_impairment.released_packets,
        .dropped_packets = packet_impairment.dropped_packets,
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
        .resync_snapshot_tick = -1,
        .host_paused_for_resync = host_runtime.paused_for_resync,
        .guest_paused_for_resync = guest_runtime.paused_for_resync,
        .host_rollback_count = host_runtime.rollback_count,
        .guest_rollback_count = guest_runtime.rollback_count,
        .host_prediction_mismatches = host_runtime.prediction_mismatches,
        .guest_prediction_mismatches = guest_runtime.prediction_mismatches,
    };
}

fn runGuestResyncSmoke(
    allocator: std.mem.Allocator,
    io: Io,
    server: relay_transport.UdpTransport,
    service: *relay_service.RelayService,
    host: *rollback_live_session.LiveSession,
    guest: *rollback_live_session.LiveSession,
    code: room_code.RoomCode,
    initial_packets_sent: usize,
    packet_impairment: *PacketImpairment,
) !SmokePayload {
    var packets_sent = initial_packets_sent;
    var last_host_step: rollback_live_session.StepSummary = .{};
    var last_guest_step: rollback_live_session.StepSummary = .{};

    for (0..5) |idx| {
        const tick: u32 = @intCast(idx + 1);
        const now_ms: i64 = 1210 + @as(i64, @intCast(idx)) * 10;

        try guest.queueLocalInput(allocator, io, .{ .flags = 100 + tick }, now_ms);
        packets_sent += try pumpRelayService(allocator, io, server, service, now_ms + 1, packet_impairment);
        try host.update(allocator, io, now_ms + 2);

        try host.queueLocalInput(allocator, io, .{ .flags = 10 + tick }, now_ms + 3);
        packets_sent += try pumpRelayService(allocator, io, server, service, now_ms + 4, packet_impairment);
        try guest.update(allocator, io, now_ms + 5);

        last_host_step = try host.stepFrames(allocator);
        last_guest_step = try guest.stepFrames(allocator);
        if (last_host_step.frames_advanced == 0 or last_guest_step.frames_advanced == 0) return error.RollbackFrameMissingBeforeResync;
    }

    if (packet_impairment.delayed_packets != 1 or packet_impairment.dropped_packets == 0) return error.RollbackImpairmentNotApplied;
    packets_sent += try packet_impairment.releaseDelayed(allocator, io, server);
    try guest.update(allocator, io, 1300);
    try guest.update(allocator, io, 1301);

    const guest_runtime = &(guest.session.runtime orelse return error.RollbackRuntimeMissing);
    if (guest_runtime.resync_count != 1 or !guest_runtime.paused_for_resync) return error.RollbackGuestResyncMissing;

    packets_sent += try pumpRelayService(allocator, io, server, service, 1302, null);
    try host.update(allocator, io, 1303);
    packets_sent += try pumpRelayService(allocator, io, server, service, 1304, null);
    try guest.update(allocator, io, 1305);
    _ = try guest.stepFrames(allocator);

    const host_runtime = &(host.session.runtime orelse return error.RollbackRuntimeMissing);
    if (host_runtime.resync_count != 0) return error.RollbackHostRequestedResync;
    if (guest_runtime.paused_for_resync or guest_runtime.pending_resync_snapshot != null) return error.RollbackGuestResyncIncomplete;
    if (guest.runner == null) return error.RollbackRunnerMissing;
    const snapshot_tick: i32 = @intCast(guest.runner.?.session.tick_index -| 1);
    if (snapshot_tick < 4) return error.RollbackSnapshotNotApplied;

    return .{
        .relay_port = server.boundPort(),
        .host_port = host.boundPort(),
        .guest_port = guest.boundPort(),
        .room_code = code,
        .impairment = Impairment.force_guest_resync.label(),
        .packets_sent = packets_sent,
        .delayed_packets = packet_impairment.delayed_packets,
        .released_packets = packet_impairment.released_packets,
        .dropped_packets = packet_impairment.dropped_packets,
        .host_tick_index = last_host_step.last_tick_index orelse return error.RollbackHostFrameMissing,
        .guest_tick_index = last_guest_step.last_tick_index orelse return error.RollbackGuestFrameMissing,
        .host_input_flags = last_guest_step.last_input_flags[0],
        .guest_input_flags = last_guest_step.last_input_flags[1],
        .host_live_ticks_advanced = last_host_step.ticks_advanced,
        .guest_live_ticks_advanced = last_guest_step.ticks_advanced,
        .host_live_tick_index = host.runner.?.session.tick_index,
        .guest_live_tick_index = guest.runner.?.session.tick_index,
        .host_resync_count = host_runtime.resync_count,
        .guest_resync_count = guest_runtime.resync_count,
        .resync_snapshot_tick = snapshot_tick,
        .host_paused_for_resync = host_runtime.paused_for_resync,
        .guest_paused_for_resync = guest_runtime.paused_for_resync,
        .host_rollback_count = host_runtime.rollback_count,
        .guest_rollback_count = guest_runtime.rollback_count,
        .host_prediction_mismatches = host_runtime.prediction_mismatches,
        .guest_prediction_mismatches = guest_runtime.prediction_mismatches,
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
    var sent = try pumpRelayService(allocator, io, server, service, now_ms + 1, null);
    try host.update(allocator, io, now_ms + 2);
    try host.queueLocalInput(allocator, io, .{}, now_ms + 3);
    sent += try pumpRelayService(allocator, io, server, service, now_ms + 4, null);
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
        _ = try pumpRelayService(allocator, io, server, service, now_ms, null);
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
        packets_sent += try pumpRelayService(allocator, io, server, service, now_ms, null);
        try guest.update(allocator, io, now_ms);
        packets_sent += try pumpRelayService(allocator, io, server, service, now_ms, null);
    }
    return error.RollbackRoomStartMissing;
}

fn pumpRelayService(
    allocator: std.mem.Allocator,
    io: Io,
    server: relay_transport.UdpTransport,
    service: *relay_service.RelayService,
    now_ms: i64,
    impairment: ?*PacketImpairment,
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
            if (impairment) |state| {
                if (try state.impairPacket(allocator, item)) continue;
            }
            try server.sendPacket(allocator, io, transportAddrFromService(item.addr), item.packet);
            sent += 1;
        }
    }
    return sent;
}

const PacketImpairment = struct {
    mode: Impairment = .none,
    target_port: u16 = 0,
    source_slot_index: i32 = -1,
    delayed: ?relay_service.AddressedPacket = null,
    delayed_packets: usize = 0,
    released_packets: usize = 0,
    dropped_packets: usize = 0,

    fn deinit(self: *PacketImpairment, allocator: std.mem.Allocator) void {
        if (self.delayed) |*packet| packet.deinit(allocator);
        self.* = undefined;
    }

    fn impairPacket(
        self: *PacketImpairment,
        allocator: std.mem.Allocator,
        packet: relay_service.AddressedPacket,
    ) !bool {
        if (!self.interceptsRollbackInput()) return false;
        if (self.mode != .force_guest_resync and (self.delayed != null or self.interceptedPackets() != 0)) return false;
        if (packet.addr.port != self.target_port) return false;
        switch (packet.packet.message) {
            .rb_input_sample => |batch| {
                if (batch.slot_index != self.source_slot_index) return false;
                if (self.mode == .force_guest_resync and self.released_packets == 0 and self.delayed_packets != 0) {
                    self.dropped_packets += 1;
                    return true;
                }
                if (self.mode == .drop_first_guest_input) {
                    self.dropped_packets += 1;
                    return true;
                }
                self.delayed = .{
                    .addr = packet.addr,
                    .packet = try relay_protocol.clonePacket(allocator, packet.packet),
                };
                self.delayed_packets += 1;
                return true;
            },
            else => return false,
        }
    }

    fn interceptsRollbackInput(self: *const PacketImpairment) bool {
        return self.mode == .delay_first_guest_input or self.mode == .reorder_first_guest_input or self.mode == .drop_first_guest_input or self.mode == .force_guest_resync;
    }

    fn interceptedPackets(self: *const PacketImpairment) usize {
        return self.delayed_packets + self.dropped_packets;
    }

    fn releaseDelayed(
        self: *PacketImpairment,
        allocator: std.mem.Allocator,
        io: Io,
        server: relay_transport.UdpTransport,
    ) !usize {
        var packet = self.delayed orelse return error.RollbackDelayedPacketMissing;
        self.delayed = null;
        defer packet.deinit(allocator);
        try server.sendPacket(allocator, io, transportAddrFromService(packet.addr), packet.packet);
        self.released_packets += 1;
        return 1;
    }
};

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
        } else if (takeValue(args, &idx, arg, "--impair")) |value| {
            request.impairment = parseImpairment(value) orelse return .{ .invalid = "invalid --impair value" };
        } else if (std.mem.eql(u8, arg, "--json")) {
            request.output_format = .json;
        } else if (std.mem.eql(u8, arg, "--delay-first-guest-input")) {
            request.impairment = .delay_first_guest_input;
        } else if (std.mem.eql(u8, arg, "--reorder-first-guest-input")) {
            request.impairment = .reorder_first_guest_input;
        } else if (std.mem.eql(u8, arg, "--drop-first-guest-input")) {
            request.impairment = .drop_first_guest_input;
        } else if (std.mem.eql(u8, arg, "--force-guest-resync")) {
            request.impairment = .force_guest_resync;
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

fn parseImpairment(value: []const u8) ?Impairment {
    const text = std.mem.trim(u8, value, " \t\r\n");
    if (std.ascii.eqlIgnoreCase(text, "none")) return .none;
    if (std.ascii.eqlIgnoreCase(text, "delay-first-guest-input")) return .delay_first_guest_input;
    if (std.ascii.eqlIgnoreCase(text, "reorder-first-guest-input")) return .reorder_first_guest_input;
    if (std.ascii.eqlIgnoreCase(text, "drop-first-guest-input")) return .drop_first_guest_input;
    if (std.ascii.eqlIgnoreCase(text, "force-guest-resync")) return .force_guest_resync;
    return null;
}

const usage =
    \\Usage:
    \\  crimson-zig net smoke-rollback [--format human|json] [--impair none|delay-first-guest-input|reorder-first-guest-input|drop-first-guest-input|force-guest-resync]
    \\
    \\Options:
    \\  --format human|json
    \\  --impair none|delay-first-guest-input|reorder-first-guest-input|drop-first-guest-input|force-guest-resync
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
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"dropped_packets\": 0") != null);
}

test "rollback smoke command can delay guest input and recover" {
    const output = try runRollbackSmoke(std.testing.allocator, std.Io.Threaded.global_single_threaded.io(), &.{ "--json", "--impair", "delay-first-guest-input" });
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"impairment\": \"delay-first-guest-input\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"delayed_packets\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"released_packets\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"dropped_packets\": 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"host_rollback_count\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"host_resync_count\": 0") != null);
}

test "rollback smoke command can reorder guest input and recover" {
    const output = try runRollbackSmoke(std.testing.allocator, std.Io.Threaded.global_single_threaded.io(), &.{ "--json", "--impair", "reorder-first-guest-input" });
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"impairment\": \"reorder-first-guest-input\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"host_input_flags\": 4") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"guest_input_flags\": 5") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"delayed_packets\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"released_packets\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"dropped_packets\": 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"host_rollback_count\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"host_resync_count\": 0") != null);
}

test "rollback smoke command can drop guest input and recover from resend history" {
    const output = try runRollbackSmoke(std.testing.allocator, std.Io.Threaded.global_single_threaded.io(), &.{ "--json", "--impair", "drop-first-guest-input" });
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"impairment\": \"drop-first-guest-input\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"host_input_flags\": 4") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"guest_input_flags\": 5") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"delayed_packets\": 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"released_packets\": 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"dropped_packets\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"host_rollback_count\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"host_resync_count\": 0") != null);
}

test "rollback smoke command can force guest resync and apply host snapshot" {
    const output = try runRollbackSmoke(std.testing.allocator, std.Io.Threaded.global_single_threaded.io(), &.{ "--json", "--impair", "force-guest-resync" });
    defer output.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"impairment\": \"force-guest-resync\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"delayed_packets\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"released_packets\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"guest_resync_count\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"resync_snapshot_tick\": 4") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"guest_paused_for_resync\": false") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "\"guest_prediction_mismatches\": 1") != null);
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
