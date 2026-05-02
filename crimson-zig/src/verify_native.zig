const builtin = @import("builtin");
const std = @import("std");

const cdt_trace = @import("cdt_trace.zig");
const replay_codec = @import("replay_codec.zig");
const replay_runner = @import("runtime/replay_runner.zig");
const runtime_paths = @import("runtime_paths.zig");

const replay_schema_version: i32 = 2;

pub const CommandOutput = struct {
    stdout: []u8,
    stderr: []u8,
    exit_code: u8,

    pub fn deinit(self: CommandOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

const OutputFormat = enum {
    human,
    json,
};

const VerifyRequest = struct {
    replay_file: []const u8,
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
    base_dir: ?[]const u8 = null,
    max_ticks: ?usize = null,
    trace_rng: bool = false,
    debug_trace_cdt: ?[]const u8 = null,
};

const ReplayRunnerProgressHint = struct {
    processed_ticks: ?usize = null,
    total_ticks: usize = 0,
    event_count: usize = 0,
};

const ParseOutcome = union(enum) {
    ok: VerifyRequest,
    invalid: []const u8,
};

const ReplayResolution = struct {
    resolved_path: []u8,
    tried_primary: []u8,
    tried_secondary: ?[]u8,
    exists: bool,

    fn deinit(self: ReplayResolution, allocator: std.mem.Allocator) void {
        allocator.free(self.resolved_path);
        allocator.free(self.tried_primary);
        if (self.tried_secondary) |secondary| allocator.free(secondary);
    }
};

const RunResult = struct {
    game_mode_id: i32,
    tick_rate: i32,
    ticks: i32,
    elapsed_ms: i64,
    score_xp: i64,
    creature_kill_count: i32,
    most_used_weapon_id: i32,
    shots_fired: i32,
    shots_hit: i32,
    rng_state: u64,
};

const ClaimedStatsPayload = struct {
    complete: bool,
    ticks: i32,
    elapsed_ms: i64,
    score_xp: i64,
    kills: i32,
    most_used_weapon_id: i32,
    shots_fired: i32,
    shots_hit: i32,
};

const HeaderClaimPayload = struct {
    expected: ClaimedStatsPayload,
    simulated: ClaimedStatsPayload,
    match: bool,
    mismatched_fields: []const []const u8,
};

const VerifyPayload = struct {
    schema_version: i32,
    status: []const u8,
    replay: []const u8,
    run_result: RunResult,
    header_claim: ?HeaderClaimPayload,
    score_claim: ?struct {},
};

pub fn runReplayVerify(
    allocator: std.mem.Allocator,
    verify_args: []const []const u8,
) !CommandOutput {
    switch (parseNativeSubset(verify_args)) {
        .ok => |request| return runNativeVerify(allocator, request),
        .invalid => |detail| return buildInvalidVerifyArgsOutput(allocator, detail),
    }
}

pub fn runReplayVerifyBytesJson(
    allocator: std.mem.Allocator,
    replay_name: []const u8,
    replay_bytes: []const u8,
    max_ticks: ?usize,
) !CommandOutput {
    return runVerifyWithReplayBytes(allocator, .{
        .replay_file = replay_name,
        .output_format = .json,
        .max_ticks = max_ticks,
    }, replay_name, replay_bytes);
}

fn runNativeVerify(
    allocator: std.mem.Allocator,
    request: VerifyRequest,
) !CommandOutput {
    if (builtin.os.tag == .freestanding) {
        return buildVerifyFailedOutput(allocator, "native file replay verify is unavailable on freestanding targets");
    }

    var default_base_dir: ?[]u8 = null;
    defer if (default_base_dir) |path| allocator.free(path);

    const base_dir = if (request.base_dir) |value|
        value
    else blk: {
        const resolved = try defaultRuntimeDir(allocator);
        default_base_dir = resolved;
        break :blk resolved;
    };

    const resolution = resolveReplayPath(allocator, request.replay_file, base_dir) catch |err| {
        return buildVerifyFailedOutput(allocator, verifySetupErrorDetail(err));
    };
    defer resolution.deinit(allocator);

    if (!resolution.exists) {
        return buildReplayNotFoundOutput(allocator, resolution);
    }

    if (!std.mem.endsWith(u8, resolution.resolved_path, ".crd")) {
        return buildVerifyFailedOutput(allocator, "replay file must use .crd extension");
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    const replay_bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        resolution.resolved_path,
        allocator,
        .limited(replay_codec.max_replay_payload_bytes),
    ) catch |err| {
        return buildVerifyFailedOutput(allocator, verifyReplayReadErrorDetail(err));
    };
    defer allocator.free(replay_bytes);

    return runVerifyWithReplayBytes(allocator, request, resolution.resolved_path, replay_bytes);
}

fn runVerifyWithReplayBytes(
    allocator: std.mem.Allocator,
    request: VerifyRequest,
    replay_path: []const u8,
    replay_bytes: []const u8,
) !CommandOutput {
    var replay_payload_alloc: ?[]u8 = null;
    defer if (replay_payload_alloc) |buf| allocator.free(buf);

    const replay_payload: []const u8 = if (replay_codec.isZstdPayload(replay_bytes)) blk: {
        const inflated = replay_codec.inflateZstdPayload(
            allocator,
            replay_bytes,
            replay_codec.max_replay_payload_bytes,
        ) catch |err| {
            return buildOutputForReplayCodecError(allocator, err);
        };
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else if (replay_codec.isGzipPayload(replay_bytes)) blk: {
        const inflated = replay_codec.inflateGzipPayload(
            allocator,
            replay_bytes,
            replay_codec.max_replay_payload_bytes,
        ) catch |err| {
            return buildOutputForReplayCodecError(allocator, err);
        };
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else replay_bytes;

    var replay = replay_codec.parseReplay(allocator, replay_payload) catch |err| {
        return buildOutputForReplayCodecError(allocator, err);
    };
    defer replay.deinit(allocator);
    const header = replay.header;

    if (replay_codec.unsupportedReplayHeaderDetail(header, replay.tickCount(), .verifier)) |detail| {
        return buildVerifyFailedOutput(allocator, detail);
    }
    replay_codec.validateReplayBootstrap(header) catch |err| {
        return buildOutputForReplayCodecError(allocator, err);
    };
    if (try replay_codec.replayEventOrderingFailureDetail(allocator, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildVerifyFailedOutput(allocator, detail);
    }
    if (try replay_codec.replayEventPlayerIndexFailureDetail(allocator, header.player_count, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildVerifyFailedOutput(allocator, detail);
    }
    if (try replay_codec.replayEventKindFailureDetail(allocator, header.game_mode_id, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildVerifyFailedOutput(allocator, detail);
    }
    const trace_requested = request.trace_rng or request.debug_trace_cdt != null;
    const ticks_to_simulate: usize = if (request.max_ticks) |max_ticks|
        @min(max_ticks, replay.tickCount())
    else
        replay.tickCount();
    const full_replay_simulated = ticks_to_simulate == replay.tickCount();
    var tick_trace: std.ArrayList(replay_runner.ReplayTickTrace) = .empty;
    defer if (trace_requested) {
        replay_runner.deinitReplayTickTraceRows(allocator, tick_trace.items);
        tick_trace.deinit(allocator);
    };

    const run = blk: {
        if (trace_requested) {
            const traced = replay_runner.runReplayWithTrace(
                allocator,
                replay,
                &tick_trace,
                .{
                    .max_ticks = request.max_ticks,
                    .trace_rng = request.trace_rng or request.debug_trace_cdt != null,
                    .trace_timing = request.debug_trace_cdt != null,
                },
            ) catch |err| {
                writeRequestedDebugTraceOutputs(
                    allocator,
                    request,
                    replay_path,
                    replay_bytes,
                    replay,
                    tick_trace.items,
                ) catch |trace_err| {
                    return buildVerifyFailedOutput(allocator, verifyDebugTraceErrorDetail(trace_err));
                };
                return buildReplayRunnerFailureOutput(
                    allocator,
                    err,
                    .{
                        .processed_ticks = tick_trace.items.len,
                        .total_ticks = ticks_to_simulate,
                        .event_count = replay.events.len,
                    },
                );
            };
            break :blk traced;
        }

        break :blk replay_runner.runReplayWithOptions(replay, .{
            .max_ticks = request.max_ticks,
        }) catch |err| {
            return buildReplayRunnerFailureOutput(
                allocator,
                err,
                .{
                    .total_ticks = ticks_to_simulate,
                    .event_count = replay.events.len,
                },
            );
        };
    };

    const run_result: RunResult = .{
        .game_mode_id = header.game_mode_id,
        .tick_rate = header.tick_rate,
        .ticks = @intCast(run.ticks),
        .elapsed_ms = run.elapsed_ms_sim,
        .score_xp = run.player_experience,
        .creature_kill_count = run.creature_kill_count,
        .most_used_weapon_id = run.most_used_weapon_id,
        .shots_fired = run.shots_fired,
        .shots_hit = run.shots_hit,
        .rng_state = run.wave_spawn_rng_state,
    };
    var header_claim_payload_storage: ?HeaderClaimPayload = null;
    defer if (header_claim_payload_storage) |payload| allocator.free(payload.mismatched_fields);

    var status: []const u8 = "ok";
    var exit_code: u8 = 0;
    if (full_replay_simulated) {
        const header_claim_payload = try buildHeaderClaimPayload(allocator, header.claimed_stats, run_result);
        header_claim_payload_storage = header_claim_payload;
        status = if (header_claim_payload.match) "ok" else "header_stats_mismatch";
        exit_code = if (std.mem.eql(u8, status, "ok")) 0 else 3;
    }

    if (trace_requested) {
        writeRequestedDebugTraceOutputs(
            allocator,
            request,
            replay_path,
            replay_bytes,
            replay,
            tick_trace.items,
        ) catch |trace_err| {
            return buildVerifyFailedOutput(allocator, verifyDebugTraceErrorDetail(trace_err));
        };
    }

    const payload = try buildVerifyPayload(
        allocator,
        replay_path,
        run_result,
        status,
        header_claim_payload_storage,
    );
    defer allocator.free(payload);

    if (request.json_out) |json_out_path| {
        writeFileWithParents(json_out_path, payload) catch |err| {
            return buildVerifyFailedOutput(allocator, verifyJsonOutErrorDetail(err));
        };
    }

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    const writer = &stdout_buf.writer;

    if (request.json_out) |json_out_path| {
        if (request.output_format == .human) {
            try writer.print("json_report={s}\n", .{json_out_path});
        }
    }

    if (request.output_format == .json) {
        try writer.writeAll(payload);
        try writer.writeByte('\n');
    } else {
        try writer.print(
            "{s}: ticks={d} elapsed_ms={d} score_xp={d} kills={d} most_used_weapon_id={d} shots_fired={d} shots_hit={d} rng_state={d}",
            .{
                status,
                run_result.ticks,
                run_result.elapsed_ms,
                run_result.score_xp,
                run_result.creature_kill_count,
                run_result.most_used_weapon_id,
                run_result.shots_fired,
                run_result.shots_hit,
                run_result.rng_state,
            },
        );
        if (header_claim_payload_storage) |header_claim_payload| {
            try writer.print(
                "; header_claim complete={s} match={s} mismatches=",
                .{
                    if (header_claim_payload.expected.complete) "True" else "False",
                    if (header_claim_payload.match) "True" else "False",
                },
            );
            if (header_claim_payload.mismatched_fields.len == 0) {
                try writer.writeAll("-");
            } else {
                for (header_claim_payload.mismatched_fields, 0..) |field, idx| {
                    if (idx != 0) try writer.writeByte(',');
                    try writer.writeAll(field);
                }
            }
        }
        try writer.writeByte('\n');
    }

    return .{
        .stdout = try stdout_buf.toOwnedSlice(),
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = exit_code,
    };
}

fn writeRequestedDebugTraceOutputs(
    allocator: std.mem.Allocator,
    request: VerifyRequest,
    replay_path: []const u8,
    replay_bytes: []const u8,
    replay: replay_codec.Replay,
    tick_trace: []const replay_runner.ReplayTickTrace,
) !void {
    if (builtin.os.tag == .freestanding) {
        return error.UnsupportedTarget;
    }

    if (request.debug_trace_cdt) |trace_path| {
        try cdt_trace.writeReplayTickTraceCdt(
            allocator,
            trace_path,
            replay_path,
            replay_bytes,
            replay,
            tick_trace,
        );
    }
}

fn buildHeaderClaimPayload(
    allocator: std.mem.Allocator,
    claimed: replay_codec.ReplayClaimedStats,
    run_result: RunResult,
) !HeaderClaimPayload {
    const expected: ClaimedStatsPayload = .{
        .complete = claimed.complete,
        .ticks = claimed.ticks,
        .elapsed_ms = claimed.elapsed_ms,
        .score_xp = claimed.score_xp,
        .kills = claimed.kills,
        .most_used_weapon_id = claimed.most_used_weapon_id,
        .shots_fired = claimed.shots_fired,
        .shots_hit = claimed.shots_hit,
    };
    const simulated: ClaimedStatsPayload = .{
        .complete = claimed.complete,
        .ticks = run_result.ticks,
        .elapsed_ms = run_result.elapsed_ms,
        .score_xp = run_result.score_xp,
        .kills = run_result.creature_kill_count,
        .most_used_weapon_id = run_result.most_used_weapon_id,
        .shots_fired = run_result.shots_fired,
        .shots_hit = run_result.shots_hit,
    };

    var mismatch_buffer: [7][]const u8 = undefined;
    var mismatch_count: usize = 0;
    if (expected.ticks != simulated.ticks) {
        mismatch_buffer[mismatch_count] = "ticks";
        mismatch_count += 1;
    }
    if (expected.elapsed_ms != simulated.elapsed_ms) {
        mismatch_buffer[mismatch_count] = "elapsed_ms";
        mismatch_count += 1;
    }
    if (expected.score_xp != simulated.score_xp) {
        mismatch_buffer[mismatch_count] = "score_xp";
        mismatch_count += 1;
    }
    if (expected.kills != simulated.kills) {
        mismatch_buffer[mismatch_count] = "kills";
        mismatch_count += 1;
    }
    if (expected.most_used_weapon_id != simulated.most_used_weapon_id) {
        mismatch_buffer[mismatch_count] = "most_used_weapon_id";
        mismatch_count += 1;
    }
    if (expected.shots_fired != simulated.shots_fired) {
        mismatch_buffer[mismatch_count] = "shots_fired";
        mismatch_count += 1;
    }
    if (expected.shots_hit != simulated.shots_hit) {
        mismatch_buffer[mismatch_count] = "shots_hit";
        mismatch_count += 1;
    }

    const mismatched_fields = try allocator.alloc([]const u8, mismatch_count);
    for (mismatch_buffer[0..mismatch_count], 0..) |field, idx| {
        mismatched_fields[idx] = field;
    }

    return .{
        .expected = expected,
        .simulated = simulated,
        .match = mismatch_count == 0,
        .mismatched_fields = mismatched_fields,
    };
}

fn buildVerifyPayload(
    allocator: std.mem.Allocator,
    replay_path: []const u8,
    run_result: RunResult,
    status: []const u8,
    header_claim: ?HeaderClaimPayload,
) ![]u8 {
    const report: VerifyPayload = .{
        .schema_version = replay_schema_version,
        .status = status,
        .replay = replay_path,
        .run_result = run_result,
        .header_claim = header_claim,
        .score_claim = null,
    };

    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer payload_writer.deinit();
    try std.json.Stringify.value(report, .{}, &payload_writer.writer);
    return payload_writer.toOwnedSlice();
}

fn writeFileWithParents(path: []const u8, bytes: []const u8) !void {
    if (builtin.os.tag == .freestanding) {
        return error.UnsupportedTarget;
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(path)) |dir| {
        if (dir.len > 0) try std.Io.Dir.cwd().createDirPath(io, dir);
    }
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes,
    });
}

fn buildReplayNotFoundOutput(
    allocator: std.mem.Allocator,
    resolution: ReplayResolution,
) !CommandOutput {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    const writer = &stderr_buf.writer;
    try writer.print("replay file not found: {s}", .{resolution.tried_primary});
    if (resolution.tried_secondary) |secondary| {
        try writer.print(" (also tried: {s})", .{secondary});
    }
    try writer.writeByte('\n');

    const stderr = try stderr_buf.toOwnedSlice();
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");

    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn buildVerifyFailedOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    const writer = &stderr_buf.writer;
    try writer.print("replay verification failed: {s}\n", .{detail});

    const stderr = try stderr_buf.toOwnedSlice();
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");

    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn buildInvalidVerifyArgsOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    const writer = &stderr_buf.writer;
    try writer.print("invalid replay verify args: {s}\n", .{detail});

    const stderr = try stderr_buf.toOwnedSlice();
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");

    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn verifySetupErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "unable to inspect replay path: access denied",
        error.OutOfMemory => "native replay verifier ran out of memory while resolving paths",
        else => @errorName(err),
    };
}

fn verifyReplayReadErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "replay file not found",
        error.AccessDenied => "unable to read replay file: access denied",
        error.FileTooBig, error.PayloadTooLarge => "replay payload exceeds max decompressed size",
        error.OutOfMemory => "native replay verifier ran out of memory while reading replay",
        else => @errorName(err),
    };
}

fn verifyDebugTraceErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.UnsupportedTarget => "debug trace output is unavailable on this target",
        error.AccessDenied => "unable to write debug trace output: access denied",
        error.OutOfMemory => "native replay verifier ran out of memory while writing debug trace output",
        else => @errorName(err),
    };
}

fn verifyJsonOutErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.UnsupportedTarget => "json output file is unavailable on this target",
        error.AccessDenied => "unable to write replay verify JSON: access denied",
        error.OutOfMemory => "native replay verifier ran out of memory while writing JSON",
        else => @errorName(err),
    };
}

fn buildOutputForReplayCodecError(
    allocator: std.mem.Allocator,
    err: replay_codec.ReplayCodecError,
) !CommandOutput {
    switch (err) {
        error.InvalidMsgpack => return buildVerifyFailedOutput(allocator, "replay payload is not valid msgpack wire format"),
        error.InvalidHeaderValue => return buildVerifyFailedOutput(allocator, "replay header contains invalid values"),
        error.MissingHeaderField => return buildVerifyFailedOutput(allocator, "replay header missing required fields"),
        error.MissingQuestLevel => return buildVerifyFailedOutput(allocator, "quest replays require a valid header.quest_level"),
        error.TypoMultiplayer => return buildVerifyFailedOutput(allocator, "Typ-o replays require player_count == 1"),
        error.TutorialMultiplayer => return buildVerifyFailedOutput(allocator, "tutorial replays require player_count == 1"),
        error.UnsupportedInputShape => return buildVerifyFailedOutput(allocator, "replay input rows are invalid: expected canonical wire shape"),
        error.UnsupportedEventShape => return buildVerifyFailedOutput(allocator, "replay events are invalid: expected canonical wire shape"),
        error.InvalidGzipPayload => return buildVerifyFailedOutput(allocator, "unable to inflate replay gzip payload"),
        error.InvalidZstdPayload => return buildVerifyFailedOutput(allocator, "unable to inflate replay zstd payload"),
        error.UnsupportedReplayFormatVersion => return buildVerifyFailedOutput(allocator, "replay format version is not supported"),
        error.UnknownCommandKind => return buildVerifyFailedOutput(allocator, "replay events include an unknown command kind"),
        error.UnsupportedBootstrapKind => return buildVerifyFailedOutput(allocator, "replay bootstrap kind is not supported"),
        error.UnsupportedInputQuantization => return buildVerifyFailedOutput(allocator, "replay input quantization is not supported"),
        error.BootstrapSeedMismatch => return buildVerifyFailedOutput(allocator, "replay bootstrap seed does not match canonical terrain bootstrap draws"),
        error.PayloadTooLarge => return buildVerifyFailedOutput(allocator, "replay payload exceeds max decompressed size"),
        error.OutOfMemory => return buildVerifyFailedOutput(allocator, "native replay msgpack decode ran out of memory"),
    }
}

fn buildReplayRunnerFailureOutput(
    allocator: std.mem.Allocator,
    err: replay_runner.ReplayRunnerError,
    progress: ReplayRunnerProgressHint,
) !CommandOutput {
    const detail = switch (err) {
        error.OutOfMemory => "native replay run ran out of memory",
        error.InvalidHeaderValue => "native replay run received invalid header values",
        error.UnsupportedGameMode => "native replay run only supports survival/rush/quest/typo/tutorial modes",
        error.UnsupportedPlayerCount => "native replay run only supports 1-4 player replays",
        error.UnsupportedInputQuantization => "native replay run only supports f32 quantization",
        error.UnsupportedEventOrdering => "replay events are not ordered in canonical tick order",
        error.UnsupportedEventKind => "replay events include invalid kinds or values for this mode",
        error.UnsupportedEventPlayerIndex => "replay events include an out-of-range player_index",
        error.InvalidCaptureEnumValue => "replay capture payload contains an invalid enum value",
        error.InvalidSpawnTemplate => "replay capture payload references an invalid creature spawn template",
        error.InvalidQuestSpawnTable => "quest replay/session payload resolves to an invalid quest spawn table",
        error.MissingRngCallerTag => "native replay trace hit an untagged gameplay RNG draw",
    };

    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    const writer = &stderr_buf.writer;
    try writer.print("replay verification failed in the native runtime: {s}", .{detail});
    if (progress.processed_ticks) |processed_ticks| {
        try writer.print(
            " (progress: ticks_processed={d}/{d}, event_count={d})\n",
            .{ processed_ticks, progress.total_ticks, progress.event_count },
        );
    } else if (progress.total_ticks > 0 or progress.event_count > 0) {
        try writer.print(
            " (progress: ticks_total={d}, event_count={d})\n",
            .{ progress.total_ticks, progress.event_count },
        );
    } else {
        try writer.writeByte('\n');
    }

    const stderr = try stderr_buf.toOwnedSlice();
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");

    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn parseNativeSubset(args: []const []const u8) ParseOutcome {
    var replay_file: ?[]const u8 = null;
    var request: VerifyRequest = .{
        .replay_file = "",
    };

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];

        if (std.mem.eql(u8, arg, "--strict-events")) {
            return .{ .invalid = "--strict-events" };
        }

        if (std.mem.eql(u8, arg, "--trace-rng")) {
            request.trace_rng = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--max-ticks")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --max-ticks" };
            idx += 1;
            const parsed = std.fmt.parseInt(i64, args[idx], 10) catch return .{ .invalid = "invalid --max-ticks value" };
            if (parsed < 0) return .{ .invalid = "invalid --max-ticks value" };
            request.max_ticks = @intCast(parsed);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--max-ticks=")) {
            const parsed = std.fmt.parseInt(i64, arg["--max-ticks=".len..], 10) catch return .{ .invalid = "invalid --max-ticks value" };
            if (parsed < 0) return .{ .invalid = "invalid --max-ticks value" };
            request.max_ticks = @intCast(parsed);
            continue;
        }
        if (std.mem.eql(u8, arg, "--debug-trace-cdt")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --debug-trace-cdt" };
            idx += 1;
            request.debug_trace_cdt = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--debug-trace-cdt=")) {
            request.debug_trace_cdt = arg["--debug-trace-cdt=".len..];
            continue;
        }
        if (std.mem.eql(u8, arg, "--format")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --format" };
            idx += 1;
            request.output_format = parseOutputFormat(args[idx]) orelse return .{ .invalid = "invalid --format value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--format=")) {
            request.output_format = parseOutputFormat(arg["--format=".len..]) orelse return .{ .invalid = "invalid --format value" };
            continue;
        }

        if (std.mem.eql(u8, arg, "--json-out")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --json-out" };
            idx += 1;
            request.json_out = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--json-out=")) {
            request.json_out = arg["--json-out=".len..];
            continue;
        }

        if (std.mem.eql(u8, arg, "--base-dir") or std.mem.eql(u8, arg, "--runtime-dir")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --base-dir/--runtime-dir" };
            idx += 1;
            request.base_dir = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--base-dir=")) {
            request.base_dir = arg["--base-dir=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--runtime-dir=")) {
            request.base_dir = arg["--runtime-dir=".len..];
            continue;
        }

        if (std.mem.startsWith(u8, arg, "-")) {
            return .{ .invalid = arg };
        }

        if (replay_file == null) {
            replay_file = arg;
            continue;
        }

        return .{ .invalid = "too many positional arguments" };
    }

    const replay = replay_file orelse return .{ .invalid = "missing replay file argument" };
    request.replay_file = replay;
    return .{ .ok = request };
}

fn parseOutputFormat(raw: []const u8) ?OutputFormat {
    if (std.mem.eql(u8, raw, "human")) return .human;
    if (std.mem.eql(u8, raw, "json")) return .json;
    return null;
}

fn resolveReplayPath(
    allocator: std.mem.Allocator,
    replay_file: []const u8,
    base_dir: []const u8,
) !ReplayResolution {
    if (builtin.os.tag == .freestanding) {
        return error.UnsupportedTarget;
    }

    const primary_exists = try isFile(replay_file);
    if (primary_exists) {
        const resolved_path = try allocator.dupe(u8, replay_file);
        errdefer allocator.free(resolved_path);
        const tried_primary = try allocator.dupe(u8, replay_file);
        errdefer allocator.free(tried_primary);

        return .{
            .resolved_path = resolved_path,
            .tried_primary = tried_primary,
            .tried_secondary = null,
            .exists = true,
        };
    }

    if (!std.fs.path.isAbsolute(replay_file) and isSingleSegmentPath(replay_file)) {
        const secondary = try std.fs.path.join(allocator, &.{ base_dir, "replays", replay_file });
        errdefer allocator.free(secondary);
        const secondary_exists = try isFile(secondary);

        const resolved_path = if (secondary_exists)
            try allocator.dupe(u8, secondary)
        else
            try allocator.dupe(u8, replay_file);
        errdefer allocator.free(resolved_path);
        const tried_primary = try allocator.dupe(u8, replay_file);
        errdefer allocator.free(tried_primary);

        return .{
            .resolved_path = resolved_path,
            .tried_primary = tried_primary,
            .tried_secondary = secondary,
            .exists = secondary_exists,
        };
    }

    const resolved_path = try allocator.dupe(u8, replay_file);
    errdefer allocator.free(resolved_path);
    const tried_primary = try allocator.dupe(u8, replay_file);
    errdefer allocator.free(tried_primary);

    return .{
        .resolved_path = resolved_path,
        .tried_primary = tried_primary,
        .tried_secondary = null,
        .exists = false,
    };
}

fn isSingleSegmentPath(path: []const u8) bool {
    return std.mem.indexOfAny(u8, path, "/\\") == null;
}

fn isFile(path: []const u8) !bool {
    if (builtin.os.tag == .freestanding) {
        return error.UnsupportedTarget;
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.IsDir => return false,
        else => return err,
    };
    defer file.close(io);
    return true;
}

fn defaultRuntimeDir(allocator: std.mem.Allocator) ![]u8 {
    if (builtin.os.tag == .freestanding) {
        return error.UnsupportedTarget;
    }
    return (try runtime_paths.defaultRuntimeDir(allocator)) orelse allocator.dupe(u8, ".");
}

test "parse native subset for reference verify options" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--format",
        "json",
        "--json-out",
        "verify.json",
    });
    const req = switch (parsed) {
        .ok => |request| request,
        else => return error.TestExpectedNativeRequest,
    };

    try std.testing.expectEqualStrings("survival_20260224_041009_score76661.crd", req.replay_file);
    try std.testing.expect(req.output_format == .json);
    try std.testing.expect(req.json_out != null);
    try std.testing.expectEqualStrings("verify.json", req.json_out.?);
}

test "parse native subset accepts debug trace cdt option" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--debug-trace-cdt",
        "trace.cdt",
    });
    const req = switch (parsed) {
        .ok => |request| request,
        else => return error.TestExpectedNativeRequest,
    };
    try std.testing.expect(req.debug_trace_cdt != null);
    try std.testing.expectEqualStrings("trace.cdt", req.debug_trace_cdt.?);
}

test "parse native subset reports missing debug trace cdt argument" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--debug-trace-cdt",
    });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("missing value for --debug-trace-cdt", detail),
        else => return error.TestExpectedInvalidOption,
    }
}

test "parse native subset accepts trace rng option" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--trace-rng",
    });
    switch (parsed) {
        .ok => |request| try std.testing.expect(request.trace_rng),
        else => return error.TestExpectedValidOption,
    }
}

test "parse native subset reports unknown option as invalid" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--unknown-option",
    });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("--unknown-option", detail),
        else => return error.TestExpectedInvalidOption,
    }
}

test "parse native subset reports removed strict events option as invalid" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--strict-events",
    });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("--strict-events", detail),
        else => return error.TestExpectedInvalidOption,
    }
}

test "parse native subset reports removed lenient events option as invalid" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--lenient-events",
    });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("--lenient-events", detail),
        else => return error.TestExpectedInvalidOption,
    }
}

test "parse native subset accepts max ticks option" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--max-ticks=1000",
    });
    switch (parsed) {
        .ok => |request| try std.testing.expectEqual(@as(?usize, 1000), request.max_ticks),
        else => return error.TestExpectedValidOption,
    }
}

test "parse native subset rejects invalid max ticks value" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--max-ticks=-1",
    });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("invalid --max-ticks value", detail),
        else => return error.TestExpectedInvalidOption,
    }
}

test "parse native subset reports removed submitted score option as invalid" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--submitted-score=76661",
    });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("--submitted-score=76661", detail),
        else => return error.TestExpectedInvalidOption,
    }
}

test "build verify payload header mismatch" {
    const allocator = std.testing.allocator;
    const mismatched = [_][]const u8{"score_xp"};
    const header_claim: HeaderClaimPayload = .{
        .expected = .{
            .complete = true,
            .ticks = 100,
            .elapsed_ms = 2000,
            .score_xp = 1000,
            .kills = 15,
            .most_used_weapon_id = 14,
            .shots_fired = 123,
            .shots_hit = 45,
        },
        .simulated = .{
            .complete = true,
            .ticks = 100,
            .elapsed_ms = 2000,
            .score_xp = 999,
            .kills = 15,
            .most_used_weapon_id = 14,
            .shots_fired = 123,
            .shots_hit = 45,
        },
        .match = false,
        .mismatched_fields = mismatched[0..],
    };
    const payload = try buildVerifyPayload(
        allocator,
        "/tmp/replay.crd",
        .{
            .game_mode_id = 1,
            .tick_rate = 60,
            .ticks = 100,
            .elapsed_ms = 2000,
            .score_xp = 999,
            .creature_kill_count = 15,
            .most_used_weapon_id = 14,
            .shots_fired = 123,
            .shots_hit = 45,
            .rng_state = 1234,
        },
        "header_stats_mismatch",
        header_claim,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"schema_version\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"status\":\"header_stats_mismatch\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"mismatched_fields\":[\"score_xp\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "replay_sha256") == null);
}

test "build verify payload escapes replay path via json stringify" {
    const allocator = std.testing.allocator;
    const payload = try buildVerifyPayload(
        allocator,
        "test\"\nreplay.crd",
        .{
            .game_mode_id = 1,
            .tick_rate = 60,
            .ticks = 100,
            .elapsed_ms = 2000,
            .score_xp = 999,
            .creature_kill_count = 15,
            .most_used_weapon_id = 14,
            .shots_fired = 123,
            .shots_hit = 45,
            .rng_state = 1234,
        },
        "ok",
        null,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"replay\":\"test\\\"\\nreplay.crd\"") != null);
}

test "replay verify file and output errors use user-facing details" {
    try std.testing.expectEqualStrings(
        "native replay verifier ran out of memory while resolving paths",
        verifySetupErrorDetail(error.OutOfMemory),
    );
    try std.testing.expectEqualStrings(
        "replay payload exceeds max decompressed size",
        verifyReplayReadErrorDetail(error.PayloadTooLarge),
    );
    try std.testing.expectEqualStrings(
        "debug trace output is unavailable on this target",
        verifyDebugTraceErrorDetail(error.UnsupportedTarget),
    );
    try std.testing.expectEqualStrings(
        "unable to write replay verify JSON: access denied",
        verifyJsonOutErrorDetail(error.AccessDenied),
    );
    try std.testing.expectEqualStrings(
        "FileBusy",
        verifyReplayReadErrorDetail(error.FileBusy),
    );
}

test "replay codec invalid replay errors map to verify failed output" {
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        err: replay_codec.ReplayCodecError,
        detail: []const u8,
    }{
        .{ .err = error.InvalidMsgpack, .detail = "replay payload is not valid msgpack wire format" },
        .{ .err = error.InvalidHeaderValue, .detail = "replay header contains invalid values" },
        .{ .err = error.MissingHeaderField, .detail = "replay header missing required fields" },
        .{ .err = error.MissingQuestLevel, .detail = "quest replays require a valid header.quest_level" },
        .{ .err = error.TypoMultiplayer, .detail = "Typ-o replays require player_count == 1" },
        .{ .err = error.TutorialMultiplayer, .detail = "tutorial replays require player_count == 1" },
        .{ .err = error.UnsupportedInputShape, .detail = "replay input rows are invalid: expected canonical wire shape" },
        .{ .err = error.UnsupportedEventShape, .detail = "replay events are invalid: expected canonical wire shape" },
        .{ .err = error.InvalidGzipPayload, .detail = "unable to inflate replay gzip payload" },
        .{ .err = error.UnsupportedReplayFormatVersion, .detail = "replay format version is not supported" },
        .{ .err = error.UnknownCommandKind, .detail = "replay events include an unknown command kind" },
        .{ .err = error.UnsupportedBootstrapKind, .detail = "replay bootstrap kind is not supported" },
        .{ .err = error.UnsupportedInputQuantization, .detail = "replay input quantization is not supported" },
        .{ .err = error.BootstrapSeedMismatch, .detail = "replay bootstrap seed does not match canonical terrain bootstrap draws" },
        .{ .err = error.PayloadTooLarge, .detail = "replay payload exceeds max decompressed size" },
        .{ .err = error.OutOfMemory, .detail = "native replay msgpack decode ran out of memory" },
    };

    for (cases) |case_item| {
        const output = try buildOutputForReplayCodecError(allocator, case_item.err);
        defer output.deinit(allocator);

        try std.testing.expectEqual(@as(i32, 1), output.exit_code);
        try std.testing.expect(std.mem.indexOf(u8, output.stderr, "replay verification failed:") != null);
        try std.testing.expect(std.mem.indexOf(u8, output.stderr, case_item.detail) != null);
        try std.testing.expect(std.mem.indexOf(u8, output.stderr, "native runtime limitation") == null);
    }
}

test "runtime replay failure output includes progress hints" {
    const allocator = std.testing.allocator;
    const output = try buildReplayRunnerFailureOutput(
        allocator,
        error.UnsupportedEventKind,
        .{
            .processed_ticks = 2559,
            .total_ticks = 8807,
            .event_count = 8,
        },
    );
    defer allocator.free(output.stdout);
    defer allocator.free(output.stderr);

    try std.testing.expectEqual(@as(i32, 1), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "replay events include invalid kinds or values for this mode") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "ticks_processed=2559/8807") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "event_count=8") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "unsupported") == null);
}

fn makeTestReplayHeader(
    allocator: std.mem.Allocator,
) !replay_codec.ReplayHeader {
    return .{
        .game_mode_id = 1,
        .seed = 1,
        .replay_format_version = replay_codec.replay_format_version,
        .quest_level = try allocator.dupe(u8, ""),
        .bootstrap_kind = try allocator.dupe(u8, "none"),
        .bootstrap_seed = 0,
        .game_version = try allocator.dupe(u8, "0.9.0"),
        .tick_rate = 60,
        .difficulty_level = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .gore_disabled = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{
            .quest_unlock_index = 0,
            .quest_unlock_index_full = 0,
            .weapon_usage_counts = [_]u32{0} ** replay_codec.weapon_usage_count,
        },
        .input_quantization = try allocator.dupe(u8, "f32"),
    };
}

test "unsupported replay header detail rejects unsupported game mode" {
    const allocator = std.testing.allocator;
    var header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);
    header.game_mode_id = 9;

    const detail = replay_codec.unsupportedReplayHeaderDetail(header, 1, .verifier) orelse return error.TestExpectedUnsupported;
    try std.testing.expectEqualStrings("native replay tools support only survival/rush/quest/typo/tutorial modes", detail);
}

test "unsupported replay header detail rejects unsupported player count" {
    const allocator = std.testing.allocator;
    var header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);
    header.player_count = 5;

    const detail = replay_codec.unsupportedReplayHeaderDetail(header, 1, .verifier) orelse return error.TestExpectedUnsupported;
    try std.testing.expectEqualStrings("native replay tools support only 1-4 player replays", detail);
}

test "unsupported replay header detail rejects non f32 quantization" {
    const allocator = std.testing.allocator;
    var header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);
    allocator.free(header.input_quantization);
    header.input_quantization = try allocator.dupe(u8, "u8");

    const detail = replay_codec.unsupportedReplayHeaderDetail(header, 1, .verifier) orelse return error.TestExpectedUnsupported;
    try std.testing.expectEqualStrings("native replay tools support only f32 input quantization", detail);
}

test "unsupported replay header detail rejects oversized tick count" {
    const allocator = std.testing.allocator;
    const header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);

    const overflow_ticks = @as(usize, std.math.maxInt(i32)) + 1;
    const detail = replay_codec.unsupportedReplayHeaderDetail(header, overflow_ticks, .verifier) orelse return error.TestExpectedUnsupported;
    try std.testing.expectEqualStrings("replay has too many ticks for current native verifier", detail);
}

test "unsupported replay header detail rejects non latest ruleset" {
    const allocator = std.testing.allocator;
    var header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);
    allocator.free(header.game_version);
    header.game_version = try allocator.dupe(u8, "0.6.9");

    const detail = replay_codec.unsupportedReplayHeaderDetail(header, 1, .verifier) orelse return error.TestExpectedUnsupported;
    try std.testing.expectEqualStrings("native replay tools require latest ruleset replays unless preserve_bugs is set", detail);
}

test "unsupported replay header detail accepts supported replay envelope" {
    const allocator = std.testing.allocator;
    const header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);

    try std.testing.expect(replay_codec.unsupportedReplayHeaderDetail(header, 1, .verifier) == null);
}

test "unsupported replay header detail accepts preserve bugs older ruleset replay envelope" {
    const allocator = std.testing.allocator;
    var header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);
    header.preserve_bugs = true;
    allocator.free(header.game_version);
    header.game_version = try allocator.dupe(u8, "0.6.9");

    try std.testing.expect(replay_codec.unsupportedReplayHeaderDetail(header, 1, .verifier) == null);
}
