const std = @import("std");
const builtin = @import("builtin");
const msgpack = @import("msgpack");

const game_ids = @import("game_ids.zig");
const replay_codec = @import("replay_codec.zig");
const replay_runner = @import("runtime/replay_runner.zig");
const runtime_paths = @import("runtime_paths.zig");
const state_mod = @import("runtime/state.zig");
const tutorial_runtime = @import("tutorial/runtime.zig");
const verify_native = @import("verify_native.zig");

const checkpoints_format_version: i32 = 4;
const checkpoint_report_schema_version: i32 = 1;
const max_checkpoints_payload_bytes: usize = 256 * 1024 * 1024;

pub const CommandOutput = verify_native.CommandOutput;

const ReplayCheckpointsWire = struct {
    version: i32,
    sample_rate: i32,
    checkpoints: []const ReplayCheckpointWire,
};

const Vec2Wire = struct {
    x: f64,
    y: f64,
};

const ReplayPlayerCheckpointWire = struct {
    pos: Vec2Wire,
    health: f64,
    weapon_id: i32,
    ammo: f64,
    experience: i32,
    level: i32,
};

const ReplayDeathLedgerEntryWire = struct {
    creature_index: i32,
    type_id: i32,
    reward_value: f64,
    xp_awarded: i32,
    owner_id: i32 = -1,

    fn msgpackRead(unpacker: anytype) !ReplayDeathLedgerEntryWire {
        const field_count = try unpacker.readMapHeader(u32);
        var field_name_buf: [64]u8 = undefined;
        var entry: ReplayDeathLedgerEntryWire = .{
            .creature_index = 0,
            .type_id = 0,
            .reward_value = 0.0,
            .xp_awarded = 0,
        };
        var seen_creature_index = false;
        var seen_type_id = false;
        var seen_reward_value = false;
        var seen_xp_awarded = false;

        for (0..field_count) |_| {
            const field_name = try unpacker.readStringInto(&field_name_buf);
            if (std.mem.eql(u8, field_name, "creature_index")) {
                entry.creature_index = try unpacker.readInt(i32);
                seen_creature_index = true;
            } else if (std.mem.eql(u8, field_name, "type_id")) {
                entry.type_id = try unpacker.readInt(i32);
                seen_type_id = true;
            } else if (std.mem.eql(u8, field_name, "reward_value")) {
                entry.reward_value = try unpacker.readFloat(f64);
                seen_reward_value = true;
            } else if (std.mem.eql(u8, field_name, "xp_awarded")) {
                entry.xp_awarded = try unpacker.readInt(i32);
                seen_xp_awarded = true;
            } else if (std.mem.eql(u8, field_name, "owner_id")) {
                entry.owner_id = try unpacker.readInt(i32);
            } else {
                return error.UnknownStructField;
            }
        }

        if (!seen_creature_index or !seen_type_id or !seen_reward_value or !seen_xp_awarded) {
            return error.MissingCheckpointDeathField;
        }

        return entry;
    }
};

const ReplayPerkSnapshotWire = struct {
    pending_count: i32,
    choices_dirty: bool,
    choices: []const i32,
    player_nonzero_counts: []const []const []const i32,
};

const ReplayHitSummaryEntryWire = struct {
    type_id: i32,
    origin: Vec2Wire,
    hit: Vec2Wire,
    target: Vec2Wire,
};

const ReplayEventSummaryWire = struct {
    hit_count: i32,
    pickup_count: i32,
    sfx_count: i32,
    sfx_head: []const []const u8,
    hit_head: []const ReplayHitSummaryEntryWire,
};

pub const BonusTimerEntryWire = struct {
    key: []const u8,
    value: i32,
};

pub const BonusTimersWire = struct {
    entries: []const BonusTimerEntryWire,

    pub fn msgpackRead(unpacker: anytype) !BonusTimersWire {
        const len = try unpacker.readMapHeader(u32);
        const entries = try unpacker.allocator.alloc(BonusTimerEntryWire, len);
        errdefer unpacker.allocator.free(entries);

        for (entries) |*entry| {
            entry.* = .{
                .key = try unpacker.readString(),
                .value = try unpacker.readInt(i32),
            };
        }

        return .{ .entries = entries };
    }
};

const ReplayTutorialSnapshotWire = struct {
    stage_index: i32,
    stage_timer_ms: i32,
    stage_transition_timer_ms: i32,
    hint_index: i32,
    hint_alpha: i32,
    hint_fade_in: bool,
    repeat_spawn_count: i32,
    hint_bonus_creature_ref: ?i32,
    prompt_text: []const u8,
    prompt_alpha: f64,
    hint_text: []const u8,
    hint_alpha_overlay: f64,
};

const ReplayTypoNameEntryWire = struct {
    creature_index: i32,
    name: []const u8,
};

const ReplayTypoSnapshotWire = struct {
    input_text: []const u8,
    submit_count: i32,
    match_count: i32,
    spawn_cooldown_ms: i32,
    active_names: []const ReplayTypoNameEntryWire,
};

const ReplayCheckpointWire = struct {
    tick_index: i32,
    rng_state: u32,
    elapsed_ms: i32,
    score_xp: i32,
    kills: i32,
    creature_count: i32,
    perk_pending: i32,
    players: []const ReplayPlayerCheckpointWire,
    bonus_timers: BonusTimersWire,
    deaths: []const ReplayDeathLedgerEntryWire,
    perk: ReplayPerkSnapshotWire,
    events: ReplayEventSummaryWire,
    tutorial: ?ReplayTutorialSnapshotWire,
    typo: ?ReplayTypoSnapshotWire,
};

const OutputFormat = enum {
    human,
    json,
};

const DiffRequest = struct {
    expected_file: []const u8 = "",
    actual_file: []const u8 = "",
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
};

const VerifyCheckpointsRequest = struct {
    replay_file: []const u8,
    checkpoints_file: ?[]const u8 = null,
    base_dir: ?[]const u8 = null,
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
    max_ticks: ?usize = null,
    trace_rng: bool = false,
};

const DiffOutputOptions = struct {
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
    expected_file: ?[]const u8 = null,
    actual_file: ?[]const u8 = null,
};

const VerifyOutputOptions = struct {
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
    replay_file: ?[]const u8 = null,
    checkpoints_file: ?[]const u8 = null,
    max_ticks: ?usize = null,
    trace_rng: bool = false,
};

const CheckpointDiffSummaryPayload = struct {
    expected_count: usize,
    actual_count: usize,
    checked_count: usize,
    rng_only_drift_tick: ?i32,
};

const CheckpointDiffPayload = struct {
    schema_version: i32,
    status: []const u8,
    command: []const u8,
    expected: ?[]const u8,
    actual: ?[]const u8,
    summary: CheckpointDiffSummaryPayload,
};

const VerifyCheckpointsSummaryPayload = struct {
    checkpoint_count: usize,
    checked_count: usize,
    ticks: usize,
    score_xp: i32,
    kills: i32,
    rng_only_drift_tick: ?i32,
    max_ticks: ?usize,
    trace_rng: bool,
};

const VerifyCheckpointsPayload = struct {
    schema_version: i32,
    status: []const u8,
    command: []const u8,
    replay: ?[]const u8,
    checkpoints: ?[]const u8,
    summary: VerifyCheckpointsSummaryPayload,
};

const DiffParseOutcome = union(enum) {
    ok: DiffRequest,
    invalid: []const u8,
};

const VerifyParseOutcome = union(enum) {
    ok: VerifyCheckpointsRequest,
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

const DiffFailure = struct {
    kind: enum { missing_checkpoint, state_mismatch },
    tick_index: i32,
    expected: *const ReplayCheckpointWire,
    actual: ?*const ReplayCheckpointWire = null,
};

const DiffResult = struct {
    ok: bool,
    checked_count: usize,
    first_rng_only_tick: ?i32 = null,
    failure: ?DiffFailure = null,
};

pub fn runReplayDiffCheckpoints(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseDiffArgs(args)) {
        .ok => |request| return runNativeDiff(allocator, request),
        .invalid => |detail| return buildInvalidArgsOutput(allocator, detail),
    }
}

pub fn runReplayVerifyCheckpoints(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !CommandOutput {
    switch (parseVerifyArgs(args)) {
        .ok => |request| return runNativeVerifyCheckpoints(allocator, request),
        .invalid => |detail| return buildInvalidVerifyArgsOutput(allocator, detail),
    }
}

pub fn runReplayDiffCheckpointsBytes(
    allocator: std.mem.Allocator,
    expected_bytes: []const u8,
    actual_bytes: []const u8,
) !CommandOutput {
    var expected = loadCheckpointsBytes(allocator, expected_bytes) catch |err| {
        return buildFailedOutput(allocator, checkpointFileLoadErrorDetail(err));
    };
    defer expected.deinit();

    var actual = loadCheckpointsBytes(allocator, actual_bytes) catch |err| {
        return buildFailedOutput(allocator, checkpointFileLoadErrorDetail(err));
    };
    defer actual.deinit();

    return runDiffWithCheckpoints(allocator, expected.value.checkpoints, actual.value.checkpoints);
}

/// Compare checkpoint msgpack payloads and return the schema-versioned JSON report.
pub fn runReplayDiffCheckpointsBytesJson(
    allocator: std.mem.Allocator,
    expected_name: []const u8,
    expected_bytes: []const u8,
    actual_name: []const u8,
    actual_bytes: []const u8,
) !CommandOutput {
    var expected = loadCheckpointsBytes(allocator, expected_bytes) catch |err| {
        return buildFailedOutput(allocator, checkpointFileLoadErrorDetail(err));
    };
    defer expected.deinit();

    var actual = loadCheckpointsBytes(allocator, actual_bytes) catch |err| {
        return buildFailedOutput(allocator, checkpointFileLoadErrorDetail(err));
    };
    defer actual.deinit();

    return runDiffWithCheckpointsOutput(
        allocator,
        expected.value.checkpoints,
        actual.value.checkpoints,
        .{
            .output_format = .json,
            .expected_file = expected_name,
            .actual_file = actual_name,
        },
    );
}

pub fn runReplayVerifyCheckpointsBytes(
    allocator: std.mem.Allocator,
    replay_bytes: []const u8,
    checkpoints_bytes: []const u8,
    max_ticks: ?usize,
    trace_rng: bool,
) !CommandOutput {
    var expected = loadCheckpointsBytes(allocator, checkpoints_bytes) catch |err| {
        return buildVerifyFailedOutput(allocator, checkpointFileLoadErrorDetail(err));
    };
    defer expected.deinit();

    var parse_detail: ?[]u8 = null;
    defer if (parse_detail) |detail| allocator.free(detail);
    var replay = loadReplayBytes(allocator, replay_bytes, &parse_detail) catch |err| {
        return buildVerifyFailedOutput(allocator, parse_detail orelse replayLoadErrorDetail(err));
    };
    defer replay.deinit(allocator);

    return runVerifyCheckpointsWithReplay(
        allocator,
        expected.value.checkpoints,
        replay,
        max_ticks,
        trace_rng,
    );
}

/// Verify replay bytes against checkpoint msgpack bytes and return the JSON report.
pub fn runReplayVerifyCheckpointsBytesJson(
    allocator: std.mem.Allocator,
    replay_name: []const u8,
    replay_bytes: []const u8,
    checkpoints_name: []const u8,
    checkpoints_bytes: []const u8,
    max_ticks: ?usize,
    trace_rng: bool,
) !CommandOutput {
    var expected = loadCheckpointsBytes(allocator, checkpoints_bytes) catch |err| {
        return buildVerifyFailedOutput(allocator, checkpointFileLoadErrorDetail(err));
    };
    defer expected.deinit();

    var parse_detail: ?[]u8 = null;
    defer if (parse_detail) |detail| allocator.free(detail);
    var replay = loadReplayBytes(allocator, replay_bytes, &parse_detail) catch |err| {
        return buildVerifyFailedOutput(allocator, parse_detail orelse replayLoadErrorDetail(err));
    };
    defer replay.deinit(allocator);

    return runVerifyCheckpointsWithReplayOutput(
        allocator,
        expected.value.checkpoints,
        replay,
        .{
            .output_format = .json,
            .replay_file = replay_name,
            .checkpoints_file = checkpoints_name,
            .max_ticks = max_ticks,
            .trace_rng = trace_rng,
        },
    );
}

fn parseDiffArgs(args: []const []const u8) DiffParseOutcome {
    var request: DiffRequest = .{};
    var path_count: usize = 0;
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
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
        if (std.mem.startsWith(u8, arg, "-")) return .{ .invalid = "expected checkpoints file path, got option" };
        switch (path_count) {
            0 => request.expected_file = arg,
            1 => request.actual_file = arg,
            else => return .{ .invalid = "expected <expected.chk> <actual.chk>" },
        }
        path_count += 1;
    }
    if (path_count != 2) return .{ .invalid = "expected <expected.chk> <actual.chk>" };
    return .{ .ok = request };
}

fn parseVerifyArgs(args: []const []const u8) VerifyParseOutcome {
    if (args.len == 0) return .{ .invalid = "missing replay file" };

    var request: VerifyCheckpointsRequest = .{ .replay_file = "" };
    var replay_seen = false;
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--trace-rng")) {
            request.trace_rng = true;
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
        if (std.mem.eql(u8, arg, "--checkpoints")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --checkpoints" };
            idx += 1;
            request.checkpoints_file = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--checkpoints=")) {
            request.checkpoints_file = arg["--checkpoints=".len..];
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
        if (std.mem.eql(u8, arg, "--max-ticks")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --max-ticks" };
            idx += 1;
            request.max_ticks = std.fmt.parseInt(usize, args[idx], 10) catch return .{ .invalid = "invalid --max-ticks" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--max-ticks=")) {
            request.max_ticks = std.fmt.parseInt(usize, arg["--max-ticks=".len..], 10) catch return .{ .invalid = "invalid --max-ticks" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return .{ .invalid = arg };
        if (replay_seen) return .{ .invalid = "unexpected extra argument" };
        request.replay_file = arg;
        replay_seen = true;
    }

    if (!replay_seen) return .{ .invalid = "missing replay file" };
    return .{ .ok = request };
}

fn runNativeDiff(
    allocator: std.mem.Allocator,
    request: DiffRequest,
) !CommandOutput {
    var expected = loadCheckpointsFile(allocator, request.expected_file) catch |err| {
        return buildFailedOutput(allocator, checkpointFileLoadErrorDetail(err));
    };
    defer expected.deinit();

    var actual = loadCheckpointsFile(allocator, request.actual_file) catch |err| {
        return buildFailedOutput(allocator, checkpointFileLoadErrorDetail(err));
    };
    defer actual.deinit();

    return runDiffWithCheckpointsOutput(
        allocator,
        expected.value.checkpoints,
        actual.value.checkpoints,
        .{
            .output_format = request.output_format,
            .json_out = request.json_out,
            .expected_file = request.expected_file,
            .actual_file = request.actual_file,
        },
    );
}

fn runDiffWithCheckpoints(
    allocator: std.mem.Allocator,
    expected_checkpoints: []const ReplayCheckpointWire,
    actual_checkpoints: []const ReplayCheckpointWire,
) !CommandOutput {
    return runDiffWithCheckpointsOutput(allocator, expected_checkpoints, actual_checkpoints, .{});
}

fn runDiffWithCheckpointsOutput(
    allocator: std.mem.Allocator,
    expected_checkpoints: []const ReplayCheckpointWire,
    actual_checkpoints: []const ReplayCheckpointWire,
    options: DiffOutputOptions,
) !CommandOutput {
    const diff = compareCheckpoints(expected_checkpoints, actual_checkpoints);
    if (!diff.ok) {
        return buildMismatchOutput(allocator, diff);
    }

    var payload_json: ?[]u8 = null;
    defer if (payload_json) |payload| allocator.free(payload);
    if (options.output_format == .json or options.json_out != null) {
        const payload = buildDiffJsonPayload(
            allocator,
            expected_checkpoints,
            actual_checkpoints,
            diff,
            options,
        ) catch |err| {
            return buildFailedOutput(allocator, checkpointJsonOutErrorDetail(err));
        };
        payload_json = payload;
        if (options.json_out) |json_out_path| {
            writeFileWithParents(json_out_path, payload) catch |err| {
                return buildFailedOutput(allocator, checkpointJsonOutErrorDetail(err));
            };
        }
    }

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    if (options.output_format == .json) {
        try stdout_buf.writer.writeAll(payload_json.?);
        try stdout_buf.writer.writeByte('\n');
    } else {
        try stdout_buf.writer.print("ok: {d} checkpoints match\n", .{expected_checkpoints.len});
        if (diff.first_rng_only_tick) |tick| {
            try stdout_buf.writer.print("first rng-only divergence tick={d}\n", .{tick});
        }
        if (options.json_out) |json_out_path| {
            try stdout_buf.writer.print("json_report={s}\n", .{json_out_path});
        }
    }

    const stdout = try stdout_buf.toOwnedSlice();
    errdefer allocator.free(stdout);
    const stderr = try allocator.dupe(u8, "");
    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 0,
    };
}

fn runNativeVerifyCheckpoints(
    allocator: std.mem.Allocator,
    request: VerifyCheckpointsRequest,
) !CommandOutput {
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
        return buildVerifyFailedOutput(allocator, generalVerifyErrorDetail(err));
    };
    defer resolution.deinit(allocator);

    if (!resolution.exists) {
        return buildReplayNotFoundOutput(allocator, resolution);
    }
    if (!std.mem.endsWith(u8, resolution.resolved_path, ".crd")) {
        return buildVerifyFailedOutput(allocator, "replay file must use .crd extension");
    }

    const checkpoints_path = if (request.checkpoints_file) |path|
        try allocator.dupe(u8, path)
    else
        try defaultCheckpointsPath(allocator, resolution.resolved_path);
    defer allocator.free(checkpoints_path);

    if (!fileExists(checkpoints_path)) {
        return buildCheckpointsNotFoundOutput(allocator, checkpoints_path);
    }

    var expected = loadCheckpointsFile(allocator, checkpoints_path) catch |err| {
        return buildVerifyFailedOutput(allocator, checkpointFileLoadErrorDetail(err));
    };
    defer expected.deinit();

    const io = std.Io.Threaded.global_single_threaded.io();
    const replay_bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        resolution.resolved_path,
        allocator,
        .limited(replay_codec.max_replay_payload_bytes),
    ) catch |err| {
        return buildVerifyFailedOutput(allocator, replayFileLoadErrorDetail(err));
    };
    defer allocator.free(replay_bytes);

    var parse_detail: ?[]u8 = null;
    defer if (parse_detail) |detail| allocator.free(detail);
    var replay = loadReplayBytes(allocator, replay_bytes, &parse_detail) catch |err| {
        return buildVerifyFailedOutput(allocator, parse_detail orelse replayLoadErrorDetail(err));
    };
    defer replay.deinit(allocator);

    return runVerifyCheckpointsWithReplayOutput(
        allocator,
        expected.value.checkpoints,
        replay,
        .{
            .output_format = request.output_format,
            .json_out = request.json_out,
            .replay_file = resolution.resolved_path,
            .checkpoints_file = checkpoints_path,
            .max_ticks = request.max_ticks,
            .trace_rng = request.trace_rng,
        },
    );
}

fn runVerifyCheckpointsWithReplay(
    allocator: std.mem.Allocator,
    expected_checkpoints: []const ReplayCheckpointWire,
    replay: replay_codec.Replay,
    max_ticks: ?usize,
    trace_rng: bool,
) !CommandOutput {
    return runVerifyCheckpointsWithReplayOutput(allocator, expected_checkpoints, replay, .{
        .max_ticks = max_ticks,
        .trace_rng = trace_rng,
    });
}

fn runVerifyCheckpointsWithReplayOutput(
    allocator: std.mem.Allocator,
    expected_checkpoints: []const ReplayCheckpointWire,
    replay: replay_codec.Replay,
    options: VerifyOutputOptions,
) !CommandOutput {
    if (try replay_codec.replayEventOrderingFailureDetail(allocator, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildVerifyFailedOutput(allocator, detail);
    }
    if (try replay_codec.replayEventPlayerIndexFailureDetail(allocator, replay.header.player_count, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildVerifyFailedOutput(allocator, detail);
    }
    if (try replay_codec.replayEventKindFailureDetail(allocator, replay.header.game_mode_id, replay.events)) |detail| {
        defer allocator.free(detail);
        return buildVerifyFailedOutput(allocator, detail);
    }

    var trace: std.ArrayList(replay_runner.ReplayTickTrace) = .empty;
    defer {
        replay_runner.deinitReplayTickTraceRows(allocator, trace.items);
        trace.deinit(allocator);
    }

    const run = replay_runner.runReplayWithTrace(
        allocator,
        replay,
        &trace,
        .{
            .max_ticks = options.max_ticks,
            .trace_rng = options.trace_rng,
            .trace_timing = false,
        },
    ) catch |err| {
        return buildVerifyFailedOutput(allocator, replayRunnerErrorDetail(err));
    };

    var actual: std.ArrayList(ReplayCheckpointWire) = .empty;
    defer {
        for (actual.items) |*checkpoint| deinitOwnedCheckpoint(allocator, checkpoint);
        actual.deinit(allocator);
    }

    for (expected_checkpoints) |expected_checkpoint| {
        const row = traceRowForTick(trace.items, expected_checkpoint.tick_index) orelse continue;
        var checkpoint = buildCheckpointFromTrace(allocator, row) catch |err| {
            return buildVerifyFailedOutput(allocator, checkpointBuildErrorDetail(err));
        };
        errdefer deinitOwnedCheckpoint(allocator, &checkpoint);
        actual.append(allocator, checkpoint) catch |err| {
            deinitOwnedCheckpoint(allocator, &checkpoint);
            return buildVerifyFailedOutput(allocator, checkpointBuildErrorDetail(err));
        };
    }

    const diff = compareCheckpoints(expected_checkpoints, actual.items);
    if (!diff.ok) return buildMismatchOutput(allocator, diff);

    var payload_json: ?[]u8 = null;
    defer if (payload_json) |payload| allocator.free(payload);
    if (options.output_format == .json or options.json_out != null) {
        const payload = buildVerifyJsonPayload(
            allocator,
            expected_checkpoints,
            diff,
            run,
            options,
        ) catch |err| {
            return buildVerifyFailedOutput(allocator, checkpointJsonOutErrorDetail(err));
        };
        payload_json = payload;
        if (options.json_out) |json_out_path| {
            writeFileWithParents(json_out_path, payload) catch |err| {
                return buildVerifyFailedOutput(allocator, checkpointJsonOutErrorDetail(err));
            };
        }
    }

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    if (options.output_format == .json) {
        try stdout_buf.writer.writeAll(payload_json.?);
        try stdout_buf.writer.writeByte('\n');
    } else {
        try stdout_buf.writer.print(
            "ok: {d} checkpoints match; ticks={d} score_xp={d} kills={d}",
            .{ expected_checkpoints.len, run.ticks, run.player_experience, run.creature_kill_count },
        );
        if (diff.first_rng_only_tick) |tick| {
            try stdout_buf.writer.print("; rng-only drift starts at tick={d}", .{tick});
        }
        if (options.json_out) |json_out_path| {
            try stdout_buf.writer.print("; json_report={s}", .{json_out_path});
        }
        try stdout_buf.writer.writeByte('\n');
    }

    const stdout = try stdout_buf.toOwnedSlice();
    errdefer allocator.free(stdout);
    const stderr = try allocator.dupe(u8, "");
    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 0,
    };
}

fn buildDiffJsonPayload(
    allocator: std.mem.Allocator,
    expected_checkpoints: []const ReplayCheckpointWire,
    actual_checkpoints: []const ReplayCheckpointWire,
    diff: DiffResult,
    options: DiffOutputOptions,
) ![]u8 {
    const payload: CheckpointDiffPayload = .{
        .schema_version = checkpoint_report_schema_version,
        .status = "ok",
        .command = "diff-checkpoints",
        .expected = options.expected_file,
        .actual = options.actual_file,
        .summary = .{
            .expected_count = expected_checkpoints.len,
            .actual_count = actual_checkpoints.len,
            .checked_count = diff.checked_count,
            .rng_only_drift_tick = diff.first_rng_only_tick,
        },
    };
    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer payload_writer.deinit();
    try std.json.Stringify.value(payload, .{}, &payload_writer.writer);
    return payload_writer.toOwnedSlice();
}

fn buildVerifyJsonPayload(
    allocator: std.mem.Allocator,
    expected_checkpoints: []const ReplayCheckpointWire,
    diff: DiffResult,
    run: replay_runner.ReplayRunResult,
    options: VerifyOutputOptions,
) ![]u8 {
    const payload: VerifyCheckpointsPayload = .{
        .schema_version = checkpoint_report_schema_version,
        .status = "ok",
        .command = "verify-checkpoints",
        .replay = options.replay_file,
        .checkpoints = options.checkpoints_file,
        .summary = .{
            .checkpoint_count = expected_checkpoints.len,
            .checked_count = diff.checked_count,
            .ticks = run.ticks,
            .score_xp = run.player_experience,
            .kills = run.creature_kill_count,
            .rng_only_drift_tick = diff.first_rng_only_tick,
            .max_ticks = options.max_ticks,
            .trace_rng = options.trace_rng,
        },
    };
    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer payload_writer.deinit();
    try std.json.Stringify.value(payload, .{}, &payload_writer.writer);
    return payload_writer.toOwnedSlice();
}

fn loadCheckpointsFile(
    allocator: std.mem.Allocator,
    path: []const u8,
) !msgpack.Decoded(ReplayCheckpointsWire) {
    const io = std.Io.Threaded.global_single_threaded.io();
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited);
    defer allocator.free(bytes);

    return loadCheckpointsBytes(allocator, bytes);
}

fn loadCheckpointsBytes(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !msgpack.Decoded(ReplayCheckpointsWire) {
    var payload: []u8 = undefined;
    var payload_owned = false;
    if (replay_codec.isZstdPayload(bytes)) {
        payload = try replay_codec.inflateZstdPayload(allocator, bytes, max_checkpoints_payload_bytes);
        payload_owned = true;
    } else {
        if (bytes.len > max_checkpoints_payload_bytes) return error.PayloadTooLarge;
        payload = @constCast(bytes);
    }
    defer if (payload_owned) allocator.free(payload);

    var decoded = msgpack.decodeFromSlice(ReplayCheckpointsWire, allocator, payload) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidMsgpack,
    };
    errdefer decoded.deinit();

    if (decoded.value.version != checkpoints_format_version) return error.UnsupportedCheckpointsVersion;
    return decoded;
}

fn loadReplayBytes(
    allocator: std.mem.Allocator,
    replay_bytes: []const u8,
    parse_detail: ?*?[]u8,
) !replay_codec.Replay {
    var replay_payload_alloc: ?[]u8 = null;
    defer if (replay_payload_alloc) |buf| allocator.free(buf);
    const replay_payload: []const u8 = if (replay_codec.isZstdPayload(replay_bytes)) blk: {
        const inflated = try replay_codec.inflateZstdPayload(
            allocator,
            replay_bytes,
            replay_codec.max_replay_payload_bytes,
        );
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else if (replay_codec.isGzipPayload(replay_bytes)) blk: {
        const inflated = try replay_codec.inflateGzipPayload(
            allocator,
            replay_bytes,
            replay_codec.max_replay_payload_bytes,
        );
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else replay_bytes;

    return replay_codec.parseReplay(allocator, replay_payload) catch |err| {
        if (err == error.UnsupportedInputShape) {
            if (parse_detail) |detail| {
                detail.* = try replay_codec.replayInputShapeFailureDetail(allocator, replay_payload);
            }
        } else if (err == error.UnsupportedEventShape) {
            if (parse_detail) |detail| {
                detail.* = try replay_codec.replayEventShapeFailureDetail(allocator, replay_payload);
            }
        } else if (err == error.UnknownCommandKind) {
            if (parse_detail) |detail| {
                detail.* = try replay_codec.replayUnknownCommandFailureDetail(allocator, replay_payload);
            }
        }
        return err;
    };
}

fn traceRowForTick(rows: []const replay_runner.ReplayTickTrace, tick_index: i32) ?*const replay_runner.ReplayTickTrace {
    if (tick_index < 0) return null;
    const wanted: usize = @intCast(tick_index);
    for (rows) |*row| {
        if (row.tick_index == wanted) return row;
    }
    return null;
}

fn buildCheckpointFromTrace(
    allocator: std.mem.Allocator,
    row: *const replay_runner.ReplayTickTrace,
) !ReplayCheckpointWire {
    const trace_players = if (row.players.len > 0) row.players else &.{row.player_state};
    const players = try allocator.alloc(ReplayPlayerCheckpointWire, trace_players.len);
    errdefer allocator.free(players);
    for (trace_players, 0..) |player, idx| {
        players[idx] = .{
            .pos = .{
                .x = round4f64(player.pos.x),
                .y = round4f64(player.pos.y),
            },
            .health = round4f64(player.health),
            .weapon_id = @intFromEnum(player.weapon.weapon_id),
            .ammo = round4f64(player.weapon.ammo),
            .experience = player.experience,
            .level = player.level,
        };
    }

    const bonus_entries = try allocator.dupe(BonusTimerEntryWire, &.{
        .{ .key = "4", .value = bonusTimerMs(row.gameplay_state.bonuses.weapon_power_up) },
        .{ .key = "9", .value = bonusTimerMs(row.gameplay_state.bonuses.reflex_boost) },
        .{ .key = "2", .value = bonusTimerMs(row.gameplay_state.bonuses.energizer) },
        .{ .key = "6", .value = bonusTimerMs(row.gameplay_state.bonuses.double_experience) },
        .{ .key = "11", .value = bonusTimerMs(row.gameplay_state.bonuses.freeze) },
    });
    errdefer allocator.free(bonus_entries);

    const perk_choices = try buildPerkChoices(allocator, row);
    errdefer allocator.free(perk_choices);
    const all_player_nonzero_counts = try allocator.alloc([]const []const i32, trace_players.len);
    errdefer allocator.free(all_player_nonzero_counts);
    var built_player_counts: usize = 0;
    errdefer {
        for (all_player_nonzero_counts[0..built_player_counts]) |player_counts| {
            deinitPlayerNonzeroCounts(allocator, player_counts);
        }
    }
    for (trace_players, 0..) |player, idx| {
        all_player_nonzero_counts[idx] = try buildPlayerNonzeroCounts(allocator, player);
        built_player_counts += 1;
    }

    const events = try buildEventSummary(allocator, row);
    errdefer deinitOwnedEventSummary(allocator, events);
    const typo = try buildTypoSnapshot(allocator, row);
    errdefer if (typo) |snapshot| deinitOwnedTypoSnapshot(allocator, snapshot);

    return .{
        .tick_index = @intCast(row.tick_index),
        .rng_state = row.rng.rng_state,
        .elapsed_ms = @intCast(row.timing.elapsed_ms),
        .score_xp = row.summary.score_xp,
        .kills = row.summary.kills,
        .creature_count = @intCast(row.summary.creature_count),
        .perk_pending = row.summary.perk_pending,
        .players = players,
        .bonus_timers = .{ .entries = bonus_entries },
        .deaths = &.{},
        .perk = .{
            .pending_count = row.gameplay_state.perk_selection.pending_count,
            .choices_dirty = row.gameplay_state.perk_selection.choices_dirty,
            .choices = perk_choices,
            .player_nonzero_counts = all_player_nonzero_counts,
        },
        .events = events,
        .tutorial = buildTutorialSnapshot(row),
        .typo = typo,
    };
}

fn deinitOwnedCheckpoint(allocator: std.mem.Allocator, checkpoint: *ReplayCheckpointWire) void {
    allocator.free(checkpoint.players);
    allocator.free(checkpoint.bonus_timers.entries);
    allocator.free(checkpoint.perk.choices);
    for (checkpoint.perk.player_nonzero_counts) |player_counts| {
        deinitPlayerNonzeroCounts(allocator, player_counts);
    }
    allocator.free(checkpoint.perk.player_nonzero_counts);
    deinitOwnedEventSummary(allocator, checkpoint.events);
    if (checkpoint.typo) |snapshot| deinitOwnedTypoSnapshot(allocator, snapshot);
}

fn deinitOwnedEventSummary(allocator: std.mem.Allocator, events: ReplayEventSummaryWire) void {
    for (events.sfx_head) |entry| allocator.free(entry);
    allocator.free(events.sfx_head);
    allocator.free(events.hit_head);
}

fn deinitOwnedTypoSnapshot(allocator: std.mem.Allocator, snapshot: ReplayTypoSnapshotWire) void {
    allocator.free(snapshot.active_names);
}

fn buildPerkChoices(
    allocator: std.mem.Allocator,
    row: *const replay_runner.ReplayTickTrace,
) ![]const i32 {
    const choices = row.gameplay_state.perk_selection.choices;
    const visible_count = @min(row.gameplay_state.perk_selection.choice_count, choices.len);
    const out = try allocator.alloc(i32, visible_count);
    for (choices[0..visible_count], 0..) |choice, idx| {
        out[idx] = @intFromEnum(choice);
    }
    return out;
}

fn buildPlayerNonzeroCounts(
    allocator: std.mem.Allocator,
    player: state_mod.PlayerState,
) ![]const []const i32 {
    var pairs: std.ArrayList([]const i32) = .empty;
    errdefer {
        for (pairs.items) |pair| allocator.free(pair);
        pairs.deinit(allocator);
    }

    inline for (std.meta.fields(game_ids.PerkId)) |field| {
        const perk_id: game_ids.PerkId = @enumFromInt(field.value);
        const count = player.perk_counts.get(perk_id);
        if (count != 0) {
            const pair = try allocator.alloc(i32, 2);
            pair[0] = @intCast(field.value);
            pair[1] = count;
            try pairs.append(allocator, pair);
        }
    }

    return pairs.toOwnedSlice(allocator);
}

fn deinitPlayerNonzeroCounts(allocator: std.mem.Allocator, pairs: []const []const i32) void {
    for (pairs) |pair| allocator.free(pair);
    allocator.free(pairs);
}

fn buildEventSummary(
    allocator: std.mem.Allocator,
    row: *const replay_runner.ReplayTickTrace,
) !ReplayEventSummaryWire {
    const sfx_events = row.sfx_events.constSlice();
    const initial_reload_sfx = initialReloadSfxKey(row);
    const sfx_count = sfx_events.len + if (initial_reload_sfx != null) @as(usize, 1) else 0;
    const head_len = @min(sfx_count, 4);
    const sfx_head = try allocator.alloc([]const u8, head_len);
    errdefer allocator.free(sfx_head);
    var built: usize = 0;
    errdefer {
        for (sfx_head[0..built]) |entry| allocator.free(entry);
    }

    if (initial_reload_sfx) |key| {
        if (built < head_len) {
            sfx_head[built] = try allocator.dupe(u8, key);
            built += 1;
        }
    }
    for (sfx_events[0..@min(sfx_events.len, head_len - built)]) |sfx_id| {
        sfx_head[built] = try std.fmt.allocPrint(allocator, "sfx_{s}", .{@tagName(sfx_id)});
        built += 1;
    }

    return .{
        .hit_count = 0,
        .pickup_count = 0,
        .sfx_count = @intCast(sfx_count),
        .sfx_head = sfx_head,
        .hit_head = try allocator.alloc(ReplayHitSummaryEntryWire, 0),
    };
}

fn initialReloadSfxKey(row: *const replay_runner.ReplayTickTrace) ?[]const u8 {
    if (row.tick_index != 0) return null;
    return switch (row.gameplay_state.game_mode) {
        .quests => "sfx_pistol_reload",
        .rush => "sfx_autorifle_reload",
        .typo => "sfx_shotgun_reload",
        else => null,
    };
}

fn buildTutorialSnapshot(row: *const replay_runner.ReplayTickTrace) ?ReplayTutorialSnapshotWire {
    if (row.gameplay_state.game_mode != .tutorial) return null;
    const tutorial = row.gameplay_state.tutorial;
    const overlay = row.gameplay_state.tutorial_overlay;
    return .{
        .stage_index = tutorial.stage_index,
        .stage_timer_ms = tutorial.stage_timer_ms,
        .stage_transition_timer_ms = tutorial.stage_transition_timer_ms,
        .hint_index = tutorial.hint_index,
        .hint_alpha = tutorial.hint_alpha,
        .hint_fade_in = tutorial.hint_fade_in,
        .repeat_spawn_count = tutorial.repeat_spawn_count,
        .hint_bonus_creature_ref = if (tutorial.hint_bonus_creature_ref) |idx| @intCast(idx) else null,
        .prompt_text = tutorial_runtime.promptText(overlay.prompt_stage_index),
        .prompt_alpha = overlay.prompt_alpha,
        .hint_text = tutorial_runtime.hintText(overlay.hint_index, tutorial.preserve_bugs),
        .hint_alpha_overlay = overlay.hint_alpha,
    };
}

fn buildTypoSnapshot(
    allocator: std.mem.Allocator,
    row: *const replay_runner.ReplayTickTrace,
) !?ReplayTypoSnapshotWire {
    if (row.gameplay_state.game_mode != .typo) return null;
    var active_names: std.ArrayList(ReplayTypoNameEntryWire) = .empty;
    errdefer active_names.deinit(allocator);
    for (row.entities.creatures) |creature| {
        const name = row.gameplay_state.typo.names.nameSlice(creature.index);
        if (name.len == 0) continue;
        try active_names.append(allocator, .{
            .creature_index = @intCast(creature.index),
            .name = name,
        });
    }
    return .{
        .input_text = row.gameplay_state.typo.typing.slice(),
        .submit_count = row.gameplay_state.typo.typing.submit_count,
        .match_count = row.gameplay_state.typo.typing.match_count,
        .spawn_cooldown_ms = row.gameplay_state.typo.spawn_cooldown_ms,
        .active_names = try active_names.toOwnedSlice(allocator),
    };
}

fn bonusTimerMs(value: f32) i32 {
    if (!(value > 0.0)) return 0;
    return @intFromFloat(@floor(value * 1000.0));
}

fn round4f64(value: f32) f64 {
    const scaled = @round(@as(f64, @floatCast(value)) * 10000.0);
    return scaled / 10000.0;
}

fn compareCheckpoints(
    expected: []const ReplayCheckpointWire,
    actual: []const ReplayCheckpointWire,
) DiffResult {
    var first_rng_only_tick: ?i32 = null;
    var checked_count: usize = 0;

    for (expected) |*exp| {
        checked_count += 1;
        const act = checkpointForTick(actual, exp.tick_index) orelse {
            return .{
                .ok = false,
                .checked_count = checked_count,
                .first_rng_only_tick = first_rng_only_tick,
                .failure = .{
                    .kind = .missing_checkpoint,
                    .tick_index = exp.tick_index,
                    .expected = exp,
                },
            };
        };

        if (checkpointEqual(exp, act, true)) continue;
        if (checkpointEqual(exp, act, false)) {
            if (first_rng_only_tick == null) first_rng_only_tick = exp.tick_index;
            continue;
        }

        return .{
            .ok = false,
            .checked_count = checked_count,
            .first_rng_only_tick = first_rng_only_tick,
            .failure = .{
                .kind = .state_mismatch,
                .tick_index = exp.tick_index,
                .expected = exp,
                .actual = act,
            },
        };
    }

    return .{
        .ok = true,
        .checked_count = checked_count,
        .first_rng_only_tick = first_rng_only_tick,
    };
}

fn checkpointForTick(checkpoints: []const ReplayCheckpointWire, tick_index: i32) ?*const ReplayCheckpointWire {
    for (checkpoints) |*checkpoint| {
        if (checkpoint.tick_index == tick_index) return checkpoint;
    }
    return null;
}

fn checkpointEqual(a: *const ReplayCheckpointWire, b: *const ReplayCheckpointWire, compare_rng: bool) bool {
    if (a.tick_index != b.tick_index) return false;
    if (compare_rng and a.rng_state != b.rng_state) return false;
    if (a.elapsed_ms != b.elapsed_ms) return false;
    if (a.score_xp != b.score_xp) return false;
    if (a.kills != b.kills) return false;
    if (a.creature_count != b.creature_count) return false;
    if (a.perk_pending != b.perk_pending) return false;
    if (!playersEqual(a.players, b.players)) return false;
    if (!bonusTimersEqual(a.bonus_timers, b.bonus_timers)) return false;
    if (!deathsEqual(a.deaths, b.deaths)) return false;
    if (!perksEqual(a.perk, b.perk)) return false;
    if (!eventsEqual(a.events, b.events)) return false;
    if (!tutorialsEqual(a.tutorial, b.tutorial)) return false;
    if (!typosEqual(a.typo, b.typo)) return false;
    return true;
}

fn playersEqual(a: []const ReplayPlayerCheckpointWire, b: []const ReplayPlayerCheckpointWire) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (left.pos.x != right.pos.x or left.pos.y != right.pos.y) return false;
        if (left.health != right.health) return false;
        if (left.weapon_id != right.weapon_id) return false;
        if (left.ammo != right.ammo) return false;
        if (left.experience != right.experience) return false;
        if (left.level != right.level) return false;
    }
    return true;
}

fn bonusTimersEqual(a: BonusTimersWire, b: BonusTimersWire) bool {
    if (a.entries.len != b.entries.len) return false;
    for (a.entries) |entry| {
        const other = bonusTimerValue(b, entry.key) orelse return false;
        if (entry.value != other) return false;
    }
    return true;
}

fn bonusTimerValue(timers: BonusTimersWire, key: []const u8) ?i32 {
    for (timers.entries) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return entry.value;
    }
    return null;
}

fn deathsEqual(a: []const ReplayDeathLedgerEntryWire, b: []const ReplayDeathLedgerEntryWire) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (left.creature_index != right.creature_index) return false;
        if (left.type_id != right.type_id) return false;
        if (left.reward_value != right.reward_value) return false;
        if (left.xp_awarded != right.xp_awarded) return false;
        if (left.owner_id != right.owner_id) return false;
    }
    return true;
}

fn perksEqual(a: ReplayPerkSnapshotWire, b: ReplayPerkSnapshotWire) bool {
    if (a.pending_count != b.pending_count) return false;
    if (a.choices_dirty != b.choices_dirty) return false;
    if (!std.mem.eql(i32, a.choices, b.choices)) return false;
    if (a.player_nonzero_counts.len != b.player_nonzero_counts.len) return false;
    for (a.player_nonzero_counts, b.player_nonzero_counts) |left_player, right_player| {
        if (left_player.len != right_player.len) return false;
        for (left_player, right_player) |left_pair, right_pair| {
            if (!std.mem.eql(i32, left_pair, right_pair)) return false;
        }
    }
    return true;
}

fn eventsEqual(a: ReplayEventSummaryWire, b: ReplayEventSummaryWire) bool {
    if (a.hit_count != b.hit_count) return false;
    if (a.pickup_count != b.pickup_count) return false;
    if (a.sfx_count != b.sfx_count) return false;
    if (a.hit_head.len != 0 and b.hit_head.len != 0 and !hitHeadSlicesEqual(a.hit_head, b.hit_head)) return false;
    return stringSlicesEqual(a.sfx_head, b.sfx_head);
}

fn hitHeadSlicesEqual(a: []const ReplayHitSummaryEntryWire, b: []const ReplayHitSummaryEntryWire) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (left.type_id != right.type_id) return false;
        if (!vec2Equal(left.origin, right.origin)) return false;
        if (!vec2Equal(left.hit, right.hit)) return false;
        if (!vec2Equal(left.target, right.target)) return false;
    }
    return true;
}

fn vec2Equal(a: Vec2Wire, b: Vec2Wire) bool {
    return a.x == b.x and a.y == b.y;
}

fn tutorialsEqual(a: ?ReplayTutorialSnapshotWire, b: ?ReplayTutorialSnapshotWire) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    const left = a.?;
    const right = b.?;
    if (left.stage_index != right.stage_index) return false;
    if (left.stage_timer_ms != right.stage_timer_ms) return false;
    if (left.stage_transition_timer_ms != right.stage_transition_timer_ms) return false;
    if (left.hint_index != right.hint_index) return false;
    if (left.hint_alpha != right.hint_alpha) return false;
    if (left.hint_fade_in != right.hint_fade_in) return false;
    if (left.repeat_spawn_count != right.repeat_spawn_count) return false;
    if (left.hint_bonus_creature_ref != right.hint_bonus_creature_ref) return false;
    if (!std.mem.eql(u8, left.prompt_text, right.prompt_text)) return false;
    if (left.prompt_alpha != right.prompt_alpha) return false;
    if (!std.mem.eql(u8, left.hint_text, right.hint_text)) return false;
    if (left.hint_alpha_overlay != right.hint_alpha_overlay) return false;
    return true;
}

fn typosEqual(a: ?ReplayTypoSnapshotWire, b: ?ReplayTypoSnapshotWire) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    const left = a.?;
    const right = b.?;
    if (!std.mem.eql(u8, left.input_text, right.input_text)) return false;
    if (left.submit_count != right.submit_count) return false;
    if (left.match_count != right.match_count) return false;
    if (left.spawn_cooldown_ms != right.spawn_cooldown_ms) return false;
    if (left.active_names.len != right.active_names.len) return false;
    for (left.active_names, right.active_names) |left_name, right_name| {
        if (left_name.creature_index != right_name.creature_index) return false;
        if (!std.mem.eql(u8, left_name.name, right_name.name)) return false;
    }
    return true;
}

fn stringSlicesEqual(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (!std.mem.eql(u8, left, right)) return false;
    }
    return true;
}

fn buildMismatchOutput(
    allocator: std.mem.Allocator,
    diff: DiffResult,
) !CommandOutput {
    const failure = diff.failure.?;
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    const writer = &stderr_buf.writer;

    switch (failure.kind) {
        .missing_checkpoint => {
            try writer.print("checkpoint missing at tick={d}\n", .{failure.tick_index});
        },
        .state_mismatch => {
            const exp = failure.expected;
            const act = failure.actual.?;
            try writer.print("checkpoint mismatch at tick={d}\n", .{failure.tick_index});
            try writeFirstStateMismatch(writer, exp, act);
            try writer.print("  rng_state expected={d} actual={d}\n", .{ exp.rng_state, act.rng_state });
            try writer.print("  score_xp expected={d} actual={d}\n", .{ exp.score_xp, act.score_xp });
            try writer.print("  kills expected={d} actual={d}\n", .{ exp.kills, act.kills });
            try writer.print("  creature_count expected={d} actual={d}\n", .{ exp.creature_count, act.creature_count });
            try writer.print("  perk_pending expected={d} actual={d}\n", .{ exp.perk_pending, act.perk_pending });
            try writer.print("  deaths expected={d} actual={d}\n", .{ exp.deaths.len, act.deaths.len });
            if (exp.deaths.len > 0 or act.deaths.len > 0) {
                try writer.writeAll("  first death expected=");
                try writeFirstDeathSummary(writer, exp.deaths);
                try writer.writeAll(" actual=");
                try writeFirstDeathSummary(writer, act.deaths);
                try writer.writeAll("\n");
            }
            if (exp.events.hit_count >= 0) {
                try writer.print(
                    "  events expected=(hits={d}, pickups={d}, sfx={d}, head=",
                    .{ exp.events.hit_count, exp.events.pickup_count, exp.events.sfx_count },
                );
                try writeStringSliceSummary(writer, exp.events.sfx_head);
                try writer.print(
                    ") actual=(hits={d}, pickups={d}, sfx={d}, head=",
                    .{ act.events.hit_count, act.events.pickup_count, act.events.sfx_count },
                );
                try writeStringSliceSummary(writer, act.events.sfx_head);
                try writer.writeAll(")\n");
            }
            if (!perksEqual(exp.perk, act.perk)) {
                try writer.print(
                    "  perk snapshot differs (expected pending={d} choices={any}, actual pending={d} choices={any})\n",
                    .{ exp.perk.pending_count, exp.perk.choices, act.perk.pending_count, act.perk.choices },
                );
            }
        },
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

fn writeFirstStateMismatch(
    writer: anytype,
    expected: *const ReplayCheckpointWire,
    actual: *const ReplayCheckpointWire,
) !void {
    if (expected.tick_index != actual.tick_index) {
        try writer.print("  first state diff: tick_index expected={d} actual={d}\n", .{ expected.tick_index, actual.tick_index });
        return;
    }
    if (expected.elapsed_ms != actual.elapsed_ms) {
        try writer.print("  first state diff: elapsed_ms expected={d} actual={d}\n", .{ expected.elapsed_ms, actual.elapsed_ms });
        return;
    }
    if (expected.score_xp != actual.score_xp) {
        try writer.print("  first state diff: score_xp expected={d} actual={d}\n", .{ expected.score_xp, actual.score_xp });
        return;
    }
    if (expected.kills != actual.kills) {
        try writer.print("  first state diff: kills expected={d} actual={d}\n", .{ expected.kills, actual.kills });
        return;
    }
    if (expected.creature_count != actual.creature_count) {
        try writer.print("  first state diff: creature_count expected={d} actual={d}\n", .{ expected.creature_count, actual.creature_count });
        return;
    }
    if (expected.perk_pending != actual.perk_pending) {
        try writer.print("  first state diff: perk_pending expected={d} actual={d}\n", .{ expected.perk_pending, actual.perk_pending });
        return;
    }
    if (try writeFirstPlayerMismatch(writer, expected.players, actual.players)) return;
    if (try writeFirstBonusTimerMismatch(writer, expected.bonus_timers, actual.bonus_timers)) return;
    if (try writeFirstDeathMismatch(writer, expected.deaths, actual.deaths)) return;
    if (try writeFirstPerkMismatch(writer, expected.perk, actual.perk)) return;
    if (try writeFirstEventMismatch(writer, expected.events, actual.events)) return;
    if (try writeFirstTutorialMismatch(writer, expected.tutorial, actual.tutorial)) return;
    if (try writeFirstTypoMismatch(writer, expected.typo, actual.typo)) return;
    try writer.writeAll("  first state diff: checkpoint payload differs\n");
}

fn writeFirstPlayerMismatch(
    writer: anytype,
    expected: []const ReplayPlayerCheckpointWire,
    actual: []const ReplayPlayerCheckpointWire,
) !bool {
    if (expected.len != actual.len) {
        try writer.print("  first state diff: players._len expected={d} actual={d}\n", .{ expected.len, actual.len });
        return true;
    }
    for (expected, actual, 0..) |exp, act, idx| {
        if (exp.pos.x != act.pos.x) {
            try writer.print("  first state diff: players[{d}].pos.x expected={d} actual={d}\n", .{ idx, exp.pos.x, act.pos.x });
            return true;
        }
        if (exp.pos.y != act.pos.y) {
            try writer.print("  first state diff: players[{d}].pos.y expected={d} actual={d}\n", .{ idx, exp.pos.y, act.pos.y });
            return true;
        }
        if (exp.health != act.health) {
            try writer.print("  first state diff: players[{d}].health expected={d} actual={d}\n", .{ idx, exp.health, act.health });
            return true;
        }
        if (exp.weapon_id != act.weapon_id) {
            try writer.print("  first state diff: players[{d}].weapon_id expected={d} actual={d}\n", .{ idx, exp.weapon_id, act.weapon_id });
            return true;
        }
        if (exp.ammo != act.ammo) {
            try writer.print("  first state diff: players[{d}].ammo expected={d} actual={d}\n", .{ idx, exp.ammo, act.ammo });
            return true;
        }
        if (exp.experience != act.experience) {
            try writer.print("  first state diff: players[{d}].experience expected={d} actual={d}\n", .{ idx, exp.experience, act.experience });
            return true;
        }
        if (exp.level != act.level) {
            try writer.print("  first state diff: players[{d}].level expected={d} actual={d}\n", .{ idx, exp.level, act.level });
            return true;
        }
    }
    return false;
}

fn writeFirstBonusTimerMismatch(
    writer: anytype,
    expected: BonusTimersWire,
    actual: BonusTimersWire,
) !bool {
    if (expected.entries.len != actual.entries.len) {
        try writer.print("  first state diff: bonus_timers._len expected={d} actual={d}\n", .{ expected.entries.len, actual.entries.len });
        return true;
    }
    for (expected.entries) |entry| {
        const actual_value = bonusTimerValue(actual, entry.key) orelse {
            try writer.print("  first state diff: bonus_timers[{s}] expected={d} actual=<missing>\n", .{ entry.key, entry.value });
            return true;
        };
        if (entry.value != actual_value) {
            try writer.print("  first state diff: bonus_timers[{s}] expected={d} actual={d}\n", .{ entry.key, entry.value, actual_value });
            return true;
        }
    }
    return false;
}

fn writeFirstDeathMismatch(
    writer: anytype,
    expected: []const ReplayDeathLedgerEntryWire,
    actual: []const ReplayDeathLedgerEntryWire,
) !bool {
    if (expected.len != actual.len) {
        try writer.print("  first state diff: deaths._len expected={d} actual={d}\n", .{ expected.len, actual.len });
        return true;
    }
    for (expected, actual, 0..) |exp, act, idx| {
        if (exp.creature_index != act.creature_index) {
            try writer.print("  first state diff: deaths[{d}].creature_index expected={d} actual={d}\n", .{ idx, exp.creature_index, act.creature_index });
            return true;
        }
        if (exp.type_id != act.type_id) {
            try writer.print("  first state diff: deaths[{d}].type_id expected={d} actual={d}\n", .{ idx, exp.type_id, act.type_id });
            return true;
        }
        if (exp.reward_value != act.reward_value) {
            try writer.print("  first state diff: deaths[{d}].reward_value expected={d} actual={d}\n", .{ idx, exp.reward_value, act.reward_value });
            return true;
        }
        if (exp.xp_awarded != act.xp_awarded) {
            try writer.print("  first state diff: deaths[{d}].xp_awarded expected={d} actual={d}\n", .{ idx, exp.xp_awarded, act.xp_awarded });
            return true;
        }
        if (exp.owner_id != act.owner_id) {
            try writer.print("  first state diff: deaths[{d}].owner_id expected={d} actual={d}\n", .{ idx, exp.owner_id, act.owner_id });
            return true;
        }
    }
    return false;
}

fn writeFirstDeathSummary(
    writer: anytype,
    deaths: []const ReplayDeathLedgerEntryWire,
) !void {
    if (deaths.len == 0) {
        try writer.writeAll("[]");
        return;
    }

    const death = deaths[0];
    try writer.print(
        "[ReplayDeathLedgerEntry(creature_index={d}, type_id={d}, reward_value={d}, xp_awarded={d}, owner_id={d})]",
        .{ death.creature_index, death.type_id, death.reward_value, death.xp_awarded, death.owner_id },
    );
}

fn writeFirstPerkMismatch(
    writer: anytype,
    expected: ReplayPerkSnapshotWire,
    actual: ReplayPerkSnapshotWire,
) !bool {
    if (expected.pending_count != actual.pending_count) {
        try writer.print("  first state diff: perk.pending_count expected={d} actual={d}\n", .{ expected.pending_count, actual.pending_count });
        return true;
    }
    if (expected.choices_dirty != actual.choices_dirty) {
        try writer.print("  first state diff: perk.choices_dirty expected={} actual={}\n", .{ expected.choices_dirty, actual.choices_dirty });
        return true;
    }
    if (try writeFirstI32SliceMismatch(writer, "perk.choices", expected.choices, actual.choices)) return true;
    if (expected.player_nonzero_counts.len != actual.player_nonzero_counts.len) {
        try writer.print("  first state diff: perk.player_nonzero_counts._len expected={d} actual={d}\n", .{ expected.player_nonzero_counts.len, actual.player_nonzero_counts.len });
        return true;
    }
    for (expected.player_nonzero_counts, actual.player_nonzero_counts, 0..) |exp_player, act_player, player_idx| {
        if (exp_player.len != act_player.len) {
            try writer.print("  first state diff: perk.player_nonzero_counts[{d}]._len expected={d} actual={d}\n", .{ player_idx, exp_player.len, act_player.len });
            return true;
        }
        for (exp_player, act_player, 0..) |exp_pair, act_pair, pair_idx| {
            if (exp_pair.len != act_pair.len) {
                try writer.print("  first state diff: perk.player_nonzero_counts[{d}][{d}]._len expected={d} actual={d}\n", .{ player_idx, pair_idx, exp_pair.len, act_pair.len });
                return true;
            }
            for (exp_pair, act_pair, 0..) |exp_value, act_value, value_idx| {
                if (exp_value != act_value) {
                    try writer.print(
                        "  first state diff: perk.player_nonzero_counts[{d}][{d}][{d}] expected={d} actual={d}\n",
                        .{ player_idx, pair_idx, value_idx, exp_value, act_value },
                    );
                    return true;
                }
            }
        }
    }
    return false;
}

fn writeFirstEventMismatch(
    writer: anytype,
    expected: ReplayEventSummaryWire,
    actual: ReplayEventSummaryWire,
) !bool {
    if (expected.hit_count != actual.hit_count) {
        try writer.print("  first state diff: events.hit_count expected={d} actual={d}\n", .{ expected.hit_count, actual.hit_count });
        return true;
    }
    if (expected.pickup_count != actual.pickup_count) {
        try writer.print("  first state diff: events.pickup_count expected={d} actual={d}\n", .{ expected.pickup_count, actual.pickup_count });
        return true;
    }
    if (expected.sfx_count != actual.sfx_count) {
        try writer.print("  first state diff: events.sfx_count expected={d} actual={d}\n", .{ expected.sfx_count, actual.sfx_count });
        return true;
    }
    if (try writeFirstStringSliceMismatch(writer, "events.sfx_head", expected.sfx_head, actual.sfx_head)) return true;
    if (expected.hit_head.len != 0 and actual.hit_head.len != 0 and !hitHeadSlicesEqual(expected.hit_head, actual.hit_head)) {
        try writer.print(
            "  first state diff: events.hit_head expected_len={d} actual_len={d}\n",
            .{ expected.hit_head.len, actual.hit_head.len },
        );
        return true;
    }
    return false;
}

fn writeFirstTutorialMismatch(
    writer: anytype,
    expected: ?ReplayTutorialSnapshotWire,
    actual: ?ReplayTutorialSnapshotWire,
) !bool {
    if (expected == null and actual == null) return false;
    if (expected == null or actual == null) {
        try writer.print("  first state diff: tutorial expected={s} actual={s}\n", .{ optionalPresence(expected), optionalPresence(actual) });
        return true;
    }
    const exp = expected.?;
    const act = actual.?;
    if (exp.stage_index != act.stage_index) {
        try writer.print("  first state diff: tutorial.stage_index expected={d} actual={d}\n", .{ exp.stage_index, act.stage_index });
        return true;
    }
    if (exp.stage_timer_ms != act.stage_timer_ms) {
        try writer.print("  first state diff: tutorial.stage_timer_ms expected={d} actual={d}\n", .{ exp.stage_timer_ms, act.stage_timer_ms });
        return true;
    }
    if (exp.stage_transition_timer_ms != act.stage_transition_timer_ms) {
        try writer.print("  first state diff: tutorial.stage_transition_timer_ms expected={d} actual={d}\n", .{ exp.stage_transition_timer_ms, act.stage_transition_timer_ms });
        return true;
    }
    if (exp.hint_index != act.hint_index) {
        try writer.print("  first state diff: tutorial.hint_index expected={d} actual={d}\n", .{ exp.hint_index, act.hint_index });
        return true;
    }
    if (exp.hint_alpha != act.hint_alpha) {
        try writer.print("  first state diff: tutorial.hint_alpha expected={d} actual={d}\n", .{ exp.hint_alpha, act.hint_alpha });
        return true;
    }
    if (exp.hint_fade_in != act.hint_fade_in) {
        try writer.print("  first state diff: tutorial.hint_fade_in expected={} actual={}\n", .{ exp.hint_fade_in, act.hint_fade_in });
        return true;
    }
    if (exp.repeat_spawn_count != act.repeat_spawn_count) {
        try writer.print("  first state diff: tutorial.repeat_spawn_count expected={d} actual={d}\n", .{ exp.repeat_spawn_count, act.repeat_spawn_count });
        return true;
    }
    if (exp.hint_bonus_creature_ref != act.hint_bonus_creature_ref) {
        try writer.print("  first state diff: tutorial.hint_bonus_creature_ref expected={?d} actual={?d}\n", .{ exp.hint_bonus_creature_ref, act.hint_bonus_creature_ref });
        return true;
    }
    if (!std.mem.eql(u8, exp.prompt_text, act.prompt_text)) {
        try writer.print("  first state diff: tutorial.prompt_text expected={s} actual={s}\n", .{ exp.prompt_text, act.prompt_text });
        return true;
    }
    if (exp.prompt_alpha != act.prompt_alpha) {
        try writer.print("  first state diff: tutorial.prompt_alpha expected={d} actual={d}\n", .{ exp.prompt_alpha, act.prompt_alpha });
        return true;
    }
    if (!std.mem.eql(u8, exp.hint_text, act.hint_text)) {
        try writer.print("  first state diff: tutorial.hint_text expected={s} actual={s}\n", .{ exp.hint_text, act.hint_text });
        return true;
    }
    if (exp.hint_alpha_overlay != act.hint_alpha_overlay) {
        try writer.print("  first state diff: tutorial.hint_alpha_overlay expected={d} actual={d}\n", .{ exp.hint_alpha_overlay, act.hint_alpha_overlay });
        return true;
    }
    return false;
}

fn writeFirstTypoMismatch(
    writer: anytype,
    expected: ?ReplayTypoSnapshotWire,
    actual: ?ReplayTypoSnapshotWire,
) !bool {
    if (expected == null and actual == null) return false;
    if (expected == null or actual == null) {
        try writer.print("  first state diff: typo expected={s} actual={s}\n", .{ optionalPresence(expected), optionalPresence(actual) });
        return true;
    }
    const exp = expected.?;
    const act = actual.?;
    if (!std.mem.eql(u8, exp.input_text, act.input_text)) {
        try writer.print("  first state diff: typo.input_text expected={s} actual={s}\n", .{ exp.input_text, act.input_text });
        return true;
    }
    if (exp.submit_count != act.submit_count) {
        try writer.print("  first state diff: typo.submit_count expected={d} actual={d}\n", .{ exp.submit_count, act.submit_count });
        return true;
    }
    if (exp.match_count != act.match_count) {
        try writer.print("  first state diff: typo.match_count expected={d} actual={d}\n", .{ exp.match_count, act.match_count });
        return true;
    }
    if (exp.spawn_cooldown_ms != act.spawn_cooldown_ms) {
        try writer.print("  first state diff: typo.spawn_cooldown_ms expected={d} actual={d}\n", .{ exp.spawn_cooldown_ms, act.spawn_cooldown_ms });
        return true;
    }
    if (exp.active_names.len != act.active_names.len) {
        try writer.print("  first state diff: typo.active_names._len expected={d} actual={d}\n", .{ exp.active_names.len, act.active_names.len });
        return true;
    }
    for (exp.active_names, act.active_names, 0..) |exp_name, act_name, idx| {
        if (exp_name.creature_index != act_name.creature_index) {
            try writer.print("  first state diff: typo.active_names[{d}].creature_index expected={d} actual={d}\n", .{ idx, exp_name.creature_index, act_name.creature_index });
            return true;
        }
        if (!std.mem.eql(u8, exp_name.name, act_name.name)) {
            try writer.print("  first state diff: typo.active_names[{d}].name expected={s} actual={s}\n", .{ idx, exp_name.name, act_name.name });
            return true;
        }
    }
    return false;
}

fn writeFirstI32SliceMismatch(
    writer: anytype,
    field: []const u8,
    expected: []const i32,
    actual: []const i32,
) !bool {
    if (expected.len != actual.len) {
        try writer.print("  first state diff: {s}._len expected={d} actual={d}\n", .{ field, expected.len, actual.len });
        return true;
    }
    for (expected, actual, 0..) |exp, act, idx| {
        if (exp != act) {
            try writer.print("  first state diff: {s}[{d}] expected={d} actual={d}\n", .{ field, idx, exp, act });
            return true;
        }
    }
    return false;
}

fn writeFirstStringSliceMismatch(
    writer: anytype,
    field: []const u8,
    expected: []const []const u8,
    actual: []const []const u8,
) !bool {
    if (expected.len != actual.len) {
        try writer.print("  first state diff: {s}._len expected={d} actual={d}\n", .{ field, expected.len, actual.len });
        return true;
    }
    for (expected, actual, 0..) |exp, act, idx| {
        if (!std.mem.eql(u8, exp, act)) {
            try writer.print("  first state diff: {s}[{d}] expected={s} actual={s}\n", .{ field, idx, exp, act });
            return true;
        }
    }
    return false;
}

fn writeStringSliceSummary(
    writer: anytype,
    values: []const []const u8,
) !void {
    try writer.writeAll("[");
    for (values, 0..) |value, idx| {
        if (idx > 0) try writer.writeAll(", ");
        try writer.print("'{s}'", .{value});
    }
    try writer.writeAll("]");
}

fn optionalPresence(value: anytype) []const u8 {
    return if (value == null) "null" else "present";
}

fn parseOutputFormat(raw: []const u8) ?OutputFormat {
    if (std.mem.eql(u8, raw, "human")) return .human;
    if (std.mem.eql(u8, raw, "json")) return .json;
    return null;
}

fn writeFileWithParents(path: []const u8, bytes: []const u8) !void {
    if (comptime builtin.os.tag == .freestanding) return error.UnsupportedTarget;
    const io = std.Io.Threaded.global_single_threaded.io();
    if (std.fs.path.dirname(path)) |dir| {
        if (dir.len > 0) try std.Io.Dir.cwd().createDirPath(io, dir);
    }
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes,
    });
}

fn buildFailedOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    try stderr_buf.writer.print("replay diff-checkpoints failed: {s}\n", .{detail});

    const stderr = try stderr_buf.toOwnedSlice();
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");
    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn buildInvalidArgsOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    try stderr_buf.writer.print("invalid replay diff-checkpoints args: {s}\n", .{detail});

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
    try stderr_buf.writer.print("invalid replay verify-checkpoints args: {s}\n", .{detail});

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
    try stderr_buf.writer.print("replay verification failed: {s}\n", .{detail});

    const stderr = try stderr_buf.toOwnedSlice();
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");
    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn checkpointFileLoadErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "checkpoints file not found",
        error.AccessDenied => "unable to read checkpoints file: access denied",
        error.InvalidMsgpack => "checkpoints payload is not valid msgpack wire format",
        error.InvalidZstdPayload => "unable to inflate checkpoints zstd payload",
        error.PayloadTooLarge => "checkpoints payload exceeds max decompressed size",
        error.UnsupportedCheckpointsVersion => "checkpoints format version is not supported",
        error.OutOfMemory => "native checkpoint decode ran out of memory",
        else => @errorName(err),
    };
}

fn replayFileLoadErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "replay file not found",
        error.AccessDenied => "unable to read replay file: access denied",
        error.FileTooBig, error.PayloadTooLarge => "replay payload exceeds max decompressed size",
        error.OutOfMemory => "native replay load ran out of memory",
        else => @errorName(err),
    };
}

fn replayLoadErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.InvalidMsgpack => "replay payload is not valid msgpack wire format",
        error.LegacyJsonPayload => "legacy JSON replay format is unsupported; regenerate the replay",
        error.InvalidHeaderValue => "replay header contains invalid values",
        error.InvalidClaimedStats => "replay header claimed_stats.shots_hit must be <= claimed_stats.shots_fired",
        error.MissingHeaderField => "replay header missing required fields",
        error.MissingQuestLevel => "quest replays require a valid header.quest_level",
        error.TypoMultiplayer => "Typ-o replays require player_count == 1",
        error.TutorialMultiplayer => "tutorial replays require player_count == 1",
        error.UnsupportedInputShape => "replay input rows are not in the canonical wire shape",
        error.UnsupportedEventShape => "replay events are not in the canonical wire shape",
        error.InvalidGzipPayload => "unable to inflate replay gzip payload",
        error.InvalidZstdPayload => "unable to inflate replay zstd payload",
        error.UnsupportedReplayFormatVersion => "replay format version is not supported",
        error.UnknownCommandKind => "replay events include an unknown command kind",
        error.UnsupportedBootstrapKind => "replay bootstrap kind is not supported",
        error.UnsupportedInputQuantization => "replay input quantization is not supported",
        error.BootstrapSeedMismatch => "replay bootstrap seed does not match canonical terrain bootstrap draws",
        error.PayloadTooLarge => "replay payload exceeds max decompressed size",
        error.OutOfMemory => "native replay load ran out of memory",
        else => @errorName(err),
    };
}

fn replayRunnerErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.OutOfMemory => "native replay run ran out of memory",
        error.InvalidHeaderValue => "native replay run received invalid header values",
        error.InvalidCaptureEnumValue => "replay capture includes an invalid enum value",
        error.UnsupportedGameMode => "native replay run only supports survival/rush/quest/typo/tutorial modes",
        error.UnsupportedPlayerCount => "native replay run only supports 1-4 player replays",
        error.UnsupportedInputQuantization => "native replay run only supports f32 quantization",
        error.UnsupportedEventOrdering => "replay events are not ordered in canonical tick order",
        error.UnsupportedEventKind => "replay events include kinds or values invalid for this mode",
        error.UnsupportedEventPlayerIndex => "replay events include an out-of-range player index",
        error.MissingRngCallerTag => "replay capture is missing required RNG caller tags",
        error.InvalidSpawnTemplate => "replay capture references an invalid spawn template",
        error.InvalidQuestSpawnTable => "replay capture references an invalid quest spawn table",
        else => @errorName(err),
    };
}

fn checkpointBuildErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.OutOfMemory => "native checkpoint comparison ran out of memory",
        else => @errorName(err),
    };
}

fn generalVerifyErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.OutOfMemory => "native checkpoint verification ran out of memory",
        else => @errorName(err),
    };
}

fn checkpointJsonOutErrorDetail(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "unable to write checkpoint JSON: access denied",
        error.OutOfMemory => "native checkpoint JSON output ran out of memory",
        error.UnsupportedTarget => "checkpoint JSON output file is unavailable on this target",
        else => @errorName(err),
    };
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

fn buildCheckpointsNotFoundOutput(
    allocator: std.mem.Allocator,
    path: []const u8,
) !CommandOutput {
    var stderr_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_buf.deinit();
    try stderr_buf.writer.print("checkpoints file not found: {s}\n", .{path});

    const stderr = try stderr_buf.toOwnedSlice();
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");
    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn resolveReplayPath(
    allocator: std.mem.Allocator,
    replay_file: []const u8,
    base_dir: []const u8,
) !ReplayResolution {
    const primary = try allocator.dupe(u8, replay_file);
    errdefer allocator.free(primary);
    if (fileExists(primary)) {
        return .{
            .resolved_path = try allocator.dupe(u8, primary),
            .tried_primary = primary,
            .tried_secondary = null,
            .exists = true,
        };
    }

    if (!std.fs.path.isAbsolute(replay_file) and std.fs.path.dirname(replay_file) == null) {
        const secondary = try std.fs.path.join(allocator, &.{ base_dir, "replays", replay_file });
        errdefer allocator.free(secondary);
        if (fileExists(secondary)) {
            return .{
                .resolved_path = try allocator.dupe(u8, secondary),
                .tried_primary = primary,
                .tried_secondary = secondary,
                .exists = true,
            };
        }
        return .{
            .resolved_path = try allocator.dupe(u8, replay_file),
            .tried_primary = primary,
            .tried_secondary = secondary,
            .exists = false,
        };
    }

    return .{
        .resolved_path = try allocator.dupe(u8, replay_file),
        .tried_primary = primary,
        .tried_secondary = null,
        .exists = false,
    };
}

fn fileExists(path: []const u8) bool {
    const io = std.Io.Threaded.global_single_threaded.io();
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn defaultRuntimeDir(allocator: std.mem.Allocator) ![]u8 {
    return (try runtime_paths.defaultRuntimeDir(allocator)) orelse try allocator.dupe(u8, ".");
}

fn defaultCheckpointsPath(allocator: std.mem.Allocator, replay_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}.chk", .{replay_path});
}

test "compare checkpoints permits rng-only divergence" {
    const expected = testCheckpoint();
    var actual = testCheckpoint();
    actual.rng_state = 0xFEED;

    const diff = compareCheckpoints(&.{expected}, &.{actual});

    try std.testing.expect(diff.ok);
    try std.testing.expectEqual(@as(?i32, 1), diff.first_rng_only_tick);
}

test "compare checkpoints reports first state mismatch" {
    const expected = testCheckpoint();
    var actual = testCheckpoint();
    actual.score_xp += 1;

    const diff = compareCheckpoints(&.{expected}, &.{actual});

    try std.testing.expect(!diff.ok);
    try std.testing.expectEqual(@as(usize, 1), diff.checked_count);
    try std.testing.expectEqual(@as(i32, 1), diff.failure.?.tick_index);
}

test "checkpoint mismatch output reports first player field difference" {
    const allocator = std.testing.allocator;
    const expected = testCheckpoint();
    var actual = testCheckpoint();
    var actual_players = [_]ReplayPlayerCheckpointWire{actual.players[0]};
    actual_players[0].health = 99.5;
    actual.players = actual_players[0..];
    const diff: DiffResult = .{
        .ok = false,
        .checked_count = 1,
        .failure = .{
            .kind = .state_mismatch,
            .tick_index = expected.tick_index,
            .expected = &expected,
            .actual = &actual,
        },
    };

    const output = try buildMismatchOutput(allocator, diff);
    defer allocator.free(output.stdout);
    defer allocator.free(output.stderr);

    try std.testing.expectEqual(@as(u8, 1), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "first state diff: players[0].health expected=100 actual=99.5") != null);
}

test "checkpoint mismatch output reports first event field difference" {
    const allocator = std.testing.allocator;
    const expected = testCheckpoint();
    var actual = testCheckpoint();
    actual.events.sfx_count = 1;
    const diff: DiffResult = .{
        .ok = false,
        .checked_count = 1,
        .failure = .{
            .kind = .state_mismatch,
            .tick_index = expected.tick_index,
            .expected = &expected,
            .actual = &actual,
        },
    };

    const output = try buildMismatchOutput(allocator, diff);
    defer allocator.free(output.stdout);
    defer allocator.free(output.stderr);

    try std.testing.expectEqual(@as(u8, 1), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "first state diff: events.sfx_count expected=0 actual=1") != null);
}

test "byte checkpoint diff accepts msgpack payloads" {
    const allocator = std.testing.allocator;
    const checkpoint = testCheckpoint();
    const payload = try encodeTestCheckpoints(allocator, &.{checkpoint});
    defer allocator.free(payload);

    const output = try runReplayDiffCheckpointsBytes(allocator, payload, payload);
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expectEqualStrings("", output.stderr);
    try std.testing.expectEqualStrings("ok: 1 checkpoints match\n", output.stdout);

    const json_output = try runReplayDiffCheckpointsBytesJson(
        allocator,
        "<expected>",
        payload,
        "<actual>",
        payload,
    );
    defer json_output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), json_output.exit_code);
    try std.testing.expectEqualStrings("", json_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, json_output.stdout, "\"schema_version\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_output.stdout, "\"command\":\"diff-checkpoints\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_output.stdout, "\"expected\":\"<expected>\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_output.stdout, "\"actual\":\"<actual>\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_output.stdout, "\"checked_count\":1") != null);
}

test "byte checkpoint verify accepts replay and checkpoint payloads" {
    const allocator = std.testing.allocator;
    const replay_bytes = try replay_codec.buildSmokeTestReplayPayload(allocator);
    defer allocator.free(replay_bytes);

    var replay = try loadReplayBytes(allocator, replay_bytes, null);
    defer replay.deinit(allocator);

    var trace: std.ArrayList(replay_runner.ReplayTickTrace) = .empty;
    defer {
        replay_runner.deinitReplayTickTraceRows(allocator, trace.items);
        trace.deinit(allocator);
    }

    _ = try replay_runner.runReplayWithTrace(
        allocator,
        replay,
        &trace,
        .{ .max_ticks = 1 },
    );
    try std.testing.expect(trace.items.len > 0);

    var checkpoint = try buildCheckpointFromTrace(allocator, &trace.items[0]);
    defer deinitOwnedCheckpoint(allocator, &checkpoint);

    const checkpoints_payload = try encodeTestCheckpoints(allocator, &.{checkpoint});
    defer allocator.free(checkpoints_payload);

    const output = try runReplayVerifyCheckpointsBytes(
        allocator,
        replay_bytes,
        checkpoints_payload,
        1,
        false,
    );
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), output.exit_code);
    try std.testing.expectEqualStrings("", output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, output.stdout, "ok: 1 checkpoints match; ticks=1") != null);

    const traced_output = try runReplayVerifyCheckpointsBytes(
        allocator,
        replay_bytes,
        checkpoints_payload,
        1,
        true,
    );
    defer traced_output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), traced_output.exit_code);
    try std.testing.expectEqualStrings("", traced_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, traced_output.stdout, "ok: 1 checkpoints match; ticks=1") != null);

    const json_output = try runReplayVerifyCheckpointsBytesJson(
        allocator,
        "<wasm>",
        replay_bytes,
        "<checkpoints>",
        checkpoints_payload,
        1,
        true,
    );
    defer json_output.deinit(allocator);

    try std.testing.expectEqual(@as(u8, 0), json_output.exit_code);
    try std.testing.expectEqualStrings("", json_output.stderr);
    try std.testing.expect(std.mem.indexOf(u8, json_output.stdout, "\"schema_version\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_output.stdout, "\"command\":\"verify-checkpoints\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_output.stdout, "\"replay\":\"<wasm>\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_output.stdout, "\"checkpoints\":\"<checkpoints>\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_output.stdout, "\"checkpoint_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_output.stdout, "\"ticks\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_output.stdout, "\"trace_rng\":true") != null);
}

test "checkpoint verify parser reports runtime dir value requirement" {
    const parsed = parseVerifyArgs(&.{ "replay.crd", "--runtime-dir" });
    switch (parsed) {
        .invalid => |detail| try std.testing.expectEqualStrings("missing value for --base-dir/--runtime-dir", detail),
        .ok => return error.TestExpectedInvalidArgs,
    }

    const ok = parseVerifyArgs(&.{ "replay.crd", "--runtime-dir", "runtime" });
    switch (ok) {
        .ok => |request| try std.testing.expectEqualStrings("runtime", request.base_dir.?),
        .invalid => return error.TestExpectedOkArgs,
    }
}

test "checkpoint diff maps checkpoint load errors to user details" {
    try std.testing.expectEqualStrings(
        "checkpoints payload is not valid msgpack wire format",
        checkpointFileLoadErrorDetail(error.InvalidMsgpack),
    );
    try std.testing.expectEqualStrings(
        "checkpoints format version is not supported",
        checkpointFileLoadErrorDetail(error.UnsupportedCheckpointsVersion),
    );
    try std.testing.expectEqualStrings(
        "checkpoints payload exceeds max decompressed size",
        checkpointFileLoadErrorDetail(error.PayloadTooLarge),
    );
    try std.testing.expectEqualStrings(
        "FileBusy",
        checkpointFileLoadErrorDetail(error.FileBusy),
    );
}

test "checkpoint death entries default legacy owner id" {
    const allocator = std.testing.allocator;
    const LegacyDeathEntry = struct {
        creature_index: i32,
        type_id: i32,
        reward_value: f64,
        xp_awarded: i32,
    };
    const wire: LegacyDeathEntry = .{
        .creature_index = 5,
        .type_id = 2,
        .reward_value = 75.0,
        .xp_awarded = 10,
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    defer writer.deinit();
    try msgpack.encode(wire, &writer.writer);

    var decoded = try msgpack.decodeFromSlice(ReplayDeathLedgerEntryWire, allocator, writer.written());
    defer decoded.deinit();

    try std.testing.expectEqual(@as(i32, 5), decoded.value.creature_index);
    try std.testing.expectEqual(@as(i32, 2), decoded.value.type_id);
    try std.testing.expectEqual(@as(f64, 75.0), decoded.value.reward_value);
    try std.testing.expectEqual(@as(i32, 10), decoded.value.xp_awarded);
    try std.testing.expectEqual(@as(i32, -1), decoded.value.owner_id);
}

test "checkpoint verify maps replay load and runner errors to user details" {
    try std.testing.expectEqualStrings(
        "replay payload is not valid msgpack wire format",
        replayLoadErrorDetail(error.InvalidMsgpack),
    );
    try std.testing.expectEqualStrings(
        "replay payload exceeds max decompressed size",
        replayLoadErrorDetail(error.PayloadTooLarge),
    );
    try std.testing.expectEqualStrings(
        "replay events include an unknown command kind",
        replayLoadErrorDetail(error.UnknownCommandKind),
    );
    try std.testing.expectEqualStrings(
        "native replay run only supports survival/rush/quest/typo/tutorial modes",
        replayRunnerErrorDetail(error.UnsupportedGameMode),
    );
    try std.testing.expectEqualStrings(
        "replay events include an out-of-range player index",
        replayRunnerErrorDetail(error.UnsupportedEventPlayerIndex),
    );
    try std.testing.expectEqualStrings(
        "replay events include kinds or values invalid for this mode",
        replayRunnerErrorDetail(error.UnsupportedEventKind),
    );
    try std.testing.expectEqualStrings(
        "FileBusy",
        replayLoadErrorDetail(error.FileBusy),
    );
}

fn testCheckpoint() ReplayCheckpointWire {
    return .{
        .tick_index = 1,
        .rng_state = 0x1234,
        .elapsed_ms = 17,
        .score_xp = 42,
        .kills = 2,
        .creature_count = 3,
        .perk_pending = 0,
        .players = &.{.{
            .pos = .{ .x = 512.0, .y = 513.0 },
            .health = 100.0,
            .weapon_id = 1,
            .ammo = 10.0,
            .experience = 42,
            .level = 1,
        }},
        .bonus_timers = .{ .entries = &.{
            .{ .key = "1", .value = 0 },
            .{ .key = "3", .value = 0 },
        } },
        .deaths = &.{},
        .perk = .{
            .pending_count = 0,
            .choices_dirty = false,
            .choices = &.{},
            .player_nonzero_counts = &.{},
        },
        .events = .{
            .hit_count = 0,
            .pickup_count = 0,
            .sfx_count = 0,
            .sfx_head = &.{},
            .hit_head = &.{},
        },
        .tutorial = null,
        .typo = null,
    };
}

fn encodeTestCheckpoints(
    allocator: std.mem.Allocator,
    checkpoints: []const ReplayCheckpointWire,
) ![]u8 {
    const payload: ReplayCheckpointsWire = .{
        .version = checkpoints_format_version,
        .sample_rate = 1,
        .checkpoints = checkpoints,
    };
    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try msgpack.encode(payload, &writer.writer);
    return writer.toOwnedSlice();
}
