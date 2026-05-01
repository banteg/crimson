const std = @import("std");
const msgpack = @import("msgpack");

const game_ids = @import("game_ids.zig");
const replay_codec = @import("replay_codec.zig");
const replay_runner = @import("runtime/replay_runner.zig");
const runtime_paths = @import("runtime_paths.zig");
const state_mod = @import("runtime/state.zig");
const verify_native = @import("verify_native.zig");

const checkpoints_format_version: i32 = 4;
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
    owner_id: i32,
};

const ReplayPerkSnapshotWire = struct {
    pending_count: i32,
    choices_dirty: bool,
    choices: []const i32,
    player_nonzero_counts: []const []const []const i32,
};

const ReplayEventSummaryWire = struct {
    hit_count: i32,
    pickup_count: i32,
    sfx_count: i32,
    sfx_head: []const []const u8,
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

const DiffRequest = struct {
    expected_file: []const u8,
    actual_file: []const u8,
};

const VerifyCheckpointsRequest = struct {
    replay_file: []const u8,
    checkpoints_file: ?[]const u8 = null,
    base_dir: ?[]const u8 = null,
    max_ticks: ?usize = null,
    trace_rng: bool = false,
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

fn parseDiffArgs(args: []const []const u8) DiffParseOutcome {
    if (args.len != 2) return .{ .invalid = "expected <expected.chk> <actual.chk>" };
    if (std.mem.startsWith(u8, args[0], "-")) return .{ .invalid = "expected checkpoints file path, got option" };
    if (std.mem.startsWith(u8, args[1], "-")) return .{ .invalid = "expected actual checkpoints file path, got option" };
    return .{ .ok = .{
        .expected_file = args[0],
        .actual_file = args[1],
    } };
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
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --base-dir" };
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

    const diff = compareCheckpoints(expected.value.checkpoints, actual.value.checkpoints);
    if (!diff.ok) {
        return buildMismatchOutput(allocator, diff);
    }

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    try stdout_buf.writer.print("ok: {d} checkpoints match\n", .{expected.value.checkpoints.len});
    if (diff.first_rng_only_tick) |tick| {
        try stdout_buf.writer.print("first rng-only divergence tick={d}\n", .{tick});
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

    var replay_payload_alloc: ?[]u8 = null;
    defer if (replay_payload_alloc) |buf| allocator.free(buf);
    const replay_payload: []const u8 = if (replay_codec.isZstdPayload(replay_bytes)) blk: {
        const inflated = replay_codec.inflateZstdPayload(
            allocator,
            replay_bytes,
            replay_codec.max_replay_payload_bytes,
        ) catch |err| {
            return buildVerifyFailedOutput(allocator, replayLoadErrorDetail(err));
        };
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else if (replay_codec.isGzipPayload(replay_bytes)) blk: {
        const inflated = replay_codec.inflateGzipPayload(
            allocator,
            replay_bytes,
            replay_codec.max_replay_payload_bytes,
        ) catch |err| {
            return buildVerifyFailedOutput(allocator, replayLoadErrorDetail(err));
        };
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else replay_bytes;

    var replay = replay_codec.parseReplay(allocator, replay_payload) catch |err| {
        return buildVerifyFailedOutput(allocator, replayLoadErrorDetail(err));
    };
    defer replay.deinit(allocator);

    var trace: std.ArrayList(replay_runner.ReplayTickTrace) = .empty;
    defer {
        replay_runner.deinitReplayTickTraceRows(allocator, trace.items);
        trace.deinit(allocator);
    }

    const run = replay_runner.runReplayWithTrace(
        allocator,
        replay,
        &trace,
        .{ .max_ticks = request.max_ticks },
    ) catch |err| {
        return buildVerifyFailedOutput(allocator, replayRunnerErrorDetail(err));
    };

    var actual: std.ArrayList(ReplayCheckpointWire) = .empty;
    defer {
        for (actual.items) |*checkpoint| deinitOwnedCheckpoint(allocator, checkpoint);
        actual.deinit(allocator);
    }

    for (expected.value.checkpoints) |expected_checkpoint| {
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

    const diff = compareCheckpoints(expected.value.checkpoints, actual.items);
    if (!diff.ok) return buildMismatchOutput(allocator, diff);

    var stdout_buf: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_buf.deinit();
    try stdout_buf.writer.print(
        "ok: {d} checkpoints match; ticks={d} score_xp={d} kills={d}",
        .{ expected.value.checkpoints.len, run.ticks, run.player_experience, run.creature_kill_count },
    );
    if (diff.first_rng_only_tick) |tick| {
        try stdout_buf.writer.print("; rng-only drift starts at tick={d}", .{tick});
    }
    try stdout_buf.writer.writeByte('\n');

    const stdout = try stdout_buf.toOwnedSlice();
    errdefer allocator.free(stdout);
    const stderr = try allocator.dupe(u8, "");
    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 0,
    };
}

fn loadCheckpointsFile(
    allocator: std.mem.Allocator,
    path: []const u8,
) !msgpack.Decoded(ReplayCheckpointsWire) {
    const io = std.Io.Threaded.global_single_threaded.io();
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited);
    defer allocator.free(bytes);

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

fn traceRowForTick(rows: []const replay_runner.ReplayTickTrace, tick_index: i32) ?replay_runner.ReplayTickTrace {
    if (tick_index < 0) return null;
    const wanted: usize = @intCast(tick_index);
    for (rows) |row| {
        if (row.tick_index == wanted) return row;
    }
    return null;
}

fn buildCheckpointFromTrace(
    allocator: std.mem.Allocator,
    row: replay_runner.ReplayTickTrace,
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
        .events = buildEventSummary(row),
        .tutorial = null,
        .typo = null,
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
}

fn buildPerkChoices(
    allocator: std.mem.Allocator,
    row: replay_runner.ReplayTickTrace,
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

fn buildEventSummary(row: replay_runner.ReplayTickTrace) ReplayEventSummaryWire {
    const quest_tick0_reload_sfx = row.tick_index == 0 and
        row.gameplay_state.game_mode == .quests and
        row.player_state.weapon.weapon_id == .pistol;
    if (!quest_tick0_reload_sfx) {
        return .{
            .hit_count = 0,
            .pickup_count = 0,
            .sfx_count = 0,
            .sfx_head = &.{},
        };
    }
    return .{
        .hit_count = 0,
        .pickup_count = 0,
        .sfx_count = 1,
        .sfx_head = &.{"sfx_pistol_reload"},
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
    return stringSlicesEqual(a.sfx_head, b.sfx_head);
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
            try writer.print("  rng_state expected={d} actual={d}\n", .{ exp.rng_state, act.rng_state });
            try writer.print("  score_xp expected={d} actual={d}\n", .{ exp.score_xp, act.score_xp });
            try writer.print("  kills expected={d} actual={d}\n", .{ exp.kills, act.kills });
            try writer.print("  creature_count expected={d} actual={d}\n", .{ exp.creature_count, act.creature_count });
            try writer.print("  perk_pending expected={d} actual={d}\n", .{ exp.perk_pending, act.perk_pending });
            try writer.print("  deaths expected={d} actual={d}\n", .{ exp.deaths.len, act.deaths.len });
            if (exp.events.hit_count >= 0) {
                try writer.print(
                    "  events expected=(hits={d}, pickups={d}, sfx={d}) actual=(hits={d}, pickups={d}, sfx={d})\n",
                    .{ exp.events.hit_count, exp.events.pickup_count, exp.events.sfx_count, act.events.hit_count, act.events.pickup_count, act.events.sfx_count },
                );
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
        error.InvalidHeaderValue => "replay header contains invalid values",
        error.MissingHeaderField => "replay header missing required fields",
        error.UnsupportedInputShape => "replay input rows are not in the canonical wire shape",
        error.UnsupportedEventShape => "replay events are not in the canonical wire shape",
        error.InvalidGzipPayload => "unable to inflate replay gzip payload",
        error.InvalidZstdPayload => "unable to inflate replay zstd payload",
        error.UnsupportedReplayFormatVersion => "replay format version is not supported",
        error.UnsupportedEventKind => "replay events include kinds unsupported by the current native runtime",
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
        error.UnsupportedEventKind => "replay events include kinds unsupported for this mode",
        error.UnsupportedEventPlayerIndex => "replay events include an out-of-range player index",
        error.InvalidPerkPickEvent => "replay perk pick event is invalid for the current state",
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
        "native replay run only supports survival/rush/quest/typo/tutorial modes",
        replayRunnerErrorDetail(error.UnsupportedGameMode),
    );
    try std.testing.expectEqualStrings(
        "replay events include an out-of-range player index",
        replayRunnerErrorDetail(error.UnsupportedEventPlayerIndex),
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
        },
        .tutorial = null,
        .typo = null,
    };
}
