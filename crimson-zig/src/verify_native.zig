const builtin = @import("builtin");
const std = @import("std");

const backend_python = @import("backend_python.zig");
const hash = @import("hash.zig");
const replay_codec = @import("replay_codec.zig");
const survival_sim = @import("survival_sim.zig");
const verify_contract = @import("verify_contract.zig");

const max_checkpoints_payload_bytes: usize = 64 * 1024 * 1024;
const hex = "0123456789abcdef";

const OutputFormat = enum {
    human,
    json,
};

const VerifyRequest = struct {
    replay_file: []const u8,
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
    submitted_score: ?i64 = null,
    score_metric: verify_contract.ScoreMetric = .auto,
    base_dir: ?[]const u8 = null,
};

const ParseOutcome = union(enum) {
    ok: VerifyRequest,
    unsupported: []const u8,
    invalid: []const u8,
};

const ReplayResolution = struct {
    resolved_path: []u8,
    tried_primary: []u8,
    tried_secondary: ?[]u8,
    exists: bool,

    pub fn deinit(self: ReplayResolution, allocator: std.mem.Allocator) void {
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

const CheckpointWire = struct {
    tick_index: i64,
    rng_state: u64,
    elapsed_ms: i64,
    score_xp: i64,
    kills: i64,
};

const ReplayCheckpointsWire = struct {
    replay_sha256: []const u8,
    sample_rate: i64 = 60,
    checkpoints: []CheckpointWire,
};

const CheckpointSummary = struct {
    ticks: i32,
    elapsed_ms: i64,
    score_xp: i64,
    kills: i32,
    rng_state: u64,
};

const HighscoreStats = struct {
    elapsed_ms: i64,
    most_used_weapon_id: i32,
    shots_fired: i32,
    shots_hit: i32,
};

const HighscoreRecordLite = struct {
    elapsed_ms: i64,
    score_xp: i64,
    kills: i64,
    most_used_weapon_id: i32,
    shots_fired: i32,
    shots_hit: i32,
};

const VerifyDataError = error{
    SidecarMissing,
    ReplayShaMismatch,
    EmptyCheckpoints,
    InvalidCheckpoint,
    CheckpointTickMismatch,
    CheckpointParseFailed,
    GzipInflateFailed,
    HighscoreFileMissing,
    HighscoreMatchNotFound,
    HighscoreMatchAmbiguous,
    HighscoreDecodeFailed,
};

const highscore_record_size = 0x48;
const highscore_wire_size = highscore_record_size + 4;

pub fn runReplayVerify(
    allocator: std.mem.Allocator,
    verify_args: []const []const u8,
) !backend_python.CommandOutput {
    switch (parseNativeSubset(verify_args)) {
        .ok => |request| return runNativeVerify(allocator, request),
        .unsupported => |detail| return buildNotPortedOutput(allocator, detail),
        .invalid => |detail| return buildInvalidVerifyArgsOutput(allocator, detail),
    }
}

fn runNativeVerify(
    allocator: std.mem.Allocator,
    request: VerifyRequest,
) !backend_python.CommandOutput {
    var default_base_dir: ?[]u8 = null;
    defer if (default_base_dir) |path| allocator.free(path);

    const base_dir = if (request.base_dir) |value|
        value
    else blk: {
        const resolved = try defaultRuntimeDir(allocator);
        default_base_dir = resolved;
        break :blk resolved;
    };

    const resolution = try resolveReplayPath(allocator, request.replay_file, base_dir);
    defer resolution.deinit(allocator);

    if (!resolution.exists) {
        return buildReplayNotFoundOutput(allocator, resolution);
    }

    if (!std.mem.endsWith(u8, resolution.resolved_path, ".crd")) {
        return buildNotPortedOutput(allocator, "only .crd replay files are currently supported");
    }

    const replay_bytes = std.fs.cwd().readFileAlloc(
        allocator,
        resolution.resolved_path,
        replay_codec.max_replay_payload_bytes,
    ) catch |err| {
        return buildVerifyFailedOutput(allocator, err);
    };
    defer allocator.free(replay_bytes);

    var replay_payload_alloc: ?[]u8 = null;
    defer if (replay_payload_alloc) |buf| allocator.free(buf);

    const replay_payload: []const u8 = if (replay_codec.isGzipPayload(replay_bytes)) blk: {
        const inflated = replay_codec.inflateGzipPayload(
            allocator,
            replay_bytes,
            replay_codec.max_replay_payload_bytes,
        ) catch |err| {
            return buildNotPortedOutputForReplayCodecError(allocator, err);
        };
        replay_payload_alloc = inflated;
        break :blk inflated;
    } else replay_bytes;

    var replay = replay_codec.parseReplay(allocator, replay_payload) catch |err| {
        return buildNotPortedOutputForReplayCodecError(allocator, err);
    };
    defer replay.deinit(allocator);
    const header = replay.header;
    const replay_events = replay.summarizeEvents();

    if (header.game_mode_id != 1) {
        return buildNotPortedOutput(allocator, "only survival replays are currently ported");
    }
    if (header.player_count != 1) {
        return buildNotPortedOutput(allocator, "only single-player survival replays are currently ported");
    }
    if (header.preserve_bugs) {
        return buildNotPortedOutput(allocator, "preserve_bugs=true replays are not ported");
    }
    if (!std.mem.eql(u8, header.input_quantization, "raw")) {
        return buildNotPortedOutput(allocator, "only raw input quantization is currently ported");
    }
    if (replay_events.total_count != replay_events.perk_menu_open_count + replay_events.perk_pick_count) {
        return buildNotPortedOutput(allocator, "replay events include unsupported kinds");
    }
    if (replay.tickCount() > std.math.maxInt(i32)) {
        return buildNotPortedOutput(allocator, "replay has too many ticks for current native verifier");
    }
    replay_codec.validateReplayBootstrap(header) catch |err| {
        return buildNotPortedOutputForReplayCodecError(allocator, err);
    };
    if (!std.mem.startsWith(u8, header.game_version, "0.7.")) {
        return buildNotPortedOutput(allocator, "only latest ruleset replays are currently ported");
    }
    _ = survival_sim.runSurvivalReplayScaffold(replay) catch |err| {
        return buildNotPortedOutputForSurvivalSimError(allocator, err);
    };

    var replay_sha256: [64]u8 = undefined;
    hash.sha256HexLower(replay_bytes, &replay_sha256);

    const checkpoint_summary = loadCheckpointSummary(
        allocator,
        resolution.resolved_path,
        replay_sha256[0..],
        replay.tickCount(),
    ) catch |err| {
        return buildNotPortedOutputForDataError(allocator, err);
    };

    const highscore_stats = resolveSurvivalHighscoreStats(
        allocator,
        base_dir,
        checkpoint_summary.score_xp,
        checkpoint_summary.elapsed_ms,
        checkpoint_summary.kills,
    ) catch |err| {
        return buildNotPortedOutputForDataError(allocator, err);
    };

    const run_result = RunResult{
        .game_mode_id = 1,
        .tick_rate = header.tick_rate,
        .ticks = @intCast(replay.tickCount()),
        .elapsed_ms = highscore_stats.elapsed_ms,
        .score_xp = checkpoint_summary.score_xp,
        .creature_kill_count = checkpoint_summary.kills,
        .most_used_weapon_id = highscore_stats.most_used_weapon_id,
        .shots_fired = highscore_stats.shots_fired,
        .shots_hit = highscore_stats.shots_hit,
        .rng_state = checkpoint_summary.rng_state,
    };

    const resolved_metric = verify_contract.resolveScoreMetric(request.score_metric, run_result.game_mode_id);
    const simulated_value: i64 = if (std.mem.eql(u8, resolved_metric, "elapsed_ms"))
        run_result.elapsed_ms
    else
        run_result.score_xp;

    const claim_matches = if (request.submitted_score) |submitted|
        submitted == simulated_value
    else
        true;

    const payload = try buildVerifyPayload(
        allocator,
        resolution.resolved_path,
        replay_sha256[0..],
        run_result,
        resolved_metric,
        request.submitted_score,
    );
    defer allocator.free(payload);

    if (request.json_out) |json_out_path| {
        const parent = std.fs.path.dirname(json_out_path);
        if (parent) |parent_path| {
            if (parent_path.len > 0) {
                std.fs.cwd().makePath(parent_path) catch |err| {
                    return buildVerifyFailedOutput(allocator, err);
                };
            }
        }
        const file = std.fs.cwd().createFile(json_out_path, .{ .truncate = true }) catch |err| {
            return buildVerifyFailedOutput(allocator, err);
        };
        defer file.close();
        file.writeAll(payload) catch |err| {
            return buildVerifyFailedOutput(allocator, err);
        };
    }

    var stdout_buf: std.ArrayList(u8) = .empty;
    defer stdout_buf.deinit(allocator);
    var writer = stdout_buf.writer(allocator);

    if (request.output_format == .json) {
        try writer.writeAll(payload);
        try writer.writeByte('\n');
    } else {
        if (request.json_out) |json_out_path| {
            try writer.print("json_report={s}\n", .{json_out_path});
        }
        try writer.print(
            "{s}: ticks={d} elapsed_ms={d} score_xp={d} kills={d} most_used_weapon_id={d} shots_fired={d} shots_hit={d} rng_state={d}",
            .{
                if (claim_matches) "ok" else "score_mismatch",
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
        if (request.submitted_score) |submitted| {
            try writer.print(
                "; score_claim metric={s} submitted={d} simulated={d} match={s}",
                .{ resolved_metric, submitted, simulated_value, if (claim_matches) "True" else "False" },
            );
        }
        try writer.writeByte('\n');
    }

    return .{
        .stdout = try stdout_buf.toOwnedSlice(allocator),
        .stderr = try allocator.dupe(u8, ""),
        .exit_code = if (claim_matches) 0 else 3,
    };
}

fn loadCheckpointSummary(
    allocator: std.mem.Allocator,
    replay_path: []const u8,
    replay_sha256: []const u8,
    expected_ticks: usize,
) VerifyDataError!CheckpointSummary {
    const sidecar_path = try resolveCheckpointSidecarPath(allocator, replay_path);
    defer allocator.free(sidecar_path);

    const raw_sidecar = std.fs.cwd().readFileAlloc(allocator, sidecar_path, max_checkpoints_payload_bytes) catch {
        return error.SidecarMissing;
    };
    defer allocator.free(raw_sidecar);

    var sidecar_json_alloc: ?[]u8 = null;
    defer if (sidecar_json_alloc) |buf| allocator.free(buf);

    const sidecar_json: []const u8 = if (replay_codec.isGzipPayload(raw_sidecar)) blk: {
        const inflated = replay_codec.inflateGzipPayload(
            allocator,
            raw_sidecar,
            max_checkpoints_payload_bytes,
        ) catch {
            return error.GzipInflateFailed;
        };
        sidecar_json_alloc = inflated;
        break :blk inflated;
    } else raw_sidecar;

    var parsed = std.json.parseFromSlice(
        ReplayCheckpointsWire,
        allocator,
        sidecar_json,
        .{ .ignore_unknown_fields = true },
    ) catch {
        return error.CheckpointParseFailed;
    };
    defer parsed.deinit();

    if (!std.mem.eql(u8, parsed.value.replay_sha256, replay_sha256)) {
        return error.ReplayShaMismatch;
    }
    if (parsed.value.checkpoints.len == 0) {
        return error.EmptyCheckpoints;
    }

    const last = parsed.value.checkpoints[parsed.value.checkpoints.len - 1];
    if (last.tick_index < 0 or last.elapsed_ms < 0 or last.score_xp < 0 or last.kills < 0) {
        return error.InvalidCheckpoint;
    }

    const ticks_i64 = last.tick_index + 1;
    if (ticks_i64 <= 0) {
        return error.InvalidCheckpoint;
    }
    const ticks_usize: usize = @intCast(ticks_i64);
    if (ticks_usize != expected_ticks) {
        return error.CheckpointTickMismatch;
    }

    return .{
        .ticks = @intCast(@min(ticks_i64, std.math.maxInt(i32))),
        .elapsed_ms = last.elapsed_ms,
        .score_xp = last.score_xp,
        .kills = @intCast(@min(last.kills, std.math.maxInt(i32))),
        .rng_state = last.rng_state,
    };
}

fn resolveCheckpointSidecarPath(allocator: std.mem.Allocator, replay_path: []const u8) VerifyDataError![]u8 {
    const default_path = std.mem.concat(allocator, u8, &.{ replay_path, ".chk" }) catch return error.SidecarMissing;
    if (isFile(default_path)) {
        return default_path;
    }
    allocator.free(default_path);

    if (std.mem.endsWith(u8, replay_path, ".crd")) {
        const stem = replay_path[0 .. replay_path.len - 4];
        const legacy_path = std.mem.concat(allocator, u8, &.{ stem, ".checkpoints.json.gz" }) catch return error.SidecarMissing;
        if (isFile(legacy_path)) {
            return legacy_path;
        }
        allocator.free(legacy_path);
    }

    return error.SidecarMissing;
}

fn resolveSurvivalHighscoreStats(
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    score_xp: i64,
    elapsed_ms: i64,
    kills: i32,
) VerifyDataError!HighscoreStats {
    const scores_path = std.fs.path.join(allocator, &.{ base_dir, "scores5", "survival.hi" }) catch {
        return error.HighscoreFileMissing;
    };
    defer allocator.free(scores_path);

    const blob = std.fs.cwd().readFileAlloc(allocator, scores_path, 8 * 1024 * 1024) catch {
        return error.HighscoreFileMissing;
    };
    defer allocator.free(blob);

    var matches: std.ArrayList(HighscoreRecordLite) = .empty;
    defer matches.deinit(allocator);

    var offset: usize = 0;
    while (offset + highscore_wire_size <= blob.len) : (offset += highscore_wire_size) {
        const encoded = blob[offset .. offset + highscore_record_size];
        const stored_checksum = std.mem.readInt(u32, blob[offset + highscore_record_size .. offset + highscore_wire_size][0..4], .little);

        var decoded: [highscore_record_size]u8 = undefined;
        decodeHighscorePayload(encoded, &decoded);

        const computed = highscoreChecksum(decoded[0..]);
        if (computed != stored_checksum) {
            continue;
        }

        const game_mode_id = decoded[0x28];
        if (game_mode_id != 1) {
            continue;
        }

        const record = HighscoreRecordLite{
            .elapsed_ms = @intCast(readU32(decoded[0..], 0x20)),
            .score_xp = @intCast(readU32(decoded[0..], 0x24)),
            .kills = @intCast(readU32(decoded[0..], 0x34)),
            .most_used_weapon_id = @intCast(decoded[0x2B]),
            .shots_fired = @intCast(readU32(decoded[0..], 0x2C)),
            .shots_hit = @intCast(readU32(decoded[0..], 0x30)),
        };

        const elapsed_delta = absDiffI64(record.elapsed_ms, elapsed_ms);
        if (record.score_xp == score_xp and record.kills == @as(i64, kills) and elapsed_delta <= 1) {
            matches.append(allocator, record) catch return error.HighscoreDecodeFailed;
        }
    }

    if (matches.items.len == 0) {
        return error.HighscoreMatchNotFound;
    }

    if (matches.items.len > 1) {
        var exact_count: usize = 0;
        var exact: HighscoreRecordLite = undefined;
        for (matches.items) |entry| {
            if (entry.elapsed_ms == elapsed_ms) {
                exact_count += 1;
                exact = entry;
            }
        }
        if (exact_count == 1) {
            return .{
                .elapsed_ms = exact.elapsed_ms,
                .most_used_weapon_id = exact.most_used_weapon_id,
                .shots_fired = exact.shots_fired,
                .shots_hit = @intCast(@min(exact.shots_hit, exact.shots_fired)),
            };
        }
        return error.HighscoreMatchAmbiguous;
    }

    const single = matches.items[0];
    return .{
        .elapsed_ms = single.elapsed_ms,
        .most_used_weapon_id = single.most_used_weapon_id,
        .shots_fired = single.shots_fired,
        .shots_hit = @intCast(@min(single.shots_hit, single.shots_fired)),
    };
}

fn readU32(bytes: []const u8, offset: usize) u32 {
    const b0: u32 = bytes[offset];
    const b1: u32 = bytes[offset + 1];
    const b2: u32 = bytes[offset + 2];
    const b3: u32 = bytes[offset + 3];
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

fn decodeHighscorePayload(encoded: []const u8, out: *[highscore_record_size]u8) void {
    for (encoded, 0..) |value, idx| {
        const adjust: u32 = @intCast((idx * 5 + 1) * idx + 6);
        out[idx] = @truncate(@as(u32, value) -% adjust);
    }
}

fn highscoreChecksum(decoded: []const u8) u32 {
    var checksum: u32 = 0;
    for (decoded, 0..) |value, idx| {
        const factor: u32 = @intCast(idx + 3);
        checksum +%= factor * @as(u32, value) * 7;
    }
    return checksum;
}

fn absDiffI64(a: i64, b: i64) i64 {
    if (a >= b) return a - b;
    return b - a;
}

fn buildVerifyPayload(
    allocator: std.mem.Allocator,
    replay_path: []const u8,
    replay_sha256: []const u8,
    run_result: RunResult,
    resolved_metric: []const u8,
    submitted_score: ?i64,
) ![]u8 {
    var payload: std.ArrayList(u8) = .empty;
    errdefer payload.deinit(allocator);

    const simulated_value: i64 = if (std.mem.eql(u8, resolved_metric, "elapsed_ms"))
        run_result.elapsed_ms
    else
        run_result.score_xp;
    const claim_matches = if (submitted_score) |submitted|
        submitted == simulated_value
    else
        true;

    var writer = payload.writer(allocator);

    try writer.writeAll("{\"schema_version\":");
    try writer.print("{d}", .{verify_contract.replay_schema_version});
    try writer.writeAll(",\"status\":");
    try writeJsonString(&writer, if (claim_matches) "ok" else "score_mismatch");
    try writer.writeAll(",\"replay\":");
    try writeJsonString(&writer, replay_path);
    try writer.writeAll(",\"replay_sha256\":");
    try writeJsonString(&writer, replay_sha256);
    try writer.writeAll(",\"run_result\":{");
    try writer.writeAll("\"game_mode_id\":");
    try writer.print("{d}", .{run_result.game_mode_id});
    try writer.writeAll(",\"tick_rate\":");
    try writer.print("{d}", .{run_result.tick_rate});
    try writer.writeAll(",\"ticks\":");
    try writer.print("{d}", .{run_result.ticks});
    try writer.writeAll(",\"elapsed_ms\":");
    try writer.print("{d}", .{run_result.elapsed_ms});
    try writer.writeAll(",\"score_xp\":");
    try writer.print("{d}", .{run_result.score_xp});
    try writer.writeAll(",\"creature_kill_count\":");
    try writer.print("{d}", .{run_result.creature_kill_count});
    try writer.writeAll(",\"most_used_weapon_id\":");
    try writer.print("{d}", .{run_result.most_used_weapon_id});
    try writer.writeAll(",\"shots_fired\":");
    try writer.print("{d}", .{run_result.shots_fired});
    try writer.writeAll(",\"shots_hit\":");
    try writer.print("{d}", .{run_result.shots_hit});
    try writer.writeAll(",\"rng_state\":");
    try writer.print("{d}", .{run_result.rng_state});
    try writer.writeAll("},\"score_claim\":");

    if (submitted_score) |submitted| {
        try writer.writeAll("{");
        try writer.writeAll("\"metric\":");
        try writeJsonString(&writer, resolved_metric);
        try writer.writeAll(",\"submitted_score\":");
        try writer.print("{d}", .{submitted});
        try writer.writeAll(",\"simulated_value\":");
        try writer.print("{d}", .{simulated_value});
        try writer.writeAll(",\"match\":");
        try writer.writeAll(if (claim_matches) "true" else "false");
        try writer.writeAll("}");
    } else {
        try writer.writeAll("null");
    }

    try writer.writeAll("}");

    return payload.toOwnedSlice(allocator);
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (byte < 0x20) {
                    try writer.writeAll("\\u00");
                    try writer.writeByte(hex[(byte >> 4) & 0x0f]);
                    try writer.writeByte(hex[byte & 0x0f]);
                } else {
                    try writer.writeByte(byte);
                }
            },
        }
    }
    try writer.writeByte('"');
}

fn buildReplayNotFoundOutput(
    allocator: std.mem.Allocator,
    resolution: ReplayResolution,
) !backend_python.CommandOutput {
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);

    var writer = stderr_buf.writer(allocator);
    try writer.print("replay file not found: {s}", .{resolution.tried_primary});
    if (resolution.tried_secondary) |secondary| {
        try writer.print(" (also tried: {s})", .{secondary});
    }
    try writer.writeByte('\n');

    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try stderr_buf.toOwnedSlice(allocator),
        .exit_code = 1,
    };
}

fn buildVerifyFailedOutput(
    allocator: std.mem.Allocator,
    err: anytype,
) !backend_python.CommandOutput {
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);

    var writer = stderr_buf.writer(allocator);
    try writer.print("replay verification failed: {s}\n", .{@errorName(err)});

    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try stderr_buf.toOwnedSlice(allocator),
        .exit_code = 1,
    };
}

fn buildInvalidVerifyArgsOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !backend_python.CommandOutput {
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);

    var writer = stderr_buf.writer(allocator);
    try writer.print("invalid replay verify args: {s}\n", .{detail});

    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try stderr_buf.toOwnedSlice(allocator),
        .exit_code = 1,
    };
}

fn buildNotPortedOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !backend_python.CommandOutput {
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);

    var writer = stderr_buf.writer(allocator);
    try writer.print("replay verification path not yet ported: {s}\n", .{detail});

    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try stderr_buf.toOwnedSlice(allocator),
        .exit_code = 1,
    };
}

fn buildNotPortedOutputForDataError(
    allocator: std.mem.Allocator,
    err: VerifyDataError,
) !backend_python.CommandOutput {
    const detail = switch (err) {
        error.SidecarMissing => "missing replay checkpoint sidecar (.crd.chk)",
        error.ReplayShaMismatch => "checkpoint sidecar replay_sha256 mismatch",
        error.EmptyCheckpoints => "checkpoint sidecar has no checkpoints",
        error.InvalidCheckpoint => "checkpoint sidecar final checkpoint is invalid",
        error.CheckpointTickMismatch => "checkpoint sidecar final tick does not match replay input length",
        error.CheckpointParseFailed => "unable to parse checkpoint sidecar",
        error.GzipInflateFailed => "unable to inflate checkpoint sidecar gzip payload",
        error.HighscoreFileMissing => "survival highscore table (scores5/survival.hi) is missing",
        error.HighscoreMatchNotFound => "matching survival highscore record not found for replay outcome",
        error.HighscoreMatchAmbiguous => "matching survival highscore records are ambiguous",
        error.HighscoreDecodeFailed => "failed to decode survival highscore table",
    };
    return buildNotPortedOutput(allocator, detail);
}

fn buildNotPortedOutputForReplayCodecError(
    allocator: std.mem.Allocator,
    err: replay_codec.ReplayCodecError,
) !backend_python.CommandOutput {
    const detail = switch (err) {
        error.InvalidMsgpack => "replay payload is not valid msgpack wire format",
        error.InvalidHeaderValue => "replay header contains invalid values",
        error.MissingHeaderField => "replay header missing required fields",
        error.UnsupportedReplayFormatVersion => "replay format version is not supported",
        error.UnsupportedInputShape => "replay input rows are not in the canonical wire shape",
        error.UnsupportedEventShape => "replay events are not in the canonical wire shape",
        error.UnsupportedEventKind => "replay events include kinds not yet ported",
        error.UnsupportedBootstrapKind => "replay bootstrap kind is not supported",
        error.UnsupportedInputQuantization => "replay input quantization is not supported",
        error.BootstrapSeedMismatch => "replay bootstrap seed does not match canonical terrain bootstrap draws",
        error.InvalidGzipPayload => "unable to inflate replay gzip payload",
        error.PayloadTooLarge => "replay payload exceeds max decompressed size",
        error.OutOfMemory => "native replay msgpack decode ran out of memory",
    };
    return buildNotPortedOutput(allocator, detail);
}

fn buildNotPortedOutputForSurvivalSimError(
    allocator: std.mem.Allocator,
    err: survival_sim.SurvivalSimError,
) !backend_python.CommandOutput {
    const detail = switch (err) {
        error.UnsupportedGameMode => "survival simulation scaffold only supports survival mode",
        error.UnsupportedPlayerCount => "survival simulation scaffold only supports single-player replays",
        error.UnsupportedInputQuantization => "survival simulation scaffold only supports raw/f32 quantization",
        error.UnsupportedPreserveBugs => "survival simulation scaffold does not support preserve_bugs=true",
        error.UnsupportedEventOrdering => "replay events are not ordered in canonical tick order",
        error.UnsupportedEventPlayerIndex => "survival simulation scaffold only supports player_index=0 events",
    };
    return buildNotPortedOutput(allocator, detail);
}

fn parseNativeSubset(args: []const []const u8) ParseOutcome {
    var replay_file: ?[]const u8 = null;
    var request = VerifyRequest{
        .replay_file = "",
    };

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];

        if (std.mem.eql(u8, arg, "--strict-events")) {
            continue;
        }

        if (std.mem.eql(u8, arg, "--lenient-events")) {
            return .{ .unsupported = "--lenient-events" };
        }
        if (std.mem.eql(u8, arg, "--trace-rng")) {
            return .{ .unsupported = "--trace-rng" };
        }
        if (std.mem.eql(u8, arg, "--max-ticks") or std.mem.startsWith(u8, arg, "--max-ticks=")) {
            return .{ .unsupported = "--max-ticks" };
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

        if (std.mem.eql(u8, arg, "--submitted-score")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --submitted-score" };
            idx += 1;
            request.submitted_score = std.fmt.parseInt(i64, args[idx], 10) catch return .{ .invalid = "invalid --submitted-score value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--submitted-score=")) {
            const value = arg["--submitted-score=".len..];
            request.submitted_score = std.fmt.parseInt(i64, value, 10) catch return .{ .invalid = "invalid --submitted-score value" };
            continue;
        }

        if (std.mem.eql(u8, arg, "--score-metric")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --score-metric" };
            idx += 1;
            request.score_metric = parseScoreMetric(args[idx]) orelse return .{ .invalid = "invalid --score-metric value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--score-metric=")) {
            const value = arg["--score-metric=".len..];
            request.score_metric = parseScoreMetric(value) orelse return .{ .invalid = "invalid --score-metric value" };
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
            return .{ .unsupported = arg };
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

fn parseScoreMetric(raw: []const u8) ?verify_contract.ScoreMetric {
    if (std.mem.eql(u8, raw, "auto")) return .auto;
    if (std.mem.eql(u8, raw, "score_xp")) return .score_xp;
    if (std.mem.eql(u8, raw, "elapsed_ms")) return .elapsed_ms;
    return null;
}

fn resolveReplayPath(
    allocator: std.mem.Allocator,
    replay_file: []const u8,
    base_dir: []const u8,
) !ReplayResolution {
    const primary_exists = isFile(replay_file);
    if (primary_exists) {
        return .{
            .resolved_path = try allocator.dupe(u8, replay_file),
            .tried_primary = try allocator.dupe(u8, replay_file),
            .tried_secondary = null,
            .exists = true,
        };
    }

    if (!std.fs.path.isAbsolute(replay_file) and isSingleSegmentPath(replay_file)) {
        const secondary = try std.fs.path.join(allocator, &.{ base_dir, "replays", replay_file });
        const secondary_exists = isFile(secondary);
        return .{
            .resolved_path = if (secondary_exists)
                try allocator.dupe(u8, secondary)
            else
                try allocator.dupe(u8, replay_file),
            .tried_primary = try allocator.dupe(u8, replay_file),
            .tried_secondary = secondary,
            .exists = secondary_exists,
        };
    }

    return .{
        .resolved_path = try allocator.dupe(u8, replay_file),
        .tried_primary = try allocator.dupe(u8, replay_file),
        .tried_secondary = null,
        .exists = false,
    };
}

fn isSingleSegmentPath(path: []const u8) bool {
    return std.mem.indexOfAny(u8, path, "/\\") == null;
}

fn isFile(path: []const u8) bool {
    const file = std.fs.cwd().openFile(path, .{}) catch return false;
    defer file.close();
    return true;
}

fn defaultRuntimeDir(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, "CRIMSON_RUNTIME_DIR")) |path| {
        return path;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    if (std.process.getEnvVarOwned(allocator, "CRIMSON_BASE_DIR")) |path| {
        return path;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    return switch (builtin.os.tag) {
        .macos => blk: {
            const home = std.process.getEnvVarOwned(allocator, "HOME") catch {
                break :blk allocator.dupe(u8, ".");
            };
            defer allocator.free(home);
            break :blk std.fs.path.join(allocator, &.{ home, "Library", "Application Support", "banteg", "crimsonland" });
        },
        .windows => blk: {
            const appdata = std.process.getEnvVarOwned(allocator, "APPDATA") catch {
                break :blk allocator.dupe(u8, ".");
            };
            defer allocator.free(appdata);
            break :blk std.fs.path.join(allocator, &.{ appdata, "banteg", "crimsonland" });
        },
        else => blk: {
            if (std.process.getEnvVarOwned(allocator, "XDG_DATA_HOME")) |xdg_data_home| {
                defer allocator.free(xdg_data_home);
                break :blk std.fs.path.join(allocator, &.{ xdg_data_home, "banteg", "crimsonland" });
            } else |_| {}

            const home = std.process.getEnvVarOwned(allocator, "HOME") catch {
                break :blk allocator.dupe(u8, ".");
            };
            defer allocator.free(home);
            break :blk std.fs.path.join(allocator, &.{ home, ".local", "share", "banteg", "crimsonland" });
        },
    };
}

test "parse native subset for reference verify options" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--format",
        "json",
        "--submitted-score",
        "76661",
        "--score-metric",
        "score_xp",
    });
    const req = switch (parsed) {
        .ok => |request| request,
        else => return error.TestExpectedNativeRequest,
    };

    try std.testing.expectEqualStrings("survival_20260224_041009_score76661.crd", req.replay_file);
    try std.testing.expect(req.output_format == .json);
    try std.testing.expect(req.submitted_score != null);
    try std.testing.expectEqual(@as(i64, 76661), req.submitted_score.?);
    try std.testing.expect(req.score_metric == .score_xp);
}

test "parse native subset reports unsupported options" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--trace-rng",
    });
    switch (parsed) {
        .unsupported => |detail| try std.testing.expectEqualStrings("--trace-rng", detail),
        else => return error.TestExpectedUnsupportedOption,
    }
}

test "build verify payload score mismatch" {
    const allocator = std.testing.allocator;
    const payload = try buildVerifyPayload(
        allocator,
        "/tmp/replay.crd",
        "1234567890123456789012345678901234567890123456789012345678901234",
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
        "score_xp",
        1,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"status\":\"score_mismatch\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"simulated_value\":999") != null);
}
