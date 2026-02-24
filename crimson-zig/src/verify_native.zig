const builtin = @import("builtin");
const std = @import("std");

const backend_python = @import("backend_python.zig");
const replay_codec = @import("replay_codec.zig");
const survival_sim = @import("survival_sim.zig");
const verify_contract = @import("verify_contract.zig");

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
    debug_trace_jsonl: ?[]const u8 = null,
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
    var tick_trace: std.ArrayList(survival_sim.SurvivalTickTrace) = .empty;
    defer tick_trace.deinit(allocator);

    const trace_out = if (request.debug_trace_jsonl != null) &tick_trace else null;
    _ = survival_sim.runSurvivalReplayScaffoldWithTrace(
        replay,
        trace_out,
        allocator,
    ) catch |err| {
        if (request.debug_trace_jsonl) |trace_path| {
            writeSurvivalTickTraceJsonl(trace_path, tick_trace.items) catch {};
        }
        return buildNotPortedOutputForSurvivalSimError(allocator, err);
    };
    if (request.debug_trace_jsonl) |trace_path| {
        writeSurvivalTickTraceJsonl(trace_path, tick_trace.items) catch {};
    }

    return buildNotPortedOutput(
        allocator,
        "full deterministic survival run-result simulation from .crd bytes is still in progress; sidecar/highscore shortcuts are disabled",
    );
}

fn writeSurvivalTickTraceJsonl(
    trace_path: []const u8,
    trace: []const survival_sim.SurvivalTickTrace,
) !void {
    const file = try std.fs.cwd().createFile(trace_path, .{
        .truncate = true,
    });
    defer file.close();

    var buffer: [4096]u8 = undefined;
    var writer = file.writer(&buffer);
    const out = &writer.interface;
    for (trace) |entry| {
        try out.print(
            "{{\"tick\":{d},\"rng_state\":{d},\"elapsed_ms\":{d},\"score_xp\":{d},\"kills\":{d},\"creature_count\":{d},\"perk_pending\":{d},\"player_weapon_id\":{d},\"player_ammo_q4\":{d},\"player_health_q4\":{d},\"player_pos_x_q4\":{d},\"player_pos_y_q4\":{d},\"player_aim_x_q4\":{d},\"player_aim_y_q4\":{d},\"player_level\":{d},\"player_experience\":{d},\"bonus_weapon_power_up_ms\":{d},\"bonus_reflex_boost_ms\":{d},\"bonus_energizer_ms\":{d},\"bonus_double_experience_ms\":{d},\"bonus_freeze_ms\":{d},\"projectile_count\":{d},\"projectile0_pos_x_q4\":{d},\"projectile0_pos_y_q4\":{d},\"projectile0_origin_x_q4\":{d},\"projectile0_origin_y_q4\":{d},\"projectile0_life_timer_q4\":{d},\"projectile0_type_id\":{d},\"projectile0_angle_q6\":{d},\"projectile0_speed_scale_q4\":{d}",
            .{
                entry.tick,
                entry.rng_state,
                entry.elapsed_ms,
                entry.score_xp,
                entry.kills,
                entry.creature_count,
                entry.perk_pending,
                entry.player_weapon_id,
                entry.player_ammo_q4,
                entry.player_health_q4,
                entry.player_pos_x_q4,
                entry.player_pos_y_q4,
                entry.player_aim_x_q4,
                entry.player_aim_y_q4,
                entry.player_level,
                entry.player_experience,
                entry.bonus_weapon_power_up_ms,
                entry.bonus_reflex_boost_ms,
                entry.bonus_energizer_ms,
                entry.bonus_double_experience_ms,
                entry.bonus_freeze_ms,
                entry.projectile_count,
                entry.projectile0_pos_x_q4,
                entry.projectile0_pos_y_q4,
                entry.projectile0_origin_x_q4,
                entry.projectile0_origin_y_q4,
                entry.projectile0_life_timer_q4,
                entry.projectile0_type_id,
                entry.projectile0_angle_q6,
                entry.projectile0_speed_scale_q4,
            },
        );
        try out.print(
            ",\"projectile_hit_count\":{d},\"projectile_type1_count\":{d},\"projectile_type6_count\":{d},\"projectile_type6_pos_x_q4\":{d},\"projectile_type6_pos_y_q4\":{d},\"projectile_type6_origin_x_q4\":{d},\"projectile_type6_origin_y_q4\":{d},\"projectile_type6_life_timer_q4\":{d},\"projectile_type6_damage_pool_q4\":{d},\"projectile_type6_b_pos_x_q4\":{d},\"projectile_type6_b_pos_y_q4\":{d},\"projectile_type6_b_life_timer_q4\":{d},\"projectile_type6_b_damage_pool_q4\":{d},\"projectile_type11_count\":{d},\"projectile_type11_pos_x_q4\":{d},\"projectile_type11_pos_y_q4\":{d},\"projectile_type11_origin_x_q4\":{d},\"projectile_type11_origin_y_q4\":{d},\"projectile_type11_life_timer_q4\":{d},\"projectile_type11_closest_to_c2_dist_q4\":{d},\"projectile_type11_closest_to_c2_pos_x_q4\":{d},\"projectile_type11_closest_to_c2_pos_y_q4\":{d},\"projectile_type11_closest_to_c2_origin_x_q4\":{d},\"projectile_type11_closest_to_c2_origin_y_q4\":{d},\"projectile_first_hit_creature_index\":{d},\"projectile_first_hit_type_id\":{d},\"projectile_first_hit_pos_x_q4\":{d},\"projectile_first_hit_pos_y_q4\":{d}",
            .{
                entry.projectile_hit_count,
                entry.projectile_type1_count,
                entry.projectile_type6_count,
                entry.projectile_type6_pos_x_q4,
                entry.projectile_type6_pos_y_q4,
                entry.projectile_type6_origin_x_q4,
                entry.projectile_type6_origin_y_q4,
                entry.projectile_type6_life_timer_q4,
                entry.projectile_type6_damage_pool_q4,
                entry.projectile_type6_b_pos_x_q4,
                entry.projectile_type6_b_pos_y_q4,
                entry.projectile_type6_b_life_timer_q4,
                entry.projectile_type6_b_damage_pool_q4,
                entry.projectile_type11_count,
                entry.projectile_type11_pos_x_q4,
                entry.projectile_type11_pos_y_q4,
                entry.projectile_type11_origin_x_q4,
                entry.projectile_type11_origin_y_q4,
                entry.projectile_type11_life_timer_q4,
                entry.projectile_type11_closest_to_c2_dist_q4,
                entry.projectile_type11_closest_to_c2_pos_x_q4,
                entry.projectile_type11_closest_to_c2_pos_y_q4,
                entry.projectile_type11_closest_to_c2_origin_x_q4,
                entry.projectile_type11_closest_to_c2_origin_y_q4,
                entry.projectile_first_hit_creature_index,
                entry.projectile_first_hit_type_id,
                entry.projectile_first_hit_pos_x_q4,
                entry.projectile_first_hit_pos_y_q4,
            },
        );
        try out.print(
            ",\"creature0_active\":{s},\"creature0_pos_x_q4\":{d},\"creature0_pos_y_q4\":{d},\"creature0_hp_q4\":{d},\"creature0_hitbox_q4\":{d},\"creature1_active\":{s},\"creature1_pos_x_q4\":{d},\"creature1_pos_y_q4\":{d},\"creature1_hp_q4\":{d},\"creature1_hitbox_q4\":{d}",
            .{
                if (entry.creature0_active) "true" else "false",
                entry.creature0_pos_x_q4,
                entry.creature0_pos_y_q4,
                entry.creature0_hp_q4,
                entry.creature0_hitbox_q4,
                if (entry.creature1_active) "true" else "false",
                entry.creature1_pos_x_q4,
                entry.creature1_pos_y_q4,
                entry.creature1_hp_q4,
                entry.creature1_hitbox_q4,
            },
        );
        try out.print(
            ",\"projectile_first_hit_projectile_index\":{d},\"projectile_first_hit_origin_x_q4\":{d},\"projectile_first_hit_origin_y_q4\":{d},\"projectile_first_hit_target_size_q4\":{d},\"projectile_first_hit_target_x_q4\":{d},\"projectile_first_hit_target_y_q4\":{d}",
            .{
                entry.projectile_first_hit_projectile_index,
                entry.projectile_first_hit_origin_x_q4,
                entry.projectile_first_hit_origin_y_q4,
                entry.projectile_first_hit_target_size_q4,
                entry.projectile_first_hit_target_x_q4,
                entry.projectile_first_hit_target_y_q4,
            },
        );
        try out.print(
            ",\"creature2_active\":{s},\"creature2_pos_x_q4\":{d},\"creature2_pos_y_q4\":{d},\"creature2_hp_q4\":{d},\"creature2_hitbox_q4\":{d},\"creature10_active\":{s},\"creature10_pos_x_q4\":{d},\"creature10_pos_y_q4\":{d},\"creature10_hp_q4\":{d},\"creature10_hitbox_q4\":{d},\"creature12_active\":{s},\"creature12_pos_x_q4\":{d},\"creature12_pos_y_q4\":{d},\"creature12_hp_q4\":{d},\"creature12_hitbox_q4\":{d},\"creature14_active\":{s},\"creature14_pos_x_q4\":{d},\"creature14_pos_y_q4\":{d},\"creature14_hp_q4\":{d},\"creature14_hitbox_q4\":{d},\"creature14_size_q4\":{d},\"creature14_target_x_q4\":{d},\"creature14_target_y_q4\":{d},\"creature14_heading_q6\":{d},\"creature14_target_heading_q6\":{d}",
            .{
                if (entry.creature2_active) "true" else "false",
                entry.creature2_pos_x_q4,
                entry.creature2_pos_y_q4,
                entry.creature2_hp_q4,
                entry.creature2_hitbox_q4,
                if (entry.creature10_active) "true" else "false",
                entry.creature10_pos_x_q4,
                entry.creature10_pos_y_q4,
                entry.creature10_hp_q4,
                entry.creature10_hitbox_q4,
                if (entry.creature12_active) "true" else "false",
                entry.creature12_pos_x_q4,
                entry.creature12_pos_y_q4,
                entry.creature12_hp_q4,
                entry.creature12_hitbox_q4,
                if (entry.creature14_active) "true" else "false",
                entry.creature14_pos_x_q4,
                entry.creature14_pos_y_q4,
                entry.creature14_hp_q4,
                entry.creature14_hitbox_q4,
                entry.creature14_size_q4,
                entry.creature14_target_x_q4,
                entry.creature14_target_y_q4,
                entry.creature14_heading_q6,
                entry.creature14_target_heading_q6,
            },
        );
        try out.print(
            ",\"creature26_active\":{s},\"creature26_hp_q4\":{d},\"creature26_hitbox_q4\":{d},\"creature26_type_id\":{d},\"creature26_flags\":{d},\"creature26_link_index\":{d},\"creature26_ai_mode\":{d},\"debug_pending_nuke\":{d},\"debug_nuke_kills_last\":{d},\"debug_nuke_tick_last\":{d},\"debug_nuke_kill_index_sum\":{d},\"debug_last_picked_bonus_id\":{d},\"debug_last_picked_bonus_amount\":{d}}}\n",
            .{
                if (entry.creature26_active) "true" else "false",
                entry.creature26_hp_q4,
                entry.creature26_hitbox_q4,
                entry.creature26_type_id,
                entry.creature26_flags,
                entry.creature26_link_index,
                entry.creature26_ai_mode,
                entry.debug_pending_nuke,
                entry.debug_nuke_kills_last,
                entry.debug_nuke_tick_last,
                entry.debug_nuke_kill_index_sum,
                entry.debug_last_picked_bonus_id,
                entry.debug_last_picked_bonus_amount,
            },
        );
    }
    try out.flush();
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
        error.OutOfMemory => "survival simulation scaffold ran out of memory",
        error.UnsupportedGameMode => "survival simulation scaffold only supports survival mode",
        error.UnsupportedPlayerCount => "survival simulation scaffold only supports single-player replays",
        error.UnsupportedInputQuantization => "survival simulation scaffold only supports raw/f32 quantization",
        error.UnsupportedPreserveBugs => "survival simulation scaffold does not support preserve_bugs=true",
        error.UnsupportedEventOrdering => "replay events are not ordered in canonical tick order",
        error.UnsupportedEventPlayerIndex => "survival simulation scaffold only supports player_index=0 events",
        error.InvalidPerkPickEvent => "replay perk_pick event could not be applied in current perk state",
        error.UnsupportedPerkApplyHandler => "replay selected a perk with apply/effect behavior not yet ported",
        error.UnsupportedSpawnTemplate => "replay triggered survival template spawns not yet ported in native creature runtime",
        error.UnsupportedWeaponFirePath => "replay triggered weapon fire path not yet ported in native projectile runtime",
        error.UnsupportedBonusApplyPath => "replay triggered bonus apply path not yet ported in native bonus runtime",
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
        if (std.mem.eql(u8, arg, "--debug-trace-jsonl")) {
            if (idx + 1 >= args.len) return .{ .invalid = "missing value for --debug-trace-jsonl" };
            idx += 1;
            request.debug_trace_jsonl = args[idx];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--debug-trace-jsonl=")) {
            request.debug_trace_jsonl = arg["--debug-trace-jsonl=".len..];
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
