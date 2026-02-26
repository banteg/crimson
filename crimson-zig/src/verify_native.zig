const builtin = @import("builtin");
const std = @import("std");

const game_ids = @import("game_ids.zig");
const hash = @import("hash.zig");
const replay_codec = @import("replay_codec.zig");
const replay_runner = @import("runtime/replay_runner.zig");

const replay_schema_version: i32 = 1;

pub const CommandOutput = struct {
    stdout: []u8,
    stderr: []u8,
    exit_code: u8,

    pub fn deinit(self: CommandOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

const ScoreMetric = enum {
    auto,
    score_xp,
    elapsed_ms,
};

fn scoreMetricFromString(raw: []const u8) ?ScoreMetric {
    return std.meta.stringToEnum(ScoreMetric, raw);
}

fn resolveScoreMetric(metric: ScoreMetric, game_mode_id: i32) ScoreMetric {
    return switch (metric) {
        .score_xp => .score_xp,
        .elapsed_ms => .elapsed_ms,
        .auto => switch (std.meta.intToEnum(game_ids.GameModeId, game_mode_id) catch @panic("invalid game mode id")) {
            .rush, .quests => .elapsed_ms,
            else => .score_xp,
        },
    };
}

fn scoreMetricLabel(metric: ScoreMetric) []const u8 {
    return @tagName(metric);
}

const OutputFormat = enum {
    human,
    json,
};

const VerifyRequest = struct {
    replay_file: []const u8,
    output_format: OutputFormat = .human,
    json_out: ?[]const u8 = null,
    submitted_score: ?i64 = null,
    score_metric: ScoreMetric = .auto,
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

const ScoreClaimPayload = struct {
    metric: []const u8,
    submitted_score: i64,
    simulated_value: i64,
    match: bool,
};

const VerifyPayload = struct {
    schema_version: i32,
    status: []const u8,
    replay: []const u8,
    replay_sha256: []const u8,
    run_result: RunResult,
    score_claim: ?ScoreClaimPayload,
};

pub fn runReplayVerify(
    allocator: std.mem.Allocator,
    verify_args: []const []const u8,
) !CommandOutput {
    switch (parseNativeSubset(verify_args)) {
        .ok => |request| return runNativeVerify(allocator, request),
        .unsupported => |detail| return buildUnsupportedVerifyOptionOutput(allocator, detail),
        .invalid => |detail| return buildInvalidVerifyArgsOutput(allocator, detail),
    }
}

fn runNativeVerify(
    allocator: std.mem.Allocator,
    request: VerifyRequest,
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
        return buildVerifyFailedOutput(allocator, @errorName(err));
    };
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
        return buildVerifyFailedOutput(allocator, @errorName(err));
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

    if (unsupportedReplayHeaderDetail(header, replay.tickCount())) |detail| {
        return buildNotPortedOutput(allocator, detail);
    }
    replay_codec.validateReplayBootstrap(header) catch |err| {
        return buildNotPortedOutputForReplayCodecError(allocator, err);
    };
    const scaffold = blk: {
        if (request.debug_trace_jsonl) |trace_path| {
            var tick_trace: std.ArrayList(replay_runner.ReplayTickTrace) = .empty;
            defer tick_trace.deinit(allocator);

            const traced = replay_runner.runReplayScaffoldWithTrace(
                replay,
                &tick_trace,
                allocator,
                .{},
            ) catch |err| {
                writeReplayTickTraceJsonl(trace_path, tick_trace.items) catch |trace_err| {
                    return buildVerifyFailedOutput(allocator, @errorName(trace_err));
                };
                return buildNotPortedOutputForReplayRunnerError(allocator, err);
            };
            writeReplayTickTraceJsonl(trace_path, tick_trace.items) catch |trace_err| {
                return buildVerifyFailedOutput(allocator, @errorName(trace_err));
            };
            break :blk traced;
        }

        break :blk replay_runner.runReplayScaffoldWithOptions(replay, .{}) catch |err| {
            return buildNotPortedOutputForReplayRunnerError(allocator, err);
        };
    };

    var replay_sha256: [64]u8 = undefined;
    hash.sha256HexLower(replay_bytes, &replay_sha256);

    const run_result = RunResult{
        .game_mode_id = header.game_mode_id,
        .tick_rate = header.tick_rate,
        .ticks = @as(i32, @intCast(scaffold.ticks)),
        .elapsed_ms = scaffold.elapsed_ms_sim,
        .score_xp = scaffold.player_experience,
        .creature_kill_count = scaffold.creature_kill_count,
        .most_used_weapon_id = scaffold.most_used_weapon_id,
        .shots_fired = scaffold.shots_fired,
        .shots_hit = scaffold.shots_hit,
        .rng_state = scaffold.wave_spawn_rng_state,
    };
    const resolved_metric: ScoreMetric = resolveScoreMetric(request.score_metric, run_result.game_mode_id);
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
        writeFileWithParents(json_out_path, payload) catch |err| {
            return buildVerifyFailedOutput(allocator, @errorName(err));
        };
    }

    const simulated_value: i64 = if (resolved_metric == .elapsed_ms)
        run_result.elapsed_ms
    else
        run_result.score_xp;
    const claim_matches = if (request.submitted_score) |submitted|
        submitted == simulated_value
    else
        true;
    const status = if (claim_matches) "ok" else "score_mismatch";

    var stdout_buf: std.ArrayList(u8) = .empty;
    defer stdout_buf.deinit(allocator);
    var writer = stdout_buf.writer(allocator);

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
        if (request.submitted_score) |submitted| {
            try writer.print(
                "; score_claim metric={s} submitted={d} simulated={d} match={s}",
                .{
                    scoreMetricLabel(resolved_metric),
                    submitted,
                    simulated_value,
                    if (claim_matches) "true" else "false",
                },
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

fn writeReplayTickTraceJsonl(
    trace_path: []const u8,
    trace: []const replay_runner.ReplayTickTrace,
) !void {
    if (std.fs.path.dirname(trace_path)) |dir| {
        if (dir.len > 0) try std.fs.cwd().makePath(dir);
    }
    const file = try std.fs.cwd().createFile(trace_path, .{
        .truncate = true,
    });
    defer file.close();

    var buffer: [4096]u8 = undefined;
    var writer = file.writer(&buffer);
    const out = &writer.interface;
    for (trace) |entry| {
        try out.print(
            "{{\"tick\":{d},\"rng_state\":{d},\"elapsed_ms\":{d},\"score_xp\":{d},\"kills\":{d},\"creature_count\":{d},\"creature_active_index_sum\":{d},\"creature_active_index_xor\":{d},\"perk_pending\":{d},\"player_weapon_id\":{d},\"player_ammo_q4\":{d},\"player_health_q4\":{d},\"player_pos_x_q4\":{d},\"player_pos_y_q4\":{d},\"player_aim_x_q4\":{d},\"player_aim_y_q4\":{d},\"player_level\":{d},\"player_experience\":{d},\"bonus_weapon_power_up_ms\":{d},\"bonus_reflex_boost_ms\":{d},\"bonus_energizer_ms\":{d},\"bonus_double_experience_ms\":{d},\"bonus_freeze_ms\":{d},\"projectile_count\":{d},\"projectile0_pos_x_q4\":{d},\"projectile0_pos_y_q4\":{d},\"projectile0_origin_x_q4\":{d},\"projectile0_origin_y_q4\":{d},\"projectile0_life_timer_q4\":{d},\"projectile0_type_id\":{d},\"projectile0_angle_q6\":{d},\"projectile0_speed_scale_q4\":{d}",
            .{
                entry.tick,
                entry.rng.rng_state,
                entry.summary.elapsed_ms,
                entry.summary.score_xp,
                entry.summary.kills,
                entry.summary.creature_count,
                entry.summary.creature_active_index_sum,
                entry.summary.creature_active_index_xor,
                entry.summary.perk_pending,
                entry.player.player_weapon_id,
                entry.player.player_ammo_q4,
                entry.player.player_health_q4,
                entry.player.player_pos_x_q4,
                entry.player.player_pos_y_q4,
                entry.player.player_aim_x_q4,
                entry.player.player_aim_y_q4,
                entry.player.player_level,
                entry.player.player_experience,
                entry.bonuses.bonus_weapon_power_up_ms,
                entry.bonuses.bonus_reflex_boost_ms,
                entry.bonuses.bonus_energizer_ms,
                entry.bonuses.bonus_double_experience_ms,
                entry.bonuses.bonus_freeze_ms,
                entry.projectiles.projectile_count,
                entry.projectiles.projectile0_pos_x_q4,
                entry.projectiles.projectile0_pos_y_q4,
                entry.projectiles.projectile0_origin_x_q4,
                entry.projectiles.projectile0_origin_y_q4,
                entry.projectiles.projectile0_life_timer_q4,
                entry.projectiles.projectile0_type_id,
                entry.projectiles.projectile0_angle_q6,
                entry.projectiles.projectile0_speed_scale_q4,
            },
        );
        try out.print(
            ",\"shots_fired_p0\":{d}",
            .{entry.summary.shots_fired_p0},
        );
        try out.print(
            ",\"bonus_active_count\":{d},\"bonus0_id\":{d},\"bonus0_amount\":{d},\"bonus1_id\":{d},\"bonus1_amount\":{d}",
            .{
                entry.bonuses.bonus_active_count,
                entry.bonuses.bonus0_id,
                entry.bonuses.bonus0_amount,
                entry.bonuses.bonus1_id,
                entry.bonuses.bonus1_amount,
            },
        );
        try out.print(
            ",\"projectile_state_hash\":{d}",
            .{entry.projectiles.projectile_state_hash},
        );
        try out.print(
            ",\"creature_state_hash\":{d}",
            .{entry.summary.creature_state_hash},
        );
        try out.print(
            ",\"projectile_active_index_sum\":{d},\"projectile_active_index_xor\":{d},\"projectile_type45_count\":{d}",
            .{
                entry.projectiles.projectile_active_index_sum,
                entry.projectiles.projectile_active_index_xor,
                entry.projectiles.projectile_type45_count,
            },
        );
        try out.print(
            ",\"rng_after_perk_effects\":{d},\"rng_after_creatures\":{d},\"rng_after_projectiles\":{d}",
            .{
                entry.rng.rng_after_perk_effects,
                entry.rng.rng_after_creatures,
                entry.rng.rng_after_projectiles,
            },
        );
        try out.print(
            ",\"rng_after_secondary_projectiles\":{d},\"rng_after_particles\":{d},\"rng_after_player_update\":{d},\"rng_after_stage_spawns\":{d},\"rng_after_wave_spawns\":{d},\"rng_after_spawns\":{d},\"rng_after_bonus_update\":{d}",
            .{
                entry.rng.rng_after_secondary_projectiles,
                entry.rng.rng_after_particles,
                entry.rng.rng_after_player_update,
                entry.rng.rng_after_stage_spawns,
                entry.rng.rng_after_wave_spawns,
                entry.rng.rng_after_spawns,
                entry.rng.rng_after_bonus_update,
            },
        );
        try out.print(
            ",\"projectile1_active\":{s},\"projectile1_pos_x_q4\":{d},\"projectile1_pos_y_q4\":{d},\"projectile1_origin_x_q4\":{d},\"projectile1_origin_y_q4\":{d},\"projectile1_life_timer_q4\":{d},\"projectile1_type_id\":{d},\"projectile1_angle_q6\":{d},\"projectile1_damage_pool_q4\":{d}",
            .{
                if (entry.projectiles.projectile1_active) "true" else "false",
                entry.projectiles.projectile1_pos_x_q4,
                entry.projectiles.projectile1_pos_y_q4,
                entry.projectiles.projectile1_origin_x_q4,
                entry.projectiles.projectile1_origin_y_q4,
                entry.projectiles.projectile1_life_timer_q4,
                entry.projectiles.projectile1_type_id,
                entry.projectiles.projectile1_angle_q6,
                entry.projectiles.projectile1_damage_pool_q4,
            },
        );
        try out.print(
            ",\"projectile6_active\":{s},\"projectile6_type_id\":{d},\"projectile6_pos_x_q4\":{d},\"projectile6_pos_y_q4\":{d},\"projectile6_origin_x_q4\":{d},\"projectile6_origin_y_q4\":{d},\"projectile6_life_timer_q4\":{d},\"projectile6_damage_pool_q4\":{d},\"projectile6_angle_q6\":{d}",
            .{
                if (entry.projectiles.projectile6_active) "true" else "false",
                entry.projectiles.projectile6_type_id,
                entry.projectiles.projectile6_pos_x_q4,
                entry.projectiles.projectile6_pos_y_q4,
                entry.projectiles.projectile6_origin_x_q4,
                entry.projectiles.projectile6_origin_y_q4,
                entry.projectiles.projectile6_life_timer_q4,
                entry.projectiles.projectile6_damage_pool_q4,
                entry.projectiles.projectile6_angle_q6,
            },
        );
        try out.print(
            ",\"player_heading_q6\":{d},\"player_aim_heading_q6\":{d},\"player_move_speed_q4\":{d},\"player_turn_speed_q4\":{d}",
            .{
                entry.player.player_heading_q6,
                entry.player.player_aim_heading_q6,
                entry.player.player_move_speed_q4,
                entry.player.player_turn_speed_q4,
            },
        );
        try out.print(
            ",\"player_reload_active\":{s},\"player_reload_timer_q4\":{d},\"player_shot_cooldown_q4\":{d},\"player_shot_seq\":{d}",
            .{
                if (entry.player.player_reload_active) "true" else "false",
                entry.player.player_reload_timer_q4,
                entry.player.player_shot_cooldown_q4,
                entry.player.player_shot_seq,
            },
        );
        try out.print(
            ",\"player_perk31_count\":{d},\"player_perk53_count\":{d},\"player_perk54_count\":{d},\"player_perk55_count\":{d},\"player_hot_tempered_timer_q6\":{d},\"player_shield_timer_q4\":{d},\"player_man_bomb_timer_q6\":{d},\"player_fire_cough_timer_q6\":{d},\"player_living_fortress_timer_q6\":{d},\"perk_interval_hot_tempered_q6\":{d},\"perk_interval_man_bomb_q6\":{d},\"perk_interval_fire_cough_q6\":{d}",
            .{
                entry.player.player_perk31_count,
                entry.player.player_perk53_count,
                entry.player.player_perk54_count,
                entry.player.player_perk55_count,
                entry.player.player_hot_tempered_timer_q6,
                entry.player.player_shield_timer_q4,
                entry.player.player_man_bomb_timer_q6,
                entry.player.player_fire_cough_timer_q6,
                entry.player.player_living_fortress_timer_q6,
                entry.player.perk_interval_hot_tempered_q6,
                entry.player.perk_interval_man_bomb_q6,
                entry.player.perk_interval_fire_cough_q6,
            },
        );
        try out.print(
            ",\"projectile_hit_count\":{d},\"projectile_type1_count\":{d},\"projectile_type6_count\":{d},\"projectile_type6_pos_x_q4\":{d},\"projectile_type6_pos_y_q4\":{d},\"projectile_type6_origin_x_q4\":{d},\"projectile_type6_origin_y_q4\":{d},\"projectile_type6_life_timer_q4\":{d},\"projectile_type6_damage_pool_q4\":{d},\"projectile_type6_b_pos_x_q4\":{d},\"projectile_type6_b_pos_y_q4\":{d},\"projectile_type6_b_life_timer_q4\":{d},\"projectile_type6_b_damage_pool_q4\":{d},\"projectile_type11_count\":{d},\"projectile_type11_pos_x_q4\":{d},\"projectile_type11_pos_y_q4\":{d},\"projectile_type11_origin_x_q4\":{d},\"projectile_type11_origin_y_q4\":{d},\"projectile_type11_life_timer_q4\":{d},\"projectile_type11_closest_to_c2_dist_q4\":{d},\"projectile_type11_closest_to_c2_pos_x_q4\":{d},\"projectile_type11_closest_to_c2_pos_y_q4\":{d},\"projectile_type11_closest_to_c2_origin_x_q4\":{d},\"projectile_type11_closest_to_c2_origin_y_q4\":{d},\"projectile_first_hit_creature_index\":{d},\"projectile_first_hit_type_id\":{d},\"projectile_first_hit_pos_x_q4\":{d},\"projectile_first_hit_pos_y_q4\":{d}",
            .{
                entry.projectiles.projectile_hit_count,
                entry.projectiles.projectile_type1_count,
                entry.projectiles.projectile_type6_count,
                entry.projectiles.projectile_type6_pos_x_q4,
                entry.projectiles.projectile_type6_pos_y_q4,
                entry.projectiles.projectile_type6_origin_x_q4,
                entry.projectiles.projectile_type6_origin_y_q4,
                entry.projectiles.projectile_type6_life_timer_q4,
                entry.projectiles.projectile_type6_damage_pool_q4,
                entry.projectiles.projectile_type6_b_pos_x_q4,
                entry.projectiles.projectile_type6_b_pos_y_q4,
                entry.projectiles.projectile_type6_b_life_timer_q4,
                entry.projectiles.projectile_type6_b_damage_pool_q4,
                entry.projectiles.projectile_type11_count,
                entry.projectiles.projectile_type11_pos_x_q4,
                entry.projectiles.projectile_type11_pos_y_q4,
                entry.projectiles.projectile_type11_origin_x_q4,
                entry.projectiles.projectile_type11_origin_y_q4,
                entry.projectiles.projectile_type11_life_timer_q4,
                entry.projectiles.projectile_type11_closest_to_c2_dist_q4,
                entry.projectiles.projectile_type11_closest_to_c2_pos_x_q4,
                entry.projectiles.projectile_type11_closest_to_c2_pos_y_q4,
                entry.projectiles.projectile_type11_closest_to_c2_origin_x_q4,
                entry.projectiles.projectile_type11_closest_to_c2_origin_y_q4,
                entry.projectiles.projectile_first_hit_creature_index,
                entry.projectiles.projectile_first_hit_type_id,
                entry.projectiles.projectile_first_hit_pos_x_q4,
                entry.projectiles.projectile_first_hit_pos_y_q4,
            },
        );
        try out.print(
            ",\"projectile_type21_count\":{d},\"projectile_type21_pos_x_q4\":{d},\"projectile_type21_pos_y_q4\":{d},\"projectile_type21_origin_x_q4\":{d},\"projectile_type21_origin_y_q4\":{d},\"projectile_type21_life_timer_q4\":{d},\"projectile_type21_angle_q6\":{d}",
            .{
                entry.projectiles.projectile_type21_count,
                entry.projectiles.projectile_type21_pos_x_q4,
                entry.projectiles.projectile_type21_pos_y_q4,
                entry.projectiles.projectile_type21_origin_x_q4,
                entry.projectiles.projectile_type21_origin_y_q4,
                entry.projectiles.projectile_type21_life_timer_q4,
                entry.projectiles.projectile_type21_angle_q6,
            },
        );
        try out.print(
            ",\"creature0_active\":{s},\"creature0_pos_x_q4\":{d},\"creature0_pos_y_q4\":{d},\"creature0_hp_q4\":{d},\"creature0_lifecycle_stage_q4\":{d},\"creature1_active\":{s},\"creature1_pos_x_q4\":{d},\"creature1_pos_y_q4\":{d},\"creature1_hp_q4\":{d},\"creature1_lifecycle_stage_q4\":{d}",
            .{
                if (entry.creatures.creature0_active) "true" else "false",
                entry.creatures.creature0_pos_x_q4,
                entry.creatures.creature0_pos_y_q4,
                entry.creatures.creature0_hp_q4,
                entry.creatures.creature0_lifecycle_stage_q4,
                if (entry.creatures.creature1_active) "true" else "false",
                entry.creatures.creature1_pos_x_q4,
                entry.creatures.creature1_pos_y_q4,
                entry.creatures.creature1_hp_q4,
                entry.creatures.creature1_lifecycle_stage_q4,
            },
        );
        try out.print(
            ",\"projectile_first_hit_projectile_index\":{d},\"projectile_first_hit_origin_x_q4\":{d},\"projectile_first_hit_origin_y_q4\":{d},\"projectile_first_hit_target_size_q4\":{d},\"projectile_first_hit_target_x_q4\":{d},\"projectile_first_hit_target_y_q4\":{d}",
            .{
                entry.projectiles.projectile_first_hit_projectile_index,
                entry.projectiles.projectile_first_hit_origin_x_q4,
                entry.projectiles.projectile_first_hit_origin_y_q4,
                entry.projectiles.projectile_first_hit_target_size_q4,
                entry.projectiles.projectile_first_hit_target_x_q4,
                entry.projectiles.projectile_first_hit_target_y_q4,
            },
        );
        try out.print(
            ",\"creature2_active\":{s},\"creature2_pos_x_q4\":{d},\"creature2_pos_y_q4\":{d},\"creature2_hp_q4\":{d},\"creature2_lifecycle_stage_q4\":{d},\"creature10_active\":{s},\"creature10_pos_x_q4\":{d},\"creature10_pos_y_q4\":{d},\"creature10_hp_q4\":{d},\"creature10_lifecycle_stage_q4\":{d},\"creature12_active\":{s},\"creature12_pos_x_q4\":{d},\"creature12_pos_y_q4\":{d},\"creature12_hp_q4\":{d},\"creature12_lifecycle_stage_q4\":{d},\"creature14_active\":{s},\"creature14_pos_x_q4\":{d},\"creature14_pos_y_q4\":{d},\"creature14_hp_q4\":{d},\"creature14_lifecycle_stage_q4\":{d},\"creature14_size_q4\":{d},\"creature14_target_x_q4\":{d},\"creature14_target_y_q4\":{d},\"creature14_heading_q6\":{d},\"creature14_target_heading_q6\":{d},\"creature18_active\":{s},\"creature18_pos_x_q4\":{d},\"creature18_pos_y_q4\":{d},\"creature18_hp_q4\":{d},\"creature18_lifecycle_stage_q4\":{d}",
            .{
                if (entry.creatures.creature2_active) "true" else "false",
                entry.creatures.creature2_pos_x_q4,
                entry.creatures.creature2_pos_y_q4,
                entry.creatures.creature2_hp_q4,
                entry.creatures.creature2_lifecycle_stage_q4,
                if (entry.creatures.creature10_active) "true" else "false",
                entry.creatures.creature10_pos_x_q4,
                entry.creatures.creature10_pos_y_q4,
                entry.creatures.creature10_hp_q4,
                entry.creatures.creature10_lifecycle_stage_q4,
                if (entry.creatures.creature12_active) "true" else "false",
                entry.creatures.creature12_pos_x_q4,
                entry.creatures.creature12_pos_y_q4,
                entry.creatures.creature12_hp_q4,
                entry.creatures.creature12_lifecycle_stage_q4,
                if (entry.creatures.creature14_active) "true" else "false",
                entry.creatures.creature14_pos_x_q4,
                entry.creatures.creature14_pos_y_q4,
                entry.creatures.creature14_hp_q4,
                entry.creatures.creature14_lifecycle_stage_q4,
                entry.creatures.creature14_size_q4,
                entry.creatures.creature14_target_x_q4,
                entry.creatures.creature14_target_y_q4,
                entry.creatures.creature14_heading_q6,
                entry.creatures.creature14_target_heading_q6,
                if (entry.creatures.creature18_active) "true" else "false",
                entry.creatures.creature18_pos_x_q4,
                entry.creatures.creature18_pos_y_q4,
                entry.creatures.creature18_hp_q4,
                entry.creatures.creature18_lifecycle_stage_q4,
            },
        );
        try out.print(
            ",\"creature18_target_x_q4\":{d},\"creature18_target_y_q4\":{d},\"creature18_heading_q6\":{d},\"creature18_target_heading_q6\":{d},\"creature18_type_id\":{d},\"creature18_flags\":{d},\"creature18_link_index\":{d},\"creature18_ai_mode\":{d}",
            .{
                entry.creatures.creature18_target_x_q4,
                entry.creatures.creature18_target_y_q4,
                entry.creatures.creature18_heading_q6,
                entry.creatures.creature18_target_heading_q6,
                entry.creatures.creature18_type_id,
                entry.creatures.creature18_flags,
                entry.creatures.creature18_link_index,
                entry.creatures.creature18_ai_mode,
            },
        );
        try out.print(
            ",\"creature15_active\":{s},\"creature15_pos_x_q4\":{d},\"creature15_pos_y_q4\":{d},\"creature15_hp_q4\":{d},\"creature15_lifecycle_stage_q4\":{d}",
            .{
                if (entry.creatures.creature15_active) "true" else "false",
                entry.creatures.creature15_pos_x_q4,
                entry.creatures.creature15_pos_y_q4,
                entry.creatures.creature15_hp_q4,
                entry.creatures.creature15_lifecycle_stage_q4,
            },
        );
        try out.print(
            ",\"creature26_active\":{s},\"creature26_hp_q4\":{d},\"creature26_lifecycle_stage_q4\":{d},\"creature26_type_id\":{d},\"creature26_flags\":{d},\"creature26_link_index\":{d},\"creature26_ai_mode\":{d},\"creature31_active\":{s},\"creature31_hp_q4\":{d},\"creature31_lifecycle_stage_q4\":{d},\"creature32_active\":{s},\"creature32_pos_x_q4\":{d},\"creature32_pos_y_q4\":{d},\"creature32_hp_q4\":{d},\"creature32_lifecycle_stage_q4\":{d},\"creature32_type_id\":{d},\"creature32_flags\":{d},\"creature32_heading_q6\":{d},\"creature32_target_heading_q6\":{d},\"creature32_target_x_q4\":{d},\"creature32_target_y_q4\":{d},\"creature32_link_index\":{d},\"creature32_ai_mode\":{d}",
            .{
                if (entry.creatures.creature26_active) "true" else "false",
                entry.creatures.creature26_hp_q4,
                entry.creatures.creature26_lifecycle_stage_q4,
                entry.creatures.creature26_type_id,
                entry.creatures.creature26_flags,
                entry.creatures.creature26_link_index,
                entry.creatures.creature26_ai_mode,
                if (entry.creatures.creature31_active) "true" else "false",
                entry.creatures.creature31_hp_q4,
                entry.creatures.creature31_lifecycle_stage_q4,
                if (entry.creatures.creature32_active) "true" else "false",
                entry.creatures.creature32_pos_x_q4,
                entry.creatures.creature32_pos_y_q4,
                entry.creatures.creature32_hp_q4,
                entry.creatures.creature32_lifecycle_stage_q4,
                entry.creatures.creature32_type_id,
                entry.creatures.creature32_flags,
                entry.creatures.creature32_heading_q6,
                entry.creatures.creature32_target_heading_q6,
                entry.creatures.creature32_target_x_q4,
                entry.creatures.creature32_target_y_q4,
                entry.creatures.creature32_link_index,
                entry.creatures.creature32_ai_mode,
            },
        );
        try out.print(
            ",\"creature39_active\":{s},\"creature39_hp_q4\":{d},\"creature39_lifecycle_stage_q4\":{d},\"creature39_type_id\":{d},\"creature39_flags\":{d},\"creature39_link_index\":{d},\"creature39_ai_mode\":{d},\"creature45_active\":{s},\"creature45_pos_x_q4\":{d},\"creature45_pos_y_q4\":{d},\"creature45_hp_q4\":{d},\"creature45_lifecycle_stage_q4\":{d},\"debug_pending_nuke\":{d},\"debug_nuke_kills_last\":{d},\"debug_nuke_tick_last\":{d},\"debug_nuke_kill_index_sum\":{d},\"debug_last_picked_bonus_id\":{d},\"debug_last_picked_bonus_amount\":{d}}}\n",
            .{
                if (entry.creatures.creature39_active) "true" else "false",
                entry.creatures.creature39_hp_q4,
                entry.creatures.creature39_lifecycle_stage_q4,
                entry.creatures.creature39_type_id,
                entry.creatures.creature39_flags,
                entry.creatures.creature39_link_index,
                entry.creatures.creature39_ai_mode,
                if (entry.creatures.creature45_active) "true" else "false",
                entry.creatures.creature45_pos_x_q4,
                entry.creatures.creature45_pos_y_q4,
                entry.creatures.creature45_hp_q4,
                entry.creatures.creature45_lifecycle_stage_q4,
                entry.debug.debug_pending_nuke,
                entry.debug.debug_nuke_kills_last,
                entry.debug.debug_nuke_tick_last,
                entry.debug.debug_nuke_kill_index_sum,
                entry.debug.debug_last_picked_bonus_id,
                entry.debug.debug_last_picked_bonus_amount,
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
    resolved_metric: ScoreMetric,
    submitted_score: ?i64,
) ![]u8 {
    const simulated_value: i64 = if (resolved_metric == .elapsed_ms)
        run_result.elapsed_ms
    else
        run_result.score_xp;
    const claim_matches = if (submitted_score) |submitted|
        submitted == simulated_value
    else
        true;
    const score_claim: ?ScoreClaimPayload = if (submitted_score) |submitted| .{
        .metric = scoreMetricLabel(resolved_metric),
        .submitted_score = submitted,
        .simulated_value = simulated_value,
        .match = claim_matches,
    } else null;
    const report: VerifyPayload = .{
        .schema_version = replay_schema_version,
        .status = if (claim_matches) "ok" else "score_mismatch",
        .replay = replay_path,
        .replay_sha256 = replay_sha256,
        .run_result = run_result,
        .score_claim = score_claim,
    };

    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer payload_writer.deinit();
    try std.json.Stringify.value(report, .{}, &payload_writer.writer);
    return payload_writer.toOwnedSlice();
}

fn writeFileWithParents(path: []const u8, bytes: []const u8) !void {
    if (std.fs.path.dirname(path)) |dir| {
        if (dir.len > 0) try std.fs.cwd().makePath(dir);
    }
    try std.fs.cwd().writeFile(.{
        .sub_path = path,
        .data = bytes,
    });
}

fn buildReplayNotFoundOutput(
    allocator: std.mem.Allocator,
    resolution: ReplayResolution,
) !CommandOutput {
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);

    var writer = stderr_buf.writer(allocator);
    try writer.print("replay file not found: {s}", .{resolution.tried_primary});
    if (resolution.tried_secondary) |secondary| {
        try writer.print(" (also tried: {s})", .{secondary});
    }
    try writer.writeByte('\n');

    const stderr = try stderr_buf.toOwnedSlice(allocator);
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
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);

    var writer = stderr_buf.writer(allocator);
    try writer.print("replay verification failed: {s}\n", .{detail});

    const stderr = try stderr_buf.toOwnedSlice(allocator);
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
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);

    var writer = stderr_buf.writer(allocator);
    try writer.print("invalid replay verify args: {s}\n", .{detail});

    const stderr = try stderr_buf.toOwnedSlice(allocator);
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");

    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn buildUnsupportedVerifyOptionOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);

    var writer = stderr_buf.writer(allocator);
    try writer.print("unsupported replay verify option in native verifier: {s}\n", .{detail});

    const stderr = try stderr_buf.toOwnedSlice(allocator);
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");

    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn buildNotPortedOutput(
    allocator: std.mem.Allocator,
    detail: []const u8,
) !CommandOutput {
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(allocator);

    var writer = stderr_buf.writer(allocator);
    try writer.print("replay verification path not yet ported: {s}\n", .{detail});

    const stderr = try stderr_buf.toOwnedSlice(allocator);
    errdefer allocator.free(stderr);
    const stdout = try allocator.dupe(u8, "");

    return .{
        .stdout = stdout,
        .stderr = stderr,
        .exit_code = 1,
    };
}

fn unsupportedReplayHeaderDetail(
    header: replay_codec.ReplayHeader,
    tick_count: usize,
) ?[]const u8 {
    if (header.game_mode_id != 1 and header.game_mode_id != 2 and header.game_mode_id != 3) {
        return "only survival/rush/quest replays are currently ported";
    }
    if (header.player_count < 1 or header.player_count > 4) {
        return "only 1-4 player replays are currently ported";
    }
    if (header.preserve_bugs) {
        return "preserve_bugs=true replays are not ported";
    }
    if (!std.mem.eql(u8, header.input_quantization, "raw") and !std.mem.eql(u8, header.input_quantization, "f32")) {
        return "only raw/f32 input quantization is currently ported";
    }
    if (tick_count > std.math.maxInt(i32)) {
        return "replay has too many ticks for current native verifier";
    }
    if (!std.mem.startsWith(u8, header.game_version, "0.7.")) {
        return "only latest ruleset replays are currently ported";
    }
    return null;
}

fn buildNotPortedOutputForReplayCodecError(
    allocator: std.mem.Allocator,
    err: replay_codec.ReplayCodecError,
) !CommandOutput {
    switch (err) {
        error.InvalidMsgpack => return buildVerifyFailedOutput(allocator, "replay payload is not valid msgpack wire format"),
        error.InvalidHeaderValue => return buildVerifyFailedOutput(allocator, "replay header contains invalid values"),
        error.MissingHeaderField => return buildVerifyFailedOutput(allocator, "replay header missing required fields"),
        error.UnsupportedInputShape => return buildVerifyFailedOutput(allocator, "replay input rows are not in the canonical wire shape"),
        error.UnsupportedEventShape => return buildVerifyFailedOutput(allocator, "replay events are not in the canonical wire shape"),
        error.InvalidGzipPayload => return buildVerifyFailedOutput(allocator, "unable to inflate replay gzip payload"),
        error.UnsupportedReplayFormatVersion => return buildNotPortedOutput(allocator, "replay format version is not supported"),
        error.UnsupportedEventKind => return buildNotPortedOutput(allocator, "replay events include kinds not yet ported"),
        error.UnsupportedBootstrapKind => return buildNotPortedOutput(allocator, "replay bootstrap kind is not supported"),
        error.UnsupportedInputQuantization => return buildNotPortedOutput(allocator, "replay input quantization is not supported"),
        error.BootstrapSeedMismatch => return buildNotPortedOutput(allocator, "replay bootstrap seed does not match canonical terrain bootstrap draws"),
        error.PayloadTooLarge => return buildNotPortedOutput(allocator, "replay payload exceeds max decompressed size"),
        error.OutOfMemory => return buildNotPortedOutput(allocator, "native replay msgpack decode ran out of memory"),
    }
}

fn buildNotPortedOutputForReplayRunnerError(
    allocator: std.mem.Allocator,
    err: replay_runner.ReplayRunnerError,
) !CommandOutput {
    const detail = switch (err) {
        error.OutOfMemory => "replay simulation scaffold ran out of memory",
        error.InvalidHeaderValue => "replay simulation scaffold received invalid header values",
        error.UnsupportedGameMode => "replay simulation scaffold only supports survival/rush/quest modes",
        error.UnsupportedPlayerCount => "replay simulation scaffold only supports 1-4 player replays",
        error.UnsupportedInputQuantization => "replay simulation scaffold only supports raw/f32 quantization",
        error.UnsupportedDemoMode => "replay simulation scaffold does not support demo_mode_active=true",
        error.UnsupportedPreserveBugs => "replay simulation scaffold does not support preserve_bugs=true",
        error.UnsupportedEventOrdering => "replay events are not ordered in canonical tick order",
        error.UnsupportedEventKind => "replay events include kinds unsupported for this mode",
        error.UnsupportedEventPlayerIndex => "replay simulation scaffold encountered an out-of-range player_index event",
        error.InvalidPerkPickEvent => "replay perk_pick event could not be applied in current perk state",
        error.InvalidCaptureEnumValue => "replay capture payload contains an invalid enum value",
        error.UnsupportedPerkApplyHandler => "replay selected a perk with apply/effect behavior not yet ported",
        error.UnsupportedSpawnTemplate => "replay triggered survival template spawns not yet ported in native creature runtime",
        error.UnsupportedQuestSpawnTable => "quest replay requires a quest spawn table variant not yet ported in native runtime",
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
            request.score_metric = scoreMetricFromString(args[idx]) orelse return .{ .invalid = "invalid --score-metric value" };
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--score-metric=")) {
            const value = arg["--score-metric=".len..];
            request.score_metric = scoreMetricFromString(value) orelse return .{ .invalid = "invalid --score-metric value" };
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
    const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.IsDir => return false,
        else => return err,
    };
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

test "parse native subset reports unsupported lenient events option" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--lenient-events",
    });
    switch (parsed) {
        .unsupported => |detail| try std.testing.expectEqualStrings("--lenient-events", detail),
        else => return error.TestExpectedUnsupportedOption,
    }
}

test "parse native subset reports unsupported max ticks option" {
    const parsed = parseNativeSubset(&.{
        "survival_20260224_041009_score76661.crd",
        "--max-ticks=1000",
    });
    switch (parsed) {
        .unsupported => |detail| try std.testing.expectEqualStrings("--max-ticks", detail),
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
        .score_xp,
        1,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"status\":\"score_mismatch\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"simulated_value\":999") != null);
}

test "build verify payload escapes replay path via json stringify" {
    const allocator = std.testing.allocator;
    const payload = try buildVerifyPayload(
        allocator,
        "test\"\nreplay.crd",
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
        .score_xp,
        null,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"replay\":\"test\\\"\\nreplay.crd\"") != null);
}

test "unsupported verify option output has dedicated wording" {
    const allocator = std.testing.allocator;
    const output = try buildUnsupportedVerifyOptionOutput(allocator, "--trace-rng");
    defer allocator.free(output.stdout);
    defer allocator.free(output.stderr);

    try std.testing.expectEqual(@as(i32, 1), output.exit_code);
    try std.testing.expect(
        std.mem.indexOf(u8, output.stderr, "unsupported replay verify option in native verifier") != null,
    );
}

test "replay codec malformed payload errors map to verify failed output" {
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        err: replay_codec.ReplayCodecError,
        detail: []const u8,
    }{
        .{ .err = error.InvalidMsgpack, .detail = "replay payload is not valid msgpack wire format" },
        .{ .err = error.InvalidHeaderValue, .detail = "replay header contains invalid values" },
        .{ .err = error.MissingHeaderField, .detail = "replay header missing required fields" },
        .{ .err = error.UnsupportedInputShape, .detail = "replay input rows are not in the canonical wire shape" },
        .{ .err = error.UnsupportedEventShape, .detail = "replay events are not in the canonical wire shape" },
        .{ .err = error.InvalidGzipPayload, .detail = "unable to inflate replay gzip payload" },
    };

    for (cases) |case_item| {
        const output = try buildNotPortedOutputForReplayCodecError(allocator, case_item.err);
        defer output.deinit(allocator);

        try std.testing.expectEqual(@as(i32, 1), output.exit_code);
        try std.testing.expect(std.mem.indexOf(u8, output.stderr, "replay verification failed:") != null);
        try std.testing.expect(std.mem.indexOf(u8, output.stderr, case_item.detail) != null);
        try std.testing.expect(std.mem.indexOf(u8, output.stderr, "path not yet ported") == null);
    }
}

test "replay codec unsupported event kind remains not ported output" {
    const allocator = std.testing.allocator;
    const output = try buildNotPortedOutputForReplayCodecError(allocator, error.UnsupportedEventKind);
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(i32, 1), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "replay verification path not yet ported:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "replay events include kinds not yet ported") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "replay verification failed:") == null);
}

test "survival sim not ported output maps unsupported weapon fire path" {
    const allocator = std.testing.allocator;
    const output = try buildNotPortedOutputForReplayRunnerError(allocator, error.UnsupportedWeaponFirePath);
    defer allocator.free(output.stdout);
    defer allocator.free(output.stderr);

    try std.testing.expectEqual(@as(i32, 1), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "weapon fire path not yet ported") != null);
}

test "survival sim not ported output maps unsupported demo mode path" {
    const allocator = std.testing.allocator;
    const output = try buildNotPortedOutputForReplayRunnerError(allocator, error.UnsupportedDemoMode);
    defer allocator.free(output.stdout);
    defer allocator.free(output.stderr);

    try std.testing.expectEqual(@as(i32, 1), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "does not support demo_mode_active=true") != null);
}

test "survival sim not ported output maps unsupported bonus apply path" {
    const allocator = std.testing.allocator;
    const output = try buildNotPortedOutputForReplayRunnerError(allocator, error.UnsupportedBonusApplyPath);
    defer allocator.free(output.stdout);
    defer allocator.free(output.stderr);

    try std.testing.expectEqual(@as(i32, 1), output.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "bonus apply path not yet ported") != null);
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
        .game_version = try allocator.dupe(u8, "0.7.0"),
        .tick_rate = 60,
        .difficulty_level = 0,
        .hardcore = false,
        .preserve_bugs = false,
        .detail_preset = 5,
        .fx_toggle = 0,
        .world_size = 1024.0,
        .player_count = 1,
        .status = .{
            .quest_unlock_index = 0,
            .quest_unlock_index_full = 0,
            .weapon_usage_counts = [_]u32{0} ** replay_codec.weapon_usage_count,
        },
        .input_quantization = try allocator.dupe(u8, "raw"),
    };
}

test "unsupported replay header detail rejects unsupported game mode" {
    const allocator = std.testing.allocator;
    var header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);
    header.game_mode_id = 9;

    const detail = unsupportedReplayHeaderDetail(header, 1) orelse return error.TestExpectedUnsupported;
    try std.testing.expectEqualStrings("only survival/rush/quest replays are currently ported", detail);
}

test "unsupported replay header detail rejects unsupported player count" {
    const allocator = std.testing.allocator;
    var header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);
    header.player_count = 5;

    const detail = unsupportedReplayHeaderDetail(header, 1) orelse return error.TestExpectedUnsupported;
    try std.testing.expectEqualStrings("only 1-4 player replays are currently ported", detail);
}

test "unsupported replay header detail rejects preserve bugs replays" {
    const allocator = std.testing.allocator;
    var header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);
    header.preserve_bugs = true;

    const detail = unsupportedReplayHeaderDetail(header, 1) orelse return error.TestExpectedUnsupported;
    try std.testing.expectEqualStrings("preserve_bugs=true replays are not ported", detail);
}

test "unsupported replay header detail rejects non raw quantization" {
    const allocator = std.testing.allocator;
    var header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);
    allocator.free(header.input_quantization);
    header.input_quantization = try allocator.dupe(u8, "u8");

    const detail = unsupportedReplayHeaderDetail(header, 1) orelse return error.TestExpectedUnsupported;
    try std.testing.expectEqualStrings("only raw/f32 input quantization is currently ported", detail);
}

test "unsupported replay header detail rejects oversized tick count" {
    const allocator = std.testing.allocator;
    const header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);

    const overflow_ticks = @as(usize, std.math.maxInt(i32)) + 1;
    const detail = unsupportedReplayHeaderDetail(header, overflow_ticks) orelse return error.TestExpectedUnsupported;
    try std.testing.expectEqualStrings("replay has too many ticks for current native verifier", detail);
}

test "unsupported replay header detail rejects non latest ruleset" {
    const allocator = std.testing.allocator;
    var header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);
    allocator.free(header.game_version);
    header.game_version = try allocator.dupe(u8, "0.6.9");

    const detail = unsupportedReplayHeaderDetail(header, 1) orelse return error.TestExpectedUnsupported;
    try std.testing.expectEqualStrings("only latest ruleset replays are currently ported", detail);
}

test "unsupported replay header detail accepts supported replay envelope" {
    const allocator = std.testing.allocator;
    const header = try makeTestReplayHeader(allocator);
    defer header.deinit(allocator);

    try std.testing.expect(unsupportedReplayHeaderDetail(header, 1) == null);
}
