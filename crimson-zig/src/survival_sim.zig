const std = @import("std");

const replay_codec = @import("replay_codec.zig");
const survival_spawn = @import("survival_spawn.zig");
const survival_state = @import("survival_state.zig");

pub const SurvivalSimError = error{
    UnsupportedGameMode,
    UnsupportedPlayerCount,
    UnsupportedInputQuantization,
    UnsupportedPreserveBugs,
    UnsupportedEventOrdering,
    UnsupportedEventPlayerIndex,
};

pub const SurvivalReplayScaffoldResult = struct {
    ticks: usize,
    elapsed_ms_nominal: i64,
    elapsed_ms_sim: i64,
    perk_menu_open_count: usize,
    perk_pick_count: usize,
    fire_pressed_count: usize,
    reload_pressed_count: usize,
    stage_spawn_count: usize,
    wave_spawn_count: usize,
    wave_spawn_rng_state: u32,
    player_level: i32,
    player_experience: i32,
    player_weapon_id: i32,
    perk_pending_count: i32,
    survival_reward_handout_enabled: bool,
    survival_reward_fire_seen: bool,
    survival_reward_damage_seen: bool,
    spawn_stage: i32,
    spawn_cooldown_ms: f64,
};

pub fn runSurvivalReplayScaffold(
    replay: replay_codec.Replay,
) SurvivalSimError!SurvivalReplayScaffoldResult {
    const header = replay.header;
    if (header.game_mode_id != 1) return error.UnsupportedGameMode;
    if (header.player_count != 1) return error.UnsupportedPlayerCount;
    if (header.preserve_bugs) return error.UnsupportedPreserveBugs;
    if (!std.mem.eql(u8, header.input_quantization, "raw") and !std.mem.eql(u8, header.input_quantization, "f32")) {
        return error.UnsupportedInputQuantization;
    }

    const events = replay.events;
    var event_index: usize = 0;
    var perk_menu_open_count: usize = 0;
    var perk_pick_count: usize = 0;
    var fire_pressed_count: usize = 0;
    var reload_pressed_count: usize = 0;
    var stage_spawn_count: usize = 0;
    var wave_spawn_count: usize = 0;
    var spawn_cooldown: f64 = 0.0;
    var spawn_stage: i32 = 0;
    var state = survival_state.GameplayState.init(header.seed);
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    survival_state.resetPlayers(players[0..], @floatCast(header.world_size), null);

    var elapsed_ms_sim: f64 = 0.0;
    const terrain_size: i32 = @max(@as(i32, 1), @as(i32, @intFromFloat(header.world_size)));
    const dt_nominal: f64 = 1.0 / @as(f64, @floatFromInt(header.tick_rate));

    for (0..replay.tickCount()) |tick_index| {
        if (event_index < events.len and events[event_index].tickIndex() < tick_index) {
            return error.UnsupportedEventOrdering;
        }
        while (event_index < events.len and events[event_index].tickIndex() == tick_index) : (event_index += 1) {
            try applyReplayEvent(
                events[event_index],
                &perk_menu_open_count,
                &perk_pick_count,
            );
        }

        const input = replay.inputs[tick_index][0];
        const flags = replay_codec.unpackInputFlags(input.flags);
        if (flags.fire_down) {
            state.survival_reward_fire_seen = true;
        }
        if (flags.fire_pressed) fire_pressed_count += 1;
        if (flags.reload_pressed) reload_pressed_count += 1;

        const dt_sim = survival_state.timeScaleReflexBoostBonus(
            state.bonuses.reflex_boost,
            state.time_scale_active,
            dt_nominal,
        );
        const dt_sim_ms = dt_sim * 1000.0;
        const elapsed_before_ms = elapsed_ms_sim;

        survival_state.survivalUpdateWeaponHandouts(
            &state,
            players[0..],
            elapsed_before_ms,
        );

        const stage_result = survival_spawn.advanceSurvivalSpawnStage(
            spawn_stage,
            players[0].level,
        );
        spawn_stage = stage_result.stage;
        stage_spawn_count += stage_result.count;

        const wave_result = survival_spawn.tickSurvivalWaveSpawnsCount(
            spawn_cooldown,
            dt_sim_ms,
            &state.rng,
            1,
            elapsed_before_ms,
            players[0].experience,
            terrain_size,
            terrain_size,
        );
        spawn_cooldown = wave_result.cooldown;
        wave_spawn_count += wave_result.spawn_count;

        _ = survival_state.survivalProgressionUpdate(&state, players[0..]);
        survival_state.survivalEnforceRewardWeaponGuard(state, players[0..]);
        state.time_scale_active = state.bonuses.reflex_boost > 0.0;
        elapsed_ms_sim += dt_sim_ms;
    }

    const terminal_tick = replay.tickCount();
    if (event_index < events.len and events[event_index].tickIndex() < terminal_tick) {
        return error.UnsupportedEventOrdering;
    }
    while (event_index < events.len and events[event_index].tickIndex() == terminal_tick) : (event_index += 1) {
        try applyReplayEvent(
            events[event_index],
            &perk_menu_open_count,
            &perk_pick_count,
        );
    }
    if (event_index != events.len) return error.UnsupportedEventOrdering;

    const tick_rate_f64: f64 = @floatFromInt(header.tick_rate);
    const ticks_f64: f64 = @floatFromInt(replay.tickCount());
    const elapsed_ms_nominal: i64 = @intFromFloat(@round(ticks_f64 * (1000.0 / tick_rate_f64)));
    const elapsed_ms_sim_i64: i64 = @intFromFloat(elapsed_ms_sim);

    return .{
        .ticks = replay.tickCount(),
        .elapsed_ms_nominal = elapsed_ms_nominal,
        .elapsed_ms_sim = elapsed_ms_sim_i64,
        .perk_menu_open_count = perk_menu_open_count,
        .perk_pick_count = perk_pick_count,
        .fire_pressed_count = fire_pressed_count,
        .reload_pressed_count = reload_pressed_count,
        .stage_spawn_count = stage_spawn_count,
        .wave_spawn_count = wave_spawn_count,
        .wave_spawn_rng_state = state.rng.state,
        .player_level = players[0].level,
        .player_experience = players[0].experience,
        .player_weapon_id = players[0].weapon_id,
        .perk_pending_count = state.perk_selection.pending_count,
        .survival_reward_handout_enabled = state.survival_reward_handout_enabled,
        .survival_reward_fire_seen = state.survival_reward_fire_seen,
        .survival_reward_damage_seen = state.survival_reward_damage_seen,
        .spawn_stage = spawn_stage,
        .spawn_cooldown_ms = spawn_cooldown,
    };
}

fn applyReplayEvent(
    event: replay_codec.ReplayEvent,
    perk_menu_open_count: *usize,
    perk_pick_count: *usize,
) SurvivalSimError!void {
    switch (event) {
        .perk_menu_open => |open| {
            if (open.player_index != 0) return error.UnsupportedEventPlayerIndex;
            perk_menu_open_count.* += 1;
        },
        .perk_pick => |pick| {
            if (pick.player_index != 0) return error.UnsupportedEventPlayerIndex;
            perk_pick_count.* += 1;
        },
    }
}

test "survival scaffold tracks event and input counters" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{
            replay_codec.fire_pressed_flag,
            replay_codec.reload_pressed_flag,
        },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 0 } },
            .{ .perk_pick = .{ .tick_index = 2, .player_index = 0, .choice_index = 1 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runSurvivalReplayScaffold(replay);
    try std.testing.expectEqual(@as(usize, 2), result.ticks);
    try std.testing.expectEqual(@as(i64, 33), result.elapsed_ms_nominal);
    try std.testing.expectEqual(@as(i64, 33), result.elapsed_ms_sim);
    try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
    try std.testing.expectEqual(@as(usize, 1), result.perk_pick_count);
    try std.testing.expectEqual(@as(usize, 1), result.fire_pressed_count);
    try std.testing.expectEqual(@as(usize, 1), result.reload_pressed_count);
    try std.testing.expectEqual(@as(usize, 0), result.stage_spawn_count);
    try std.testing.expectEqual(@as(usize, 1), result.wave_spawn_count);
    try std.testing.expectEqual(survival_state.WeaponId.pistol, result.player_weapon_id);
    try std.testing.expectEqual(@as(i32, 1), result.player_level);
    try std.testing.expectEqual(@as(i32, 0), result.perk_pending_count);
    try std.testing.expect(result.survival_reward_fire_seen);
}

test "survival scaffold rejects unsupported event player index" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag},
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 1 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.UnsupportedEventPlayerIndex,
        runSurvivalReplayScaffold(replay),
    );
}

const TestReplayConfig = struct {
    tick_rate: i32,
    inputs: []const u32,
    events: []const replay_codec.ReplayEvent,
};

fn buildTestReplay(
    allocator: std.mem.Allocator,
    cfg: TestReplayConfig,
) !replay_codec.Replay {
    const ticks = try allocator.alloc(replay_codec.ReplayTickInputs, cfg.inputs.len);
    errdefer allocator.free(ticks);

    for (cfg.inputs, 0..) |flags, tick_index| {
        const input_tick = try allocator.alloc(replay_codec.ReplayPlayerInput, 1);
        input_tick[0] = .{
            .move_x = 0.0,
            .move_y = 0.0,
            .aim_x = 0.0,
            .aim_y = 0.0,
            .flags = flags,
        };
        ticks[tick_index] = input_tick;
    }

    const events = try allocator.alloc(replay_codec.ReplayEvent, cfg.events.len);
    for (cfg.events, 0..) |event, idx| {
        events[idx] = event;
    }

    return .{
        .header = .{
            .game_mode_id = 1,
            .seed = 1,
            .replay_format_version = replay_codec.replay_format_version,
            .quest_level = try allocator.dupe(u8, ""),
            .bootstrap_kind = try allocator.dupe(u8, "none"),
            .bootstrap_seed = 1,
            .game_version = try allocator.dupe(u8, "0.7.0"),
            .tick_rate = cfg.tick_rate,
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
        },
        .inputs = ticks,
        .events = events,
    };
}
