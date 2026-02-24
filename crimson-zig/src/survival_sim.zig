const std = @import("std");

const replay_codec = @import("replay_codec.zig");
const survival_bonuses = @import("survival_bonuses.zig");
const survival_creatures = @import("survival_creatures.zig");
const survival_perks = @import("survival_perks.zig");
const survival_projectiles = @import("survival_projectiles.zig");
const survival_spawn = @import("survival_spawn.zig");
const survival_state = @import("survival_state.zig");
const survival_weapon_runtime = @import("survival_weapon_runtime.zig");
const native_half_pi: f64 = 1.5707963705062866;
const native_tau: f64 = 6.2831854820251465;

pub const SurvivalSimError = error{
    OutOfMemory,
    UnsupportedGameMode,
    UnsupportedPlayerCount,
    UnsupportedInputQuantization,
    UnsupportedPreserveBugs,
    UnsupportedEventOrdering,
    UnsupportedEventPlayerIndex,
    InvalidPerkPickEvent,
    UnsupportedPerkApplyHandler,
    UnsupportedSpawnTemplate,
    UnsupportedWeaponFirePath,
    UnsupportedBonusApplyPath,
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
    most_used_weapon_id: i32,
    shots_fired: i32,
    shots_hit: i32,
    creature_kill_count: i32,
    creature_active_count: usize,
    perk_pending_count: i32,
    survival_reward_handout_enabled: bool,
    survival_reward_fire_seen: bool,
    survival_reward_damage_seen: bool,
    spawn_stage: i32,
    spawn_cooldown_ms: f64,
};

pub const SurvivalTickTrace = struct {
    tick: usize,
    rng_state: u32,
    elapsed_ms: i64,
    score_xp: i32,
    kills: i32,
    creature_count: usize,
    perk_pending: i32,
    player_weapon_id: i32,
    player_ammo_q4: i32,
    player_health_q4: i32,
    player_pos_x_q4: i32,
    player_pos_y_q4: i32,
    player_aim_x_q4: i32,
    player_aim_y_q4: i32,
    player_level: i32,
    player_experience: i32,
    bonus_weapon_power_up_ms: i32,
    bonus_reflex_boost_ms: i32,
    bonus_energizer_ms: i32,
    bonus_double_experience_ms: i32,
    bonus_freeze_ms: i32,
    projectile_count: usize,
    projectile0_pos_x_q4: i32,
    projectile0_pos_y_q4: i32,
    projectile0_origin_x_q4: i32,
    projectile0_origin_y_q4: i32,
    projectile0_life_timer_q4: i32,
    projectile0_type_id: i32,
    projectile0_angle_q6: i32,
    projectile0_speed_scale_q4: i32,
    projectile_hit_count: i32,
    projectile_type1_count: usize,
    projectile_type6_count: usize,
    projectile_type6_pos_x_q4: i32,
    projectile_type6_pos_y_q4: i32,
    projectile_type6_origin_x_q4: i32,
    projectile_type6_origin_y_q4: i32,
    projectile_type6_life_timer_q4: i32,
    projectile_type6_damage_pool_q4: i32,
    projectile_type6_b_pos_x_q4: i32,
    projectile_type6_b_pos_y_q4: i32,
    projectile_type6_b_life_timer_q4: i32,
    projectile_type6_b_damage_pool_q4: i32,
    projectile_type11_count: usize,
    projectile_type11_pos_x_q4: i32,
    projectile_type11_pos_y_q4: i32,
    projectile_type11_origin_x_q4: i32,
    projectile_type11_origin_y_q4: i32,
    projectile_type11_life_timer_q4: i32,
    projectile_type11_closest_to_c2_dist_q4: i32,
    projectile_type11_closest_to_c2_pos_x_q4: i32,
    projectile_type11_closest_to_c2_pos_y_q4: i32,
    projectile_type11_closest_to_c2_origin_x_q4: i32,
    projectile_type11_closest_to_c2_origin_y_q4: i32,
    projectile_first_hit_creature_index: i32,
    projectile_first_hit_projectile_index: i32,
    projectile_first_hit_type_id: i32,
    projectile_first_hit_origin_x_q4: i32,
    projectile_first_hit_origin_y_q4: i32,
    projectile_first_hit_pos_x_q4: i32,
    projectile_first_hit_pos_y_q4: i32,
    projectile_first_hit_target_size_q4: i32,
    projectile_first_hit_target_x_q4: i32,
    projectile_first_hit_target_y_q4: i32,
    creature0_active: bool,
    creature0_pos_x_q4: i32,
    creature0_pos_y_q4: i32,
    creature0_hp_q4: i32,
    creature0_hitbox_q4: i32,
    creature1_active: bool,
    creature1_pos_x_q4: i32,
    creature1_pos_y_q4: i32,
    creature1_hp_q4: i32,
    creature1_hitbox_q4: i32,
    creature2_active: bool,
    creature2_pos_x_q4: i32,
    creature2_pos_y_q4: i32,
    creature2_hp_q4: i32,
    creature2_hitbox_q4: i32,
    creature10_active: bool,
    creature10_pos_x_q4: i32,
    creature10_pos_y_q4: i32,
    creature10_hp_q4: i32,
    creature10_hitbox_q4: i32,
    creature12_active: bool,
    creature12_pos_x_q4: i32,
    creature12_pos_y_q4: i32,
    creature12_hp_q4: i32,
    creature12_hitbox_q4: i32,
    creature14_active: bool,
    creature14_pos_x_q4: i32,
    creature14_pos_y_q4: i32,
    creature14_hp_q4: i32,
    creature14_hitbox_q4: i32,
    creature14_size_q4: i32,
    creature14_target_x_q4: i32,
    creature14_target_y_q4: i32,
    creature14_heading_q6: i32,
    creature14_target_heading_q6: i32,
    creature26_active: bool,
    creature26_hp_q4: i32,
    creature26_hitbox_q4: i32,
    creature26_type_id: i32,
    creature26_flags: i32,
    creature26_link_index: i32,
    creature26_ai_mode: i32,
    debug_pending_nuke: i32,
    debug_nuke_kills_last: i32,
    debug_nuke_tick_last: i32,
    debug_nuke_kill_index_sum: i32,
    debug_last_picked_bonus_id: i32,
    debug_last_picked_bonus_amount: i32,
};

pub fn runSurvivalReplayScaffold(
    replay: replay_codec.Replay,
) SurvivalSimError!SurvivalReplayScaffoldResult {
    return runSurvivalReplayScaffoldWithTrace(
        replay,
        null,
        std.heap.page_allocator,
    );
}

pub fn runSurvivalReplayScaffoldWithTrace(
    replay: replay_codec.Replay,
    trace_out: ?*std.ArrayList(SurvivalTickTrace),
    trace_allocator: std.mem.Allocator,
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
    var creatures = survival_creatures.CreaturePool{};
    var projectiles = survival_projectiles.ProjectilePool{};
    var bonuses = survival_bonuses.BonusPool{};
    survival_state.resetPlayers(players[0..], @floatCast(header.world_size), null);
    state.status_quest_unlock_index = header.status.quest_unlock_index;
    state.status_quest_unlock_index_full = header.status.quest_unlock_index_full;
    for (header.status.weapon_usage_counts, 0..) |count, idx| {
        if (idx >= state.status_weapon_usage_counts.len) break;
        state.status_weapon_usage_counts[idx] = count;
    }

    var elapsed_ms_sim: f64 = 0.0;
    const terrain_size: i32 = @max(@as(i32, 1), @as(i32, @intFromFloat(header.world_size)));
    const dt_nominal: f64 = 1.0 / @as(f64, @floatFromInt(header.tick_rate));
    const quest_unlock_index = header.status.quest_unlock_index;
    const player_count = header.player_count;
    const game_mode = header.game_mode_id;

    for (0..replay.tickCount()) |tick_index| {
        if (event_index < events.len and events[event_index].tickIndex() < tick_index) {
            return error.UnsupportedEventOrdering;
        }
        while (event_index < events.len and events[event_index].tickIndex() == tick_index) : (event_index += 1) {
            try applyReplayEvent(
                events[event_index],
                &state,
                players[0..],
                game_mode,
                player_count,
                quest_unlock_index,
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

        survival_perks.updatePerkEffects(&state, players[0..], dt_sim);

        creatures.update(
            &state,
            players[0..],
            dt_sim,
            @floatCast(header.world_size),
            &bonuses,
        );

        const projectile_tick_stats = projectiles.update(
            &state,
            players[0..],
            &creatures,
            &bonuses,
            dt_sim,
            @floatCast(header.world_size),
        );

        updatePlayerFromReplayInput(
            &players[0],
            input,
            &state,
            dt_sim,
            @floatCast(header.world_size),
        );

        survival_weapon_runtime.stepPlayerForTick(
            &state,
            &players[0],
            &projectiles,
            .{
                .fire_down = flags.fire_down,
                .fire_pressed = flags.fire_pressed,
                .reload_pressed = flags.reload_pressed,
            },
            dt_sim,
        ) catch |err| switch (err) {
            error.UnsupportedWeaponFirePath => return error.UnsupportedWeaponFirePath,
        };

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
        for (stage_result.slice()) |spawn_call| {
            creatures.spawnTemplateCall(spawn_call, &state.rng) catch |err| switch (err) {
                error.UnsupportedSpawnTemplate => return error.UnsupportedSpawnTemplate,
            };
        }

        const wave_result = survival_spawn.tickSurvivalWaveSpawnsBatch(
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
        wave_spawn_count += wave_result.count;
        creatures.spawnInits(wave_result.slice());

        cameraShakeUpdate(&state, dt_sim);
        _ = survival_state.survivalProgressionUpdate(&state, players[0..]);
        state.time_scale_active = state.bonuses.reflex_boost > 0.0;
        survival_bonuses.updatePrePickupTimers(&state, dt_sim);
        survival_bonuses.bonusUpdate(
            &bonuses,
            &state,
            players[0..],
            dt_sim,
        ) catch |err| switch (err) {
            error.UnsupportedBonusApplyPath => return error.UnsupportedBonusApplyPath,
        };
        applyPendingBonusEffects(
            &state,
            players[0..],
            &projectiles,
            &creatures,
            &bonuses,
            dt_sim,
            @floatCast(header.world_size),
            tick_index,
        );
        survival_state.survivalEnforceRewardWeaponGuard(state, players[0..]);
        creatures.finalizePostRenderLifecycle();
        elapsed_ms_sim += dt_sim_ms;

        if (trace_out) |trace| {
            try trace.append(
                trace_allocator,
                buildTickTrace(
                    tick_index,
                    elapsed_ms_sim,
                    &state,
                    players[0],
                    &creatures,
                    &projectiles,
                    projectile_tick_stats,
                ),
            );
        }
    }

    const terminal_tick = replay.tickCount();
    if (event_index < events.len and events[event_index].tickIndex() < terminal_tick) {
        return error.UnsupportedEventOrdering;
    }
    while (event_index < events.len and events[event_index].tickIndex() == terminal_tick) : (event_index += 1) {
        try applyReplayEvent(
            events[event_index],
            &state,
            players[0..],
            game_mode,
            player_count,
            quest_unlock_index,
            &perk_menu_open_count,
            &perk_pick_count,
        );
    }
    if (event_index != events.len) return error.UnsupportedEventOrdering;

    const tick_rate_f64: f64 = @floatFromInt(header.tick_rate);
    const ticks_f64: f64 = @floatFromInt(replay.tickCount());
    const elapsed_ms_nominal: i64 = @intFromFloat(@round(ticks_f64 * (1000.0 / tick_rate_f64)));
    const elapsed_ms_sim_i64: i64 = @intFromFloat(elapsed_ms_sim);
    const shots = survival_state.player0Shots(state);
    const most_used_weapon_id = survival_state.mostUsedWeaponIdForPlayer(
        state,
        0,
        players[0].weapon_id,
    );

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
        .most_used_weapon_id = most_used_weapon_id,
        .shots_fired = shots.fired,
        .shots_hit = shots.hit,
        .creature_kill_count = creatures.kill_count,
        .creature_active_count = creatures.activeCount(),
        .perk_pending_count = state.perk_selection.pending_count,
        .survival_reward_handout_enabled = state.survival_reward_handout_enabled,
        .survival_reward_fire_seen = state.survival_reward_fire_seen,
        .survival_reward_damage_seen = state.survival_reward_damage_seen,
        .spawn_stage = spawn_stage,
        .spawn_cooldown_ms = spawn_cooldown,
    };
}

fn buildTickTrace(
    tick_index: usize,
    elapsed_ms_sim: f64,
    state: *const survival_state.GameplayState,
    player: survival_state.PlayerState,
    creatures: *const survival_creatures.CreaturePool,
    projectiles: *const survival_projectiles.ProjectilePool,
    projectile_tick_stats: survival_projectiles.ProjectileTickStats,
) SurvivalTickTrace {
    var projectile_count: usize = 0;
    var projectile0 = survival_projectiles.Projectile{};
    var projectile0_found = false;
    var projectile_type1_count: usize = 0;
    var projectile_type6_count: usize = 0;
    var projectile_type6 = survival_projectiles.Projectile{};
    var projectile_type6_found = false;
    var projectile_type6_b = survival_projectiles.Projectile{};
    var projectile_type6_b_found = false;
    var projectile_type11_count: usize = 0;
    var projectile_type11 = survival_projectiles.Projectile{};
    var projectile_type11_found = false;
    var projectile_type11_closest = survival_projectiles.Projectile{};
    var projectile_type11_closest_found = false;
    var projectile_type11_closest_dist = std.math.inf(f64);
    const creature2_pos = creatures.entries[2].pos;
    for (projectiles.entries) |entry| {
        if (!entry.active) continue;
        projectile_count += 1;
        if (!projectile0_found) {
            projectile0_found = true;
            projectile0 = entry;
        }
        if (entry.type_id == 1) {
            projectile_type1_count += 1;
        }
        if (entry.type_id == 6) {
            projectile_type6_count += 1;
            if (!projectile_type6_found) {
                projectile_type6_found = true;
                projectile_type6 = entry;
            } else if (!projectile_type6_b_found) {
                projectile_type6_b_found = true;
                projectile_type6_b = entry;
            }
        }
        if (entry.type_id == 11) {
            projectile_type11_count += 1;
            if (!projectile_type11_found) {
                projectile_type11_found = true;
                projectile_type11 = entry;
            }
            const dx = entry.pos.x - creature2_pos.x;
            const dy = entry.pos.y - creature2_pos.y;
            const dist = std.math.sqrt(dx * dx + dy * dy);
            if (!projectile_type11_closest_found or dist < projectile_type11_closest_dist) {
                projectile_type11_closest_found = true;
                projectile_type11_closest_dist = dist;
                projectile_type11_closest = entry;
            }
        }
    }

    return .{
        .tick = tick_index,
        .rng_state = state.rng.state,
        .elapsed_ms = @intFromFloat(@round(elapsed_ms_sim)),
        .score_xp = player.experience,
        .kills = creatures.kill_count,
        .creature_count = creatures.activeCount(),
        .perk_pending = state.perk_selection.pending_count,
        .player_weapon_id = player.weapon_id,
        .player_ammo_q4 = quantizeQ4(player.ammo),
        .player_health_q4 = quantizeQ4(player.health),
        .player_pos_x_q4 = quantizeQ4(player.pos.x),
        .player_pos_y_q4 = quantizeQ4(player.pos.y),
        .player_aim_x_q4 = quantizeQ4(player.aim.x),
        .player_aim_y_q4 = quantizeQ4(player.aim.y),
        .player_level = player.level,
        .player_experience = player.experience,
        .bonus_weapon_power_up_ms = bonusTimerMs(state.bonuses.weapon_power_up),
        .bonus_reflex_boost_ms = bonusTimerMs(state.bonuses.reflex_boost),
        .bonus_energizer_ms = bonusTimerMs(state.bonuses.energizer),
        .bonus_double_experience_ms = bonusTimerMs(state.bonuses.double_experience),
        .bonus_freeze_ms = bonusTimerMs(state.bonuses.freeze),
        .projectile_count = projectile_count,
        .projectile0_pos_x_q4 = if (projectile0_found) quantizeQ4(projectile0.pos.x) else 0,
        .projectile0_pos_y_q4 = if (projectile0_found) quantizeQ4(projectile0.pos.y) else 0,
        .projectile0_origin_x_q4 = if (projectile0_found) quantizeQ4(projectile0.origin.x) else 0,
        .projectile0_origin_y_q4 = if (projectile0_found) quantizeQ4(projectile0.origin.y) else 0,
        .projectile0_life_timer_q4 = if (projectile0_found) quantizeQ4(projectile0.life_timer) else 0,
        .projectile0_type_id = if (projectile0_found) projectile0.type_id else 0,
        .projectile0_angle_q6 = if (projectile0_found) quantizeQ6(projectile0.angle) else 0,
        .projectile0_speed_scale_q4 = if (projectile0_found) quantizeQ4(projectile0.speed_scale) else 0,
        .projectile_hit_count = projectile_tick_stats.hit_count,
        .projectile_type1_count = projectile_type1_count,
        .projectile_type6_count = projectile_type6_count,
        .projectile_type6_pos_x_q4 = if (projectile_type6_found) quantizeQ4(projectile_type6.pos.x) else 0,
        .projectile_type6_pos_y_q4 = if (projectile_type6_found) quantizeQ4(projectile_type6.pos.y) else 0,
        .projectile_type6_origin_x_q4 = if (projectile_type6_found) quantizeQ4(projectile_type6.origin.x) else 0,
        .projectile_type6_origin_y_q4 = if (projectile_type6_found) quantizeQ4(projectile_type6.origin.y) else 0,
        .projectile_type6_life_timer_q4 = if (projectile_type6_found) quantizeQ4(projectile_type6.life_timer) else 0,
        .projectile_type6_damage_pool_q4 = if (projectile_type6_found) quantizeQ4(projectile_type6.damage_pool) else 0,
        .projectile_type6_b_pos_x_q4 = if (projectile_type6_b_found) quantizeQ4(projectile_type6_b.pos.x) else 0,
        .projectile_type6_b_pos_y_q4 = if (projectile_type6_b_found) quantizeQ4(projectile_type6_b.pos.y) else 0,
        .projectile_type6_b_life_timer_q4 = if (projectile_type6_b_found) quantizeQ4(projectile_type6_b.life_timer) else 0,
        .projectile_type6_b_damage_pool_q4 = if (projectile_type6_b_found) quantizeQ4(projectile_type6_b.damage_pool) else 0,
        .projectile_type11_count = projectile_type11_count,
        .projectile_type11_pos_x_q4 = if (projectile_type11_found) quantizeQ4(projectile_type11.pos.x) else 0,
        .projectile_type11_pos_y_q4 = if (projectile_type11_found) quantizeQ4(projectile_type11.pos.y) else 0,
        .projectile_type11_origin_x_q4 = if (projectile_type11_found) quantizeQ4(projectile_type11.origin.x) else 0,
        .projectile_type11_origin_y_q4 = if (projectile_type11_found) quantizeQ4(projectile_type11.origin.y) else 0,
        .projectile_type11_life_timer_q4 = if (projectile_type11_found) quantizeQ4(projectile_type11.life_timer) else 0,
        .projectile_type11_closest_to_c2_dist_q4 = if (projectile_type11_closest_found) quantizeQ4(projectile_type11_closest_dist) else 0,
        .projectile_type11_closest_to_c2_pos_x_q4 = if (projectile_type11_closest_found) quantizeQ4(projectile_type11_closest.pos.x) else 0,
        .projectile_type11_closest_to_c2_pos_y_q4 = if (projectile_type11_closest_found) quantizeQ4(projectile_type11_closest.pos.y) else 0,
        .projectile_type11_closest_to_c2_origin_x_q4 = if (projectile_type11_closest_found) quantizeQ4(projectile_type11_closest.origin.x) else 0,
        .projectile_type11_closest_to_c2_origin_y_q4 = if (projectile_type11_closest_found) quantizeQ4(projectile_type11_closest.origin.y) else 0,
        .projectile_first_hit_creature_index = projectile_tick_stats.first_hit_creature_index,
        .projectile_first_hit_projectile_index = projectile_tick_stats.first_hit_projectile_index,
        .projectile_first_hit_type_id = projectile_tick_stats.first_hit_type_id,
        .projectile_first_hit_origin_x_q4 = quantizeQ4(projectile_tick_stats.first_hit_origin.x),
        .projectile_first_hit_origin_y_q4 = quantizeQ4(projectile_tick_stats.first_hit_origin.y),
        .projectile_first_hit_pos_x_q4 = quantizeQ4(projectile_tick_stats.first_hit_pos.x),
        .projectile_first_hit_pos_y_q4 = quantizeQ4(projectile_tick_stats.first_hit_pos.y),
        .projectile_first_hit_target_size_q4 = quantizeQ4(projectile_tick_stats.first_hit_target_size),
        .projectile_first_hit_target_x_q4 = quantizeQ4(projectile_tick_stats.first_hit_target_x),
        .projectile_first_hit_target_y_q4 = quantizeQ4(projectile_tick_stats.first_hit_target_y),
        .creature0_active = creatures.entries[0].active,
        .creature0_pos_x_q4 = quantizeQ4(creatures.entries[0].pos.x),
        .creature0_pos_y_q4 = quantizeQ4(creatures.entries[0].pos.y),
        .creature0_hp_q4 = quantizeQ4(creatures.entries[0].hp),
        .creature0_hitbox_q4 = quantizeQ4(creatures.entries[0].hitbox_size),
        .creature1_active = creatures.entries[1].active,
        .creature1_pos_x_q4 = quantizeQ4(creatures.entries[1].pos.x),
        .creature1_pos_y_q4 = quantizeQ4(creatures.entries[1].pos.y),
        .creature1_hp_q4 = quantizeQ4(creatures.entries[1].hp),
        .creature1_hitbox_q4 = quantizeQ4(creatures.entries[1].hitbox_size),
        .creature2_active = creatures.entries[2].active,
        .creature2_pos_x_q4 = quantizeQ4(creatures.entries[2].pos.x),
        .creature2_pos_y_q4 = quantizeQ4(creatures.entries[2].pos.y),
        .creature2_hp_q4 = quantizeQ4(creatures.entries[2].hp),
        .creature2_hitbox_q4 = quantizeQ4(creatures.entries[2].hitbox_size),
        .creature10_active = creatures.entries[10].active,
        .creature10_pos_x_q4 = quantizeQ4(creatures.entries[10].pos.x),
        .creature10_pos_y_q4 = quantizeQ4(creatures.entries[10].pos.y),
        .creature10_hp_q4 = quantizeQ4(creatures.entries[10].hp),
        .creature10_hitbox_q4 = quantizeQ4(creatures.entries[10].hitbox_size),
        .creature12_active = creatures.entries[12].active,
        .creature12_pos_x_q4 = quantizeQ4(creatures.entries[12].pos.x),
        .creature12_pos_y_q4 = quantizeQ4(creatures.entries[12].pos.y),
        .creature12_hp_q4 = quantizeQ4(creatures.entries[12].hp),
        .creature12_hitbox_q4 = quantizeQ4(creatures.entries[12].hitbox_size),
        .creature14_active = creatures.entries[14].active,
        .creature14_pos_x_q4 = quantizeQ4(creatures.entries[14].pos.x),
        .creature14_pos_y_q4 = quantizeQ4(creatures.entries[14].pos.y),
        .creature14_hp_q4 = quantizeQ4(creatures.entries[14].hp),
        .creature14_hitbox_q4 = quantizeQ4(creatures.entries[14].hitbox_size),
        .creature14_size_q4 = quantizeQ4(creatures.entries[14].size),
        .creature14_target_x_q4 = quantizeQ4(creatures.entries[14].target.x),
        .creature14_target_y_q4 = quantizeQ4(creatures.entries[14].target.y),
        .creature14_heading_q6 = quantizeQ6(creatures.entries[14].heading),
        .creature14_target_heading_q6 = quantizeQ6(creatures.entries[14].target_heading),
        .creature26_active = creatures.entries[26].active,
        .creature26_hp_q4 = quantizeQ4(creatures.entries[26].hp),
        .creature26_hitbox_q4 = quantizeQ4(creatures.entries[26].hitbox_size),
        .creature26_type_id = creatures.entries[26].type_id,
        .creature26_flags = @bitCast(creatures.entries[26].flags),
        .creature26_link_index = creatures.entries[26].link_index,
        .creature26_ai_mode = creatures.entries[26].ai_mode,
        .debug_pending_nuke = state.pending_nuke_count,
        .debug_nuke_kills_last = state.debug_nuke_kills_last,
        .debug_nuke_tick_last = state.debug_nuke_tick_last,
        .debug_nuke_kill_index_sum = state.debug_nuke_kill_index_sum,
        .debug_last_picked_bonus_id = state.debug_last_picked_bonus_id,
        .debug_last_picked_bonus_amount = state.debug_last_picked_bonus_amount,
    };
}

fn quantizeQ4(value: f64) i32 {
    const scaled = @round(value * 10000.0);
    if (scaled <= @as(f64, @floatFromInt(std.math.minInt(i32)))) return std.math.minInt(i32);
    if (scaled >= @as(f64, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(scaled);
}

fn quantizeQ6(value: f64) i32 {
    const scaled = @round(value * 1_000_000.0);
    if (scaled <= @as(f64, @floatFromInt(std.math.minInt(i32)))) return std.math.minInt(i32);
    if (scaled >= @as(f64, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(scaled);
}

fn bonusTimerMs(seconds: f64) i32 {
    if (!(seconds > 0.0)) return 0;
    const ms = @round(seconds * 1000.0);
    if (ms <= 0.0) return 0;
    if (ms >= @as(f64, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(ms);
}

fn cameraShakeUpdate(
    state: *survival_state.GameplayState,
    dt: f64,
) void {
    if (state.camera_shake_timer <= 0.0) {
        state.camera_shake_offset = .{};
        return;
    }

    state.camera_shake_timer = asF32F64(state.camera_shake_timer - asF32F64(dt * 3.0));
    if (state.camera_shake_timer >= 0.0) return;

    state.camera_shake_pulses -= 1;
    if (state.camera_shake_pulses < 1) {
        state.camera_shake_timer = 0.0;
        return;
    }

    state.camera_shake_timer = if (state.bonuses.reflex_boost > 0.0) 0.06 else 0.1;
    const max_amp = state.camera_shake_pulses * 3;
    if (max_amp <= 0) {
        state.camera_shake_offset = .{};
        state.camera_shake_timer = 0.0;
        state.camera_shake_pulses = 0;
        return;
    }

    const max_amp_u32: u32 = @intCast(max_amp);
    var mag_x: i32 = @intCast(state.rng.rand() % max_amp_u32);
    mag_x += @intCast(state.rng.rand() % 10);
    if ((state.rng.rand() & 1) == 0) {
        mag_x = -mag_x;
    }

    var mag_y: i32 = @intCast(state.rng.rand() % max_amp_u32);
    mag_y += @intCast(state.rng.rand() % 10);
    if ((state.rng.rand() & 1) == 0) {
        mag_y = -mag_y;
    }

    state.camera_shake_offset = .{
        .x = asF32F64(@floatFromInt(mag_x)),
        .y = asF32F64(@floatFromInt(mag_y)),
    };
}

fn applyPendingBonusEffects(
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    creatures: *survival_creatures.CreaturePool,
    bonuses: *survival_bonuses.BonusPool,
    dt: f64,
    world_size: f64,
    tick_index: usize,
) void {
    state.debug_nuke_kills_last = 0;
    state.debug_nuke_tick_last = -1;
    state.debug_nuke_kill_index_sum = 0;
    const pending_count_i32 = @min(state.pending_nuke_count, @as(i32, @intCast(state.pending_nuke_origins.len)));
    var pending_idx: i32 = 0;
    while (pending_idx < pending_count_i32) : (pending_idx += 1) {
        const origin = state.pending_nuke_origins[@intCast(pending_idx)];
        applyNukeBonus(
            state,
            players,
            projectiles,
            creatures,
            bonuses,
            origin,
            dt,
            world_size,
            tick_index,
        );
    }
    state.pending_nuke_count = 0;
}

fn applyNukeBonus(
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    projectiles: *survival_projectiles.ProjectilePool,
    creatures: *survival_creatures.CreaturePool,
    bonuses: *survival_bonuses.BonusPool,
    origin: survival_state.Vec2,
    dt: f64,
    world_size: f64,
    tick_index: usize,
) void {
    if (players.len == 0) return;
    const player = &players[0];
    const projectile_owner_id: i32 = -100;
    const damage_owner_id: i32 = -1 - player.index;
    var nuke_kill_count: i32 = 0;
    state.camera_shake_pulses = 0x14;
    state.camera_shake_timer = 0.2;

    var bullet_count: i32 = @intCast(state.rng.rand() & 3);
    bullet_count += 4;
    var bullet_idx: i32 = 0;
    while (bullet_idx < bullet_count) : (bullet_idx += 1) {
        const angle_heading = @as(f64, @floatFromInt(state.rng.rand() % 0x274)) * 0.01;
        const angle = angle_heading - native_half_pi;
        var type_id = survival_state.ProjectileTypeId.pistol;
        applyPlayerProjectileSpawnRules(state, players, projectile_owner_id, &type_id);
        const meta = survival_state.weaponProjectileMeta(type_id);
        const proj_idx = projectiles.spawn(origin, angle, type_id, projectile_owner_id, meta, false);
        const speed_scale = asF32F64(@as(f64, @floatFromInt(state.rng.rand() % 0x32)) * 0.01 + 0.5);
        projectiles.entries[proj_idx].speed_scale = asF32F64(projectiles.entries[proj_idx].speed_scale * speed_scale);
    }

    for (0..2) |_| {
        const angle_heading = @as(f64, @floatFromInt(state.rng.rand() % 0x274)) * 0.01;
        const angle = angle_heading - native_half_pi;
        var type_id = survival_state.ProjectileTypeId.gauss_gun;
        applyPlayerProjectileSpawnRules(state, players, projectile_owner_id, &type_id);
        const meta = survival_state.weaponProjectileMeta(type_id);
        _ = projectiles.spawn(origin, angle, type_id, projectile_owner_id, meta, false);
    }

    consumeExplosionBurstRng(state, 5);

    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        const dx = creature.pos.x - origin.x;
        const dy = creature.pos.y - origin.y;
        if (@abs(dx) > 256.0 or @abs(dy) > 256.0) continue;
        const dist = std.math.sqrt(dx * dx + dy * dy);
        if (dist >= 256.0) continue;
        const damage = (256.0 - dist) * 5.0;
        const xp = creatures.applyExplosionDamage(
            state,
            players,
            bonuses,
            idx,
            damage,
            damage_owner_id,
            dt,
            world_size,
        );
        if (xp > 0) {
            state.debug_nuke_kill_index_sum += @intCast(idx);
            nuke_kill_count += 1;
        }
    }
    state.debug_nuke_kills_last = nuke_kill_count;
    state.debug_nuke_tick_last = @intCast(tick_index);
}

fn applyPlayerProjectileSpawnRules(
    state: *survival_state.GameplayState,
    players: []const survival_state.PlayerState,
    owner_id: i32,
    type_id: *i32,
) void {
    if (state.bonus_spawn_guard) return;
    if (owner_id != -100 and owner_id != -1 and owner_id != -2 and owner_id != -3) return;

    state.shots_fired_total += 1;

    var player_index: ?usize = null;
    if (owner_id == -100 and players.len == 1) {
        player_index = 0;
    } else if (owner_id < 0 and owner_id != -100) {
        const idx: i32 = -1 - owner_id;
        if (idx >= 0) {
            const as_usize: usize = @intCast(idx);
            if (as_usize < players.len) {
                player_index = as_usize;
            }
        }
    }

    if (player_index) |idx| {
        if (idx < state.shots_fired.len) {
            state.shots_fired[idx] += 1;
        }
        if (type_id.* != survival_state.ProjectileTypeId.fire_bullets and
            players[idx].fire_bullets_timer > 0.0)
        {
            type_id.* = survival_state.ProjectileTypeId.fire_bullets;
        }
    }
}

fn consumeExplosionBurstRng(
    state: *survival_state.GameplayState,
    detail_preset: i32,
) void {
    if (detail_preset > 3) {
        for (0..2) |_| {
            _ = state.rng.rand() % 0x266;
        }
    }
    const count: usize = if (detail_preset < 2) 1 else 3 + (if (detail_preset > 3) @as(usize, 1) else 0);
    for (0..count) |_| {
        _ = state.rng.rand() % 0x13A;
        _ = state.rng.rand() & 0x3F;
        _ = state.rng.rand() & 0x3F;
        _ = state.rng.rand();
        _ = state.rng.rand();
    }
}

fn applyReplayEvent(
    event: replay_codec.ReplayEvent,
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    game_mode: i32,
    player_count: i32,
    quest_unlock_index: i32,
    perk_menu_open_count: *usize,
    perk_pick_count: *usize,
) SurvivalSimError!void {
    switch (event) {
        .perk_menu_open => |open| {
            if (open.player_index != 0) return error.UnsupportedEventPlayerIndex;
            _ = survival_perks.perkSelectionCurrentChoices(
                state,
                players,
                game_mode,
                player_count,
                quest_unlock_index,
            );
            perk_menu_open_count.* += 1;
        },
        .perk_pick => |pick| {
            if (pick.player_index != 0) return error.UnsupportedEventPlayerIndex;
            const applied = survival_perks.perkSelectionPick(
                state,
                players,
                pick.choice_index,
                game_mode,
                player_count,
                quest_unlock_index,
            ) catch |err| switch (err) {
                error.UnsupportedPerkApplyHandler => return error.UnsupportedPerkApplyHandler,
            };
            if (applied == null) {
                return error.InvalidPerkPickEvent;
            }
            perk_pick_count.* += 1;
        },
    }
}

fn updatePlayerFromReplayInput(
    player: *survival_state.PlayerState,
    input: replay_codec.ReplayPlayerInput,
    state: *const survival_state.GameplayState,
    dt: f64,
    world_size: f64,
) void {
    const dt_f32 = asF32F64(dt);
    var movement_dt = dt_f32;
    if (state.time_scale_active and movement_dt > 0.0) {
        const reflex_f32 = asF32F64(state.bonuses.reflex_boost);
        var time_scale_factor = asF32F64(0.3);
        if (reflex_f32 < 1.0) {
            time_scale_factor = asF32F64((1.0 - reflex_f32) * 0.7 + 0.3);
        }
        if (time_scale_factor > 0.0) {
            movement_dt = asF32F64((0.6 / time_scale_factor) * movement_dt);
        }
    }

    var raw_move = survival_state.Vec2{
        .x = input.move_x,
        .y = input.move_y,
    };
    const raw_mag = raw_move.length();
    var move = directionFromHeadingNative(player.heading);

    var speed_multiplier = player.speed_multiplier;
    if (player.speed_bonus_timer > 0.0) {
        speed_multiplier += 1.0;
    }

    const moving_input = raw_mag > 0.2;
    var turn_alignment_scale: f64 = 1.0;
    if (moving_input) {
        const inv = if (raw_mag > 1e-9) 1.0 / raw_mag else 0.0;
        raw_move = raw_move.mul(inv);
        const target_heading = normalizeHeading(raw_move.toHeading());
        const angle_diff = playerHeadingApproachTarget(player, target_heading, movement_dt);
        move = directionFromHeadingNative(player.heading);
        turn_alignment_scale = @max(0.0, (std.math.pi - angle_diff) / std.math.pi);
        playerAccelerateMoveSpeed(player, movement_dt);
    } else {
        playerDecelerateMoveSpeed(player, movement_dt);
        move = directionFromHeadingNative(player.heading);
    }

    playerApplyMoveSpeedCaps(player);

    var speed = player.move_speed * speed_multiplier * 25.0;
    if (moving_input) {
        speed *= @min(1.0, raw_mag);
        speed *= turn_alignment_scale;
    }

    const move_step = asF32F64(speed * movement_dt);
    const delta = survival_state.Vec2{
        .x = asF32F64(move.x * move_step),
        .y = asF32F64(move.y * move_step),
    };
    player.pos = survival_state.Vec2.add(player.pos, delta);

    const half_size = @max(0.0, player.size * 0.5);
    player.pos = player.pos.clampRect(
        half_size,
        half_size,
        world_size - half_size,
        world_size - half_size,
    );

    player.aim = .{
        .x = input.aim_x,
        .y = input.aim_y,
    };
    var aim_dir = survival_state.Vec2.sub(player.aim, player.pos);
    const aim_len_sq = aim_dir.lengthSq();
    if (aim_len_sq > 1e-9) {
        aim_dir = aim_dir.mul(1.0 / std.math.sqrt(aim_len_sq));
        player.aim_dir = .{
            .x = asF32F64(aim_dir.x),
            .y = asF32F64(aim_dir.y),
        };
    }
}

fn directionFromHeadingNative(heading: f64) survival_state.Vec2 {
    const radians = heading - native_half_pi;
    return .{
        .x = std.math.cos(radians),
        .y = std.math.sin(radians),
    };
}

fn playerAccelerateMoveSpeed(
    player: *survival_state.PlayerState,
    dt: f64,
) void {
    const dt_f32 = asF32F64(dt);
    if (perkActive(player.*, survival_perks.PerkId.long_distance_runner)) {
        if (player.move_speed < 2.0) {
            player.move_speed = asF32F64(player.move_speed + dt_f32 * 4.0);
        }
        player.move_speed = asF32F64(player.move_speed + dt_f32);
        if (player.move_speed > 2.8) player.move_speed = 2.8;
    } else {
        player.move_speed = asF32F64(player.move_speed + dt_f32 * 5.0);
        if (player.move_speed > 2.0) player.move_speed = 2.0;
    }
}

fn playerDecelerateMoveSpeed(
    player: *survival_state.PlayerState,
    dt: f64,
) void {
    const dt_f32 = asF32F64(dt);
    player.move_speed = asF32F64(player.move_speed - dt_f32 * 15.0);
    if (player.move_speed < 0.0) player.move_speed = 0.0;
}

fn playerApplyMoveSpeedCaps(
    player: *survival_state.PlayerState,
) void {
    if (player.weapon_id == survival_state.WeaponId.mean_minigun and player.move_speed > 0.8) {
        player.move_speed = 0.8;
    }
}

fn playerHeadingApproachTarget(
    player: *survival_state.PlayerState,
    target_heading: f64,
    dt: f64,
) f64 {
    var heading = asF32F64(normalizeHeading(player.heading));
    player.heading = heading;
    const target = asF32F64(target_heading);

    const direct = asF32F64(@abs(asF32F64(target - heading)));
    var high = heading;
    if (target > high) high = target;
    var low = heading;
    if (target < low) low = target;
    const wrapped = asF32F64(@abs(asF32F64(native_tau - high + low)));
    const diff = if (direct >= wrapped) wrapped else direct;

    const dt_f32 = asF32F64(dt);
    const scaled = asF32F64(dt_f32 * diff);
    var turn_delta: f64 = 0.0;
    if (direct <= wrapped) {
        if (target > heading) {
            turn_delta = asF32F64(scaled * 5.0);
        } else {
            turn_delta = asF32F64(scaled * -5.0);
        }
    } else {
        if (target >= heading) {
            turn_delta = asF32F64(scaled * -5.0);
        } else {
            turn_delta = asF32F64(scaled * 5.0);
        }
    }

    heading = asF32F64(heading + turn_delta);
    player.heading = heading;
    return diff;
}

fn normalizeHeading(value: f64) f64 {
    var angle = asF32F64(value);
    while (angle < 0.0) {
        angle = asF32F64(angle + native_tau);
    }
    while (angle > native_tau) {
        angle = asF32F64(angle - native_tau);
    }
    return angle;
}

fn perkActive(player: survival_state.PlayerState, perk_id: i32) bool {
    if (perk_id < 0 or perk_id >= player.perk_counts.len) return false;
    return player.perk_counts[@intCast(perk_id)] > 0;
}

fn asF32F64(value: f64) f64 {
    const rounded: f32 = @floatCast(value);
    return @floatCast(rounded);
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
        },
    });
    defer replay.deinit(allocator);

    const result = try runSurvivalReplayScaffold(replay);
    try std.testing.expectEqual(@as(usize, 2), result.ticks);
    try std.testing.expectEqual(@as(i64, 33), result.elapsed_ms_nominal);
    try std.testing.expectEqual(@as(i64, 33), result.elapsed_ms_sim);
    try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
    try std.testing.expectEqual(@as(usize, 0), result.perk_pick_count);
    try std.testing.expectEqual(@as(usize, 1), result.fire_pressed_count);
    try std.testing.expectEqual(@as(usize, 1), result.reload_pressed_count);
    try std.testing.expectEqual(@as(usize, 0), result.stage_spawn_count);
    try std.testing.expectEqual(@as(usize, 1), result.wave_spawn_count);
    try std.testing.expectEqual(survival_state.WeaponId.pistol, result.player_weapon_id);
    try std.testing.expectEqual(survival_state.WeaponId.pistol, result.most_used_weapon_id);
    try std.testing.expectEqual(@as(i32, 0), result.shots_fired);
    try std.testing.expectEqual(@as(i32, 0), result.shots_hit);
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

test "survival scaffold rejects invalid perk pick without pending count" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag},
        .events = &.{
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.InvalidPerkPickEvent,
        runSurvivalReplayScaffold(replay),
    );
}

test "survival scaffold tracks weapon runtime counters" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{
            replay_codec.fire_down_flag,
            replay_codec.fire_down_flag,
        },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runSurvivalReplayScaffold(replay);
    try std.testing.expectEqual(@as(i32, 1), result.shots_fired);
    try std.testing.expectEqual(@as(i32, 0), result.shots_hit);
    try std.testing.expectEqual(survival_state.WeaponId.pistol, result.most_used_weapon_id);
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
