const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");

const replay_codec = @import("../replay_codec.zig");
const survival_bonuses = @import("bonuses.zig");
const survival_creatures = @import("creatures.zig");
const survival_perks = @import("perks.zig");
const survival_particles = @import("particles.zig");
const survival_projectiles = @import("projectiles.zig");
const survival_secondary_projectiles = @import("secondary_projectiles.zig");
const survival_spawn = @import("spawn.zig");
const quest_spawn_logic = @import("../quest_spawn/logic_full.zig");
const survival_state = @import("state.zig");
const survival_weapon_runtime = @import("weapons.zig");
const survival_math = @import("math.zig");

const asF32F64 = native_math.roundF32;
const creature_lifecycle_stage_alive: f64 = 16.0;
const native_half_pi: f64 = native_math.f64f32(native_math.native_half_pi);
const native_pi: f64 = native_math.f64f32(native_math.native_pi);
const native_tau: f64 = native_math.f64f32(native_math.native_tau);
const relative_move_heading_none: f64 = -1.0;
const relative_move_heading_forward: f64 = 0.0;
const relative_move_heading_forward_right: f64 = 0.7853981852531433;
const relative_move_heading_right: f64 = native_half_pi;
const relative_move_heading_backward_right: f64 = 2.356194496154785;
const relative_move_heading_backward: f64 = native_pi;
const relative_move_heading_backward_left: f64 = 3.9269909858703613;
const relative_move_heading_left: f64 = native_math.f64f32(native_tau - native_half_pi);
const relative_move_heading_forward_left: f64 = 5.4977874755859375;
const relative_move_turn_align_scale: f64 = 7.957746982574463;
const movement_control_relative: i32 = 1;
const movement_control_static: i32 = 2;
const movement_control_dual_action_pad: i32 = 3;
const movement_control_computer: i32 = 5;
const aim_scheme_mouse: i32 = 0;
const aim_scheme_computer: i32 = 5;
const game_mode_survival: i32 = 1;
const game_mode_rush: i32 = 2;
const game_mode_quests: i32 = 3;
const TickEventPhase = enum {
    pre_step,
    post_state_transition,
    post_spawn_hook,
    post_menu_open,
};
const max_test_quest_spawn_entries: usize = 1024;
const perk_id_jinxed: i32 = survival_perks.PerkId.jinxed;

pub const ReplayRunnerError = error{
    OutOfMemory,
    UnsupportedGameMode,
    UnsupportedPlayerCount,
    UnsupportedInputQuantization,
    UnsupportedPreserveBugs,
    UnsupportedEventOrdering,
    UnsupportedEventKind,
    UnsupportedEventPlayerIndex,
    InvalidPerkPickEvent,
    UnsupportedPerkApplyHandler,
    UnsupportedSpawnTemplate,
    UnsupportedQuestSpawnTable,
    UnsupportedWeaponFirePath,
    UnsupportedBonusApplyPath,
};

pub const ReplayScaffoldResult = struct {
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
    quest_completion_transition_ms: f64,
    quest_completed: bool,
    quest_play_hit_sfx: bool,
    quest_play_completion_music: bool,
};

pub const ReplayTickTrace = struct {
    tick: usize,
    rng_state: u32,
    rng_after_perk_effects: u32,
    rng_after_creatures: u32,
    rng_after_projectiles: u32,
    rng_after_secondary_projectiles: u32,
    rng_after_particles: u32,
    rng_after_player_update: u32,
    rng_after_stage_spawns: u32,
    rng_after_wave_spawns: u32,
    rng_after_spawns: u32,
    rng_after_bonus_update: u32,
    elapsed_ms: i64,
    score_xp: i32,
    kills: i32,
    shots_fired_p0: i32,
    creature_count: usize,
    creature_active_index_sum: i32,
    creature_active_index_xor: i32,
    creature_state_hash: u64,
    perk_pending: i32,
    player_weapon_id: i32,
    player_ammo_q4: i32,
    player_health_q4: i32,
    player_pos_x_q4: i32,
    player_pos_y_q4: i32,
    player_aim_x_q4: i32,
    player_aim_y_q4: i32,
    player_heading_q6: i32,
    player_aim_heading_q6: i32,
    player_move_speed_q4: i32,
    player_turn_speed_q4: i32,
    player_level: i32,
    player_experience: i32,
    player_reload_active: bool,
    player_reload_timer_q4: i32,
    player_shot_cooldown_q4: i32,
    player_shot_seq: i32,
    player_perk31_count: i32,
    player_perk53_count: i32,
    player_perk54_count: i32,
    player_perk55_count: i32,
    player_hot_tempered_timer_q6: i32,
    player_shield_timer_q4: i32,
    player_man_bomb_timer_q6: i32,
    player_fire_cough_timer_q6: i32,
    player_living_fortress_timer_q6: i32,
    perk_interval_hot_tempered_q6: i32,
    perk_interval_man_bomb_q6: i32,
    perk_interval_fire_cough_q6: i32,
    bonus_weapon_power_up_ms: i32,
    bonus_reflex_boost_ms: i32,
    bonus_energizer_ms: i32,
    bonus_double_experience_ms: i32,
    bonus_freeze_ms: i32,
    bonus_active_count: usize,
    bonus0_id: i32,
    bonus0_amount: i32,
    bonus1_id: i32,
    bonus1_amount: i32,
    projectile_state_hash: u64,
    projectile_count: usize,
    projectile_active_index_sum: i32,
    projectile_active_index_xor: i32,
    projectile_type45_count: usize,
    projectile0_pos_x_q4: i32,
    projectile0_pos_y_q4: i32,
    projectile0_origin_x_q4: i32,
    projectile0_origin_y_q4: i32,
    projectile0_life_timer_q4: i32,
    projectile0_type_id: i32,
    projectile0_angle_q6: i32,
    projectile0_speed_scale_q4: i32,
    projectile1_active: bool,
    projectile1_pos_x_q4: i32,
    projectile1_pos_y_q4: i32,
    projectile1_origin_x_q4: i32,
    projectile1_origin_y_q4: i32,
    projectile1_life_timer_q4: i32,
    projectile1_type_id: i32,
    projectile1_angle_q6: i32,
    projectile1_damage_pool_q4: i32,
    projectile6_active: bool,
    projectile6_type_id: i32,
    projectile6_pos_x_q4: i32,
    projectile6_pos_y_q4: i32,
    projectile6_origin_x_q4: i32,
    projectile6_origin_y_q4: i32,
    projectile6_life_timer_q4: i32,
    projectile6_damage_pool_q4: i32,
    projectile6_angle_q6: i32,
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
    projectile_type21_count: usize,
    projectile_type21_pos_x_q4: i32,
    projectile_type21_pos_y_q4: i32,
    projectile_type21_origin_x_q4: i32,
    projectile_type21_origin_y_q4: i32,
    projectile_type21_life_timer_q4: i32,
    projectile_type21_angle_q6: i32,
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
    creature0_lifecycle_stage_q4: i32,
    creature1_active: bool,
    creature1_pos_x_q4: i32,
    creature1_pos_y_q4: i32,
    creature1_hp_q4: i32,
    creature1_lifecycle_stage_q4: i32,
    creature2_active: bool,
    creature2_pos_x_q4: i32,
    creature2_pos_y_q4: i32,
    creature2_hp_q4: i32,
    creature2_lifecycle_stage_q4: i32,
    creature10_active: bool,
    creature10_pos_x_q4: i32,
    creature10_pos_y_q4: i32,
    creature10_hp_q4: i32,
    creature10_lifecycle_stage_q4: i32,
    creature12_active: bool,
    creature12_pos_x_q4: i32,
    creature12_pos_y_q4: i32,
    creature12_hp_q4: i32,
    creature12_lifecycle_stage_q4: i32,
    creature14_active: bool,
    creature14_pos_x_q4: i32,
    creature14_pos_y_q4: i32,
    creature14_hp_q4: i32,
    creature14_lifecycle_stage_q4: i32,
    creature14_size_q4: i32,
    creature14_target_x_q4: i32,
    creature14_target_y_q4: i32,
    creature14_heading_q6: i32,
    creature14_target_heading_q6: i32,
    creature15_active: bool,
    creature15_pos_x_q4: i32,
    creature15_pos_y_q4: i32,
    creature15_hp_q4: i32,
    creature15_lifecycle_stage_q4: i32,
    creature18_active: bool,
    creature18_pos_x_q4: i32,
    creature18_pos_y_q4: i32,
    creature18_hp_q4: i32,
    creature18_lifecycle_stage_q4: i32,
    creature18_target_x_q4: i32,
    creature18_target_y_q4: i32,
    creature18_heading_q6: i32,
    creature18_target_heading_q6: i32,
    creature18_type_id: i32,
    creature18_flags: i32,
    creature18_link_index: i32,
    creature18_ai_mode: i32,
    creature26_active: bool,
    creature26_hp_q4: i32,
    creature26_lifecycle_stage_q4: i32,
    creature26_type_id: i32,
    creature26_flags: i32,
    creature26_link_index: i32,
    creature26_ai_mode: i32,
    creature31_active: bool,
    creature31_hp_q4: i32,
    creature31_lifecycle_stage_q4: i32,
    creature32_active: bool,
    creature32_pos_x_q4: i32,
    creature32_pos_y_q4: i32,
    creature32_hp_q4: i32,
    creature32_lifecycle_stage_q4: i32,
    creature32_type_id: i32,
    creature32_flags: i32,
    creature32_heading_q6: i32,
    creature32_target_heading_q6: i32,
    creature32_target_x_q4: i32,
    creature32_target_y_q4: i32,
    creature32_link_index: i32,
    creature32_ai_mode: i32,
    creature39_active: bool,
    creature39_hp_q4: i32,
    creature39_lifecycle_stage_q4: i32,
    creature39_type_id: i32,
    creature39_flags: i32,
    creature39_link_index: i32,
    creature39_ai_mode: i32,
    creature45_active: bool,
    creature45_pos_x_q4: i32,
    creature45_pos_y_q4: i32,
    creature45_hp_q4: i32,
    creature45_lifecycle_stage_q4: i32,
    debug_pending_nuke: i32,
    debug_nuke_kills_last: i32,
    debug_nuke_tick_last: i32,
    debug_nuke_kill_index_sum: i32,
    debug_last_picked_bonus_id: i32,
    debug_last_picked_bonus_amount: i32,
};

pub const DtFrameOverride = struct {
    tick_index: usize,
    dt_frame: f64,
};

pub const ReplayScaffoldOptions = struct {
    strict_events: bool = true,
    inter_tick_rand_draws: i32 = 0,
    dt_frame_overrides: ?[]const DtFrameOverride = null,
    quest_spawn_entries: ?[]const survival_spawn.QuestSpawnEntry = null,
    quest_start_weapon_id: ?i32 = null,
};

pub fn runReplayScaffold(
    replay: replay_codec.Replay,
) ReplayRunnerError!ReplayScaffoldResult {
    return runReplayScaffoldWithOptions(replay, .{});
}

pub fn runReplayScaffoldWithOptions(
    replay: replay_codec.Replay,
    options: ReplayScaffoldOptions,
) ReplayRunnerError!ReplayScaffoldResult {
    return runReplayScaffoldWithTrace(
        replay,
        null,
        std.heap.page_allocator,
        options,
    );
}

pub fn runReplayScaffoldWithTrace(
    replay: replay_codec.Replay,
    trace_out: ?*std.ArrayList(ReplayTickTrace),
    trace_allocator: std.mem.Allocator,
    options: ReplayScaffoldOptions,
) ReplayRunnerError!ReplayScaffoldResult {
    const header = replay.header;
    if (header.game_mode_id != game_mode_survival and
        header.game_mode_id != game_mode_rush and
        header.game_mode_id != game_mode_quests)
    {
        return error.UnsupportedGameMode;
    }
    if (header.player_count <= 0 or header.player_count > survival_state.max_players) {
        return error.UnsupportedPlayerCount;
    }
    if (header.preserve_bugs) return error.UnsupportedPreserveBugs;
    if (!std.mem.eql(u8, header.input_quantization, "raw") and !std.mem.eql(u8, header.input_quantization, "f32")) {
        return error.UnsupportedInputQuantization;
    }

    const events = replay.events;
    var original_capture_replay = false;
    var has_capture_creature_spawn_events = false;
    for (events) |event| {
        switch (event) {
            .capture_bootstrap => original_capture_replay = true,
            .capture_creature_spawn => has_capture_creature_spawn_events = true,
            else => {},
        }
    }
    const capture_spawn_events_authoritative = original_capture_replay and has_capture_creature_spawn_events;
    const apply_world_dt_steps = !(original_capture_replay and options.dt_frame_overrides != null);

    var event_index: usize = 0;
    var perk_menu_open_count: usize = 0;
    var perk_pick_count: usize = 0;
    var fire_pressed_count: usize = 0;
    var reload_pressed_count: usize = 0;
    var stage_spawn_count: usize = 0;
    var wave_spawn_count: usize = 0;
    var spawn_cooldown: f64 = 0.0;
    var spawn_stage: i32 = 0;
    var quest_spawn_timeline_ms: f64 = 0.0;
    var quest_no_creatures_timer_ms: f64 = 0.0;
    var quest_creatures_none_active: bool = false;
    var quest_completion_transition_ms: f64 = -1.0;
    var quest_completed: bool = false;
    var quest_play_hit_sfx: bool = false;
    var quest_play_completion_music: bool = false;
    var pending_capture_state_reset = false;
    var quest_start_weapon_id_for_reset: i32 = @intFromEnum(game_ids.WeaponId.pistol);
    var reset_quest_spawn_entries_len: usize = 0;
    var quest_spawn_entries_storage: [max_test_quest_spawn_entries]survival_spawn.QuestSpawnEntry = undefined;
    var quest_spawn_entries: []survival_spawn.QuestSpawnEntry = &.{};
    var state = survival_state.GameplayState.init(header.seed);
    state.fx_toggle = header.fx_toggle;
    state.game_mode = header.game_mode_id;
    var players_storage: [survival_state.max_players]survival_state.PlayerState = undefined;
    const players_len: usize = @intCast(header.player_count);
    var players = players_storage[0..players_len];
    var creatures = survival_creatures.CreaturePool{};
    creatures.capture_spawn_events_authoritative = capture_spawn_events_authoritative;
    var particles = survival_particles.ParticlePool{};
    var projectiles = survival_projectiles.ProjectilePool{};
    var secondary_projectiles = survival_secondary_projectiles.SecondaryProjectilePool{};
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
    if (game_mode == game_mode_rush) {
        enforceRushLoadout(players[0..]);
    } else if (game_mode == game_mode_quests) {
        var quest_start_weapon_id = options.quest_start_weapon_id orelse @intFromEnum(game_ids.WeaponId.pistol);
        applyQuestStageFromHeader(&state, header);
        if (options.quest_spawn_entries) |entries| {
            std.debug.assert(entries.len <= quest_spawn_entries_storage.len);
            @memcpy(quest_spawn_entries_storage[0..entries.len], entries);
            quest_spawn_entries = quest_spawn_entries_storage[0..entries.len];
        } else {
            const level_key = resolveQuestLevelKey(header) orelse return error.UnsupportedQuestSpawnTable;
            const built = quest_spawn_logic.buildQuestSpawnTable(
                level_key,
                header.player_count,
                header.seed,
                header.world_size,
                quest_spawn_entries_storage[0..],
            ) catch |build_err| switch (build_err) {
                error.UnsupportedQuestSpawnTable => return error.UnsupportedQuestSpawnTable,
                error.OutOfSpace => return error.UnsupportedQuestSpawnTable,
            };
            quest_spawn_entries = quest_spawn_entries_storage[0..built.entries.len];
            if (options.quest_start_weapon_id == null) {
                quest_start_weapon_id = @intFromEnum(built.start_weapon_id);
            }
            if (quest_spawn_entries.len == 0) {
                return error.UnsupportedQuestSpawnTable;
            }
        }
        reset_quest_spawn_entries_len = quest_spawn_entries.len;
        if (header.hardcore) {
            survival_spawn.applyHardcoreQuestSpawnTableAdjustment(quest_spawn_entries);
        }
        if (capture_spawn_events_authoritative) {
            quest_spawn_entries = &.{};
            reset_quest_spawn_entries_len = 0;
        }
        const weapon_id = @max(1, quest_start_weapon_id);
        quest_start_weapon_id_for_reset = weapon_id;
        for (players) |*player| {
            const start_weapon = survival_state.weaponIdFromInt(weapon_id) orelse game_ids.WeaponId.pistol;
            survival_state.weaponAssignPlayer(player, start_weapon);
        }
    }

    const defer_menu_open_events = original_capture_replay;
    for (0..replay.tickCount()) |tick_index| {
        if (pending_capture_state_reset) {
            applyCaptureStateReset(
                &state,
                players[0..],
                &creatures,
                @floatCast(header.world_size),
                quest_start_weapon_id_for_reset,
                capture_spawn_events_authoritative,
                quest_spawn_entries_storage[0..],
                reset_quest_spawn_entries_len,
                &quest_spawn_entries,
                &quest_spawn_timeline_ms,
                &quest_no_creatures_timer_ms,
                &quest_completion_transition_ms,
            );
            pending_capture_state_reset = false;
        }
        state.game_mode = game_mode;
        for (0..@as(usize, @intCast(@max(options.inter_tick_rand_draws, 0)))) |_| {
            _ = state.rng.rand();
        }
        if (event_index < events.len and events[event_index].tickIndex() < tick_index) {
            return error.UnsupportedEventOrdering;
        }
        const dt_tick = resolveDtFrame(options.dt_frame_overrides, tick_index, dt_nominal);
        const tick_event_start = event_index;
        while (event_index < events.len and events[event_index].tickIndex() == tick_index) : (event_index += 1) {}
        const tick_event_end = event_index;
        var menu_open_seen_this_tick = false;

        var tick_event_idx = tick_event_start;
        while (tick_event_idx < tick_event_end) : (tick_event_idx += 1) {
            if (classifyTickEvent(events[tick_event_idx], defer_menu_open_events) != .pre_step) continue;
            try applyReplayEvent(
                events[tick_event_idx],
                &state,
                players[0..],
                &creatures,
                dt_tick,
                &quest_spawn_timeline_ms,
                &quest_no_creatures_timer_ms,
                &quest_completion_transition_ms,
                &pending_capture_state_reset,
                game_mode,
                player_count,
                quest_unlock_index,
                options.strict_events,
                &perk_menu_open_count,
                &perk_pick_count,
                &menu_open_seen_this_tick,
            );
        }

        const tick_inputs = replay.inputs[tick_index];
        var reload_active_any = false;
        for (tick_inputs[0..players.len]) |input| {
            const flags = replay_codec.unpackInputFlags(input.flags);
            if (flags.fire_down) {
                state.survival_reward_fire_seen = true;
            }
            if (flags.fire_pressed) fire_pressed_count += 1;
            if (flags.reload_pressed) reload_pressed_count += 1;
            if (flags.reload_pressed) reload_active_any = true;
        }

        const dt_world = if (apply_world_dt_steps)
            applyPerkWorldDtSteps(players[0..], dt_tick)
        else
            dt_tick;
        const dt_sim = survival_state.timeScaleReflexBoostBonus(
            state.bonuses.reflex_boost,
            state.time_scale_active,
            asF32F64(dt_world),
        );
        const dt_frame_ms = dt_tick * 1000.0;
        const dt_sim_ms = dt_sim * 1000.0;
        const elapsed_before_ms = elapsed_ms_sim;
        const elapsed_after_ms = elapsed_before_ms + (if (game_mode == game_mode_survival) dt_sim_ms else dt_frame_ms);
        var freeze_corpse_at_tick_start = [_]bool{false} ** survival_creatures.max_creatures;
        for (creatures.entries, 0..) |creature, idx| {
            freeze_corpse_at_tick_start[idx] = creature.active and creature.hp <= 0.0;
        }
        var health_before_creatures: [survival_state.max_players]f64 = undefined;
        for (players, 0..) |player, player_idx| {
            health_before_creatures[player_idx] = player.health;
        }
        updateEvilEyesTargets(&state, players[0..], creatures.entries[0..]);
        survival_perks.updatePerkEffects(&state, players[0..], dt_sim);
        applyJinxedEffects(&state, players[0..], &creatures, dt_sim);
        applyPyrokineticEffects(
            &state,
            players[0..],
            &creatures,
            &particles,
            dt_sim,
        );
        const rng_after_perk_effects = state.rng.state;

        creatures.update(
            &state,
            players[0..],
            dt_sim,
            @floatCast(header.world_size),
            &bonuses,
        );
        applyPendingCreatureProjectiles(&state, &projectiles);
        const rng_after_creatures = state.rng.state;
        for (players, 0..) |_, player_idx| {
            applyFinalRevengeOnDeathTransition(
                &state,
                players[0..],
                player_idx,
                health_before_creatures[player_idx],
                &creatures,
                &bonuses,
                dt_sim,
                @floatCast(header.world_size),
                header.detail_preset,
            );
        }

        const projectile_tick_stats = projectiles.update(
            &state,
            players[0..],
            &creatures,
            &bonuses,
            dt_sim,
            @floatCast(header.world_size),
        );
        const rng_after_projectiles = state.rng.state;

        secondary_projectiles.updatePulseGun(
            &state,
            players[0..],
            &creatures,
            &bonuses,
            dt_sim,
            @floatCast(header.world_size),
            header.detail_preset,
        );
        const rng_after_secondary_projectiles = state.rng.state;

        particles.update(
            &state,
            players[0..],
            &creatures,
            &bonuses,
            dt_sim,
            @floatCast(header.world_size),
        );
        const rng_after_particles = state.rng.state;

        if (game_mode == game_mode_rush) {
            enforceRushLoadout(players[0..]);
        }
        var player_preprocessed_alive = [_]bool{false} ** survival_state.max_players;
        for (players, 0..) |*player, player_idx| {
            const should_tick_perks = survival_weapon_runtime.preprocessPlayerForPerkTicks(
                &state,
                player,
                dt_sim,
            );
            player_preprocessed_alive[player_idx] = should_tick_perks;
            if (!should_tick_perks) continue;
            survival_weapon_runtime.applyPlayerPerkTicks(
                &state,
                player,
                &projectiles,
                dt_sim,
            );
        }
        for (tick_inputs[0..players.len], players, 0..) |input, *player, player_idx| {
            if (!player_preprocessed_alive[player_idx]) {
                continue;
            }
            const health_before_player_step = player.health;
            const flags = replay_codec.unpackInputFlags(input.flags);
            const move_mode_for_tick = resolveMoveModeForUpdate(flags, &state);
            updatePlayerFromReplayInput(
                player,
                input,
                flags,
                &state,
                dt_sim,
            );
            survival_weapon_runtime.stepPlayerForTick(
                &state,
                player,
                &projectiles,
                &secondary_projectiles,
                &creatures,
                &particles,
                .{
                    .fire_down = flags.fire_down,
                    .fire_pressed = flags.fire_pressed,
                    .reload_pressed = flags.reload_pressed,
                    .reload_active_any = reload_active_any,
                    .move_mode = move_mode_for_tick,
                    .single_player_mode = players.len == 1,
                    .preprocessed_player_tick = true,
                },
                dt_sim,
            ) catch |err| switch (err) {
                error.UnsupportedWeaponFirePath => return error.UnsupportedWeaponFirePath,
            };
            applyFinalRevengeOnDeathTransition(
                &state,
                players[0..],
                player_idx,
                health_before_player_step,
                &creatures,
                &bonuses,
                dt_sim,
                @floatCast(header.world_size),
                header.detail_preset,
            );
            finalizePlayerPostUpdate(player, @floatCast(header.world_size));
        }
        const rng_after_player_update = state.rng.state;

        var rng_after_stage_spawns = state.rng.state;
        var rng_after_wave_spawns = state.rng.state;
        if (game_mode == game_mode_survival) {
            survival_state.survivalUpdateWeaponHandouts(
                &state,
                players[0..],
                asF32F64(elapsed_before_ms),
            );

            const stage_result = survival_spawn.advanceSurvivalSpawnStage(
                spawn_stage,
                players[0].level,
            );
            spawn_stage = stage_result.stage;
            stage_spawn_count += stage_result.count;
            for (stage_result.slice()) |spawn_call| {
                creatures.spawnTemplateCallWithRuntimeContext(
                    spawn_call,
                    &state.rng,
                    &state,
                    @floatCast(header.world_size),
                ) catch |err| switch (err) {
                    error.UnsupportedSpawnTemplate => return error.UnsupportedSpawnTemplate,
                };
            }
            rng_after_stage_spawns = state.rng.state;

            const wave_result = survival_spawn.tickSurvivalWaveSpawnsBatch(
                spawn_cooldown,
                dt_sim_ms,
                &state.rng,
                player_count,
                elapsed_before_ms,
                players[0].experience,
                terrain_size,
                terrain_size,
            );
            spawn_cooldown = wave_result.cooldown;
            wave_spawn_count += wave_result.count;
            creatures.spawnInits(wave_result.slice());
            rng_after_wave_spawns = state.rng.state;
        } else if (game_mode == game_mode_rush) {
            const wave_result = survival_spawn.tickRushModeSpawnsBatch(
                spawn_cooldown,
                dt_frame_ms,
                &state.rng,
                player_count,
                elapsed_after_ms,
                terrain_size,
                terrain_size,
            );
            spawn_cooldown = wave_result.cooldown;
            wave_spawn_count += wave_result.count;
            creatures.spawnInits(wave_result.slice());
            rng_after_stage_spawns = state.rng.state;
            rng_after_wave_spawns = state.rng.state;
        } else {
            quest_creatures_none_active = creatures.activeCount() == 0;
            const quest_spawns = survival_spawn.tickQuestModeSpawns(
                quest_spawn_entries,
                quest_spawn_timeline_ms,
                dt_frame_ms,
                @as(f64, @floatFromInt(terrain_size)),
                quest_creatures_none_active,
                quest_no_creatures_timer_ms,
            );
            quest_spawn_timeline_ms = quest_spawns.quest_spawn_timeline_ms;
            quest_creatures_none_active = quest_spawns.creatures_none_active;
            quest_no_creatures_timer_ms = quest_spawns.no_creatures_timer_ms;
            wave_spawn_count += quest_spawns.spawn_count;
            for (quest_spawns.slice()) |spawn_call| {
                creatures.spawnTemplateCallWithRuntimeContext(
                    spawn_call,
                    &state.rng,
                    &state,
                    @floatCast(header.world_size),
                ) catch |err| switch (err) {
                    error.UnsupportedSpawnTemplate => return error.UnsupportedSpawnTemplate,
                };
            }

            const spawn_table_empty_now = survival_spawn.questSpawnTableEmpty(quest_spawn_entries);
            if (!state.demo_mode_active and quest_creatures_none_active and spawn_table_empty_now) {
                state.bonuses.reflex_boost = 0.0;
                state.time_scale_active = false;
            }

            var any_alive_after = false;
            for (players) |player| {
                if (player.health > 0.0) {
                    any_alive_after = true;
                    break;
                }
            }
            if (any_alive_after) {
                const quest_completion = survival_spawn.tickQuestCompletionTransition(
                    quest_completion_transition_ms,
                    dt_frame_ms,
                    quest_creatures_none_active,
                    spawn_table_empty_now,
                );
                quest_completion_transition_ms = quest_completion.completion_transition_ms;
                quest_completed = quest_completion.completed;
                quest_play_hit_sfx = quest_completion.play_hit_sfx;
                quest_play_completion_music = quest_completion.play_completion_music;
            } else {
                quest_completion_transition_ms = -1.0;
                quest_completed = false;
                quest_play_hit_sfx = false;
                quest_play_completion_music = false;
            }

            rng_after_stage_spawns = state.rng.state;
            rng_after_wave_spawns = state.rng.state;
        }
        const rng_after_spawns = state.rng.state;

        const dt_after_player = playerFrameDtAfterRoundtrip(
            dt_sim,
            state.time_scale_active,
            state.bonuses.reflex_boost,
        );
        cameraShakeUpdate(&state, dt_after_player);
        if (game_mode != game_mode_rush) {
            _ = survival_state.survivalProgressionUpdate(&state, players[0..]);
        }
        state.time_scale_active = state.bonuses.reflex_boost > 0.0;
        survival_bonuses.updatePrePickupTimers(&state, dt_after_player);
        survival_bonuses.bonusUpdate(
            &bonuses,
            &state,
            players[0..],
            dt_after_player,
        ) catch |err| switch (err) {
            error.UnsupportedBonusApplyPath => return error.UnsupportedBonusApplyPath,
        };
        if (state.debug_last_picked_bonus_id == @intFromEnum(game_ids.BonusId.freeze)) {
            applyFreezePickupCorpseCleanupRng(
                &state,
                &creatures,
                freeze_corpse_at_tick_start[0..],
            );
        }
        applyPendingBonusEffects(
            &state,
            players[0..],
            &projectiles,
            &creatures,
            &bonuses,
            dt_after_player,
            @floatCast(header.world_size),
            tick_index,
        );
        const rng_after_bonus_update = state.rng.state;
        if (game_mode == game_mode_survival) {
            survival_state.survivalEnforceRewardWeaponGuard(state, players[0..]);
        }
        creatures.finalizePostRenderLifecycle();
        elapsed_ms_sim = elapsed_after_ms;

        if (defer_menu_open_events and tick_event_start < tick_event_end) {
            for ([_]TickEventPhase{
                .post_state_transition,
                .post_spawn_hook,
                .post_menu_open,
            }) |post_phase| {
                var post_idx = tick_event_start;
                while (post_idx < tick_event_end) : (post_idx += 1) {
                    if (classifyTickEvent(events[post_idx], defer_menu_open_events) != post_phase) continue;
                    try applyReplayEvent(
                        events[post_idx],
                        &state,
                        players[0..],
                        &creatures,
                        dt_tick,
                        &quest_spawn_timeline_ms,
                        &quest_no_creatures_timer_ms,
                        &quest_completion_transition_ms,
                        &pending_capture_state_reset,
                        game_mode,
                        player_count,
                        quest_unlock_index,
                        options.strict_events,
                        &perk_menu_open_count,
                        &perk_pick_count,
                        &menu_open_seen_this_tick,
                    );
                }
            }
        }

        if (trace_out) |trace| {
            const trace_elapsed_ms = if (game_mode == game_mode_quests)
                quest_spawn_timeline_ms
            else
                elapsed_ms_sim;
            try trace.append(
                trace_allocator,
                buildTickTrace(
                    tick_index,
                    trace_elapsed_ms,
                    &state,
                    players[0],
                    &creatures,
                    &bonuses,
                    &projectiles,
                    projectile_tick_stats,
                    rng_after_perk_effects,
                    rng_after_creatures,
                    rng_after_projectiles,
                    rng_after_secondary_projectiles,
                    rng_after_particles,
                    rng_after_player_update,
                    rng_after_stage_spawns,
                    rng_after_wave_spawns,
                    rng_after_spawns,
                    rng_after_bonus_update,
                ),
            );
        }
    }

    const terminal_tick = replay.tickCount();
    if (event_index < events.len and events[event_index].tickIndex() < terminal_tick) {
        return error.UnsupportedEventOrdering;
    }
    var terminal_menu_open_seen = false;
    while (event_index < events.len and events[event_index].tickIndex() == terminal_tick) : (event_index += 1) {
        const dt_tick = resolveDtFrame(options.dt_frame_overrides, terminal_tick, dt_nominal);
        try applyReplayEvent(
            events[event_index],
            &state,
            players[0..],
            &creatures,
            dt_tick,
            &quest_spawn_timeline_ms,
            &quest_no_creatures_timer_ms,
            &quest_completion_transition_ms,
            &pending_capture_state_reset,
            game_mode,
            player_count,
            quest_unlock_index,
            options.strict_events,
            &perk_menu_open_count,
            &perk_pick_count,
            &terminal_menu_open_seen,
        );
    }
    if (event_index != events.len) return error.UnsupportedEventOrdering;

    const tick_rate_f64: f64 = @floatFromInt(header.tick_rate);
    const ticks_f64: f64 = @floatFromInt(replay.tickCount());
    const elapsed_ms_nominal: i64 = @intFromFloat(@round(ticks_f64 * (1000.0 / tick_rate_f64)));
    const elapsed_ms_sim_i64: i64 = if (game_mode == game_mode_quests)
        @intFromFloat(quest_spawn_timeline_ms)
    else
        @intFromFloat(elapsed_ms_sim);
    const shots = survival_state.player0Shots(state);
    const most_used_weapon_id = survival_state.mostUsedWeaponIdForPlayer(
        state,
        0,
        @intFromEnum(players[0].weapon_id),
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
        .player_weapon_id = @intFromEnum(players[0].weapon_id),
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
        .quest_completion_transition_ms = quest_completion_transition_ms,
        .quest_completed = quest_completed,
        .quest_play_hit_sfx = quest_play_hit_sfx,
        .quest_play_completion_music = quest_play_completion_music,
    };
}

fn buildTickTrace(
    tick_index: usize,
    elapsed_ms_sim: f64,
    state: *const survival_state.GameplayState,
    player: survival_state.PlayerState,
    creatures: *const survival_creatures.CreaturePool,
    bonuses: *const survival_bonuses.BonusPool,
    projectiles: *const survival_projectiles.ProjectilePool,
    projectile_tick_stats: survival_projectiles.ProjectileTickStats,
    rng_after_perk_effects: u32,
    rng_after_creatures: u32,
    rng_after_projectiles: u32,
    rng_after_secondary_projectiles: u32,
    rng_after_particles: u32,
    rng_after_player_update: u32,
    rng_after_stage_spawns: u32,
    rng_after_wave_spawns: u32,
    rng_after_spawns: u32,
    rng_after_bonus_update: u32,
) ReplayTickTrace {
    var projectile_count: usize = 0;
    var projectile_state_hash: u64 = 1469598103934665603;
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
    const projectile1 = projectiles.entries[1];
    var projectile_type21_count: usize = 0;
    var projectile_type21 = survival_projectiles.Projectile{};
    var projectile_type21_found = false;
    const projectile6 = projectiles.entries[6];
    var projectile_type45_count: usize = 0;
    var projectile_active_index_sum: i32 = 0;
    var projectile_active_index_xor: i32 = 0;
    const creature2_pos = creatures.entries[2].pos;
    for (projectiles.entries, 0..) |entry, idx| {
        projectile_state_hash = hashMix(projectile_state_hash, @intCast(idx));
        projectile_state_hash = hashMix(projectile_state_hash, if (entry.active) 1 else 0);
        if (!entry.active) continue;
        const idx_i32: i32 = @intCast(idx);
        projectile_active_index_sum += idx_i32;
        projectile_active_index_xor ^= idx_i32;
        projectile_state_hash = hashMix(projectile_state_hash, @bitCast(@as(i64, entry.type_id)));
        projectile_state_hash = hashMix(projectile_state_hash, @bitCast(@as(i64, quantizeQ4(entry.pos.x))));
        projectile_state_hash = hashMix(projectile_state_hash, @bitCast(@as(i64, quantizeQ4(entry.pos.y))));
        projectile_state_hash = hashMix(projectile_state_hash, @bitCast(@as(i64, quantizeQ4(entry.origin.x))));
        projectile_state_hash = hashMix(projectile_state_hash, @bitCast(@as(i64, quantizeQ4(entry.origin.y))));
        projectile_state_hash = hashMix(projectile_state_hash, @bitCast(@as(i64, quantizeQ4(entry.life_timer))));
        projectile_state_hash = hashMix(projectile_state_hash, @bitCast(@as(i64, quantizeQ4(entry.damage_pool))));
        projectile_state_hash = hashMix(projectile_state_hash, @bitCast(@as(i64, quantizeQ6(entry.angle))));
        projectile_state_hash = hashMix(projectile_state_hash, @bitCast(@as(i64, quantizeQ4(entry.speed_scale))));
        projectile_state_hash = hashMix(projectile_state_hash, @bitCast(@as(i64, entry.owner_id)));
        projectile_state_hash = hashMix(projectile_state_hash, if (entry.hits_players) 1 else 0);
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
        if (entry.type_id == 21) {
            projectile_type21_count += 1;
            if (!projectile_type21_found) {
                projectile_type21_found = true;
                projectile_type21 = entry;
            }
        }
        if (entry.type_id == 45) {
            projectile_type45_count += 1;
        }
    }

    var creature_active_index_sum: i32 = 0;
    var creature_active_index_xor: i32 = 0;
    var creature_state_hash: u64 = 1469598103934665603;
    for (creatures.entries, 0..) |creature, idx| {
        creature_state_hash = hashMix(creature_state_hash, @intCast(idx));
        creature_state_hash = hashMix(creature_state_hash, if (creature.active) 1 else 0);
        if (!creature.active) continue;

        const idx_i32: i32 = @intCast(idx);
        creature_active_index_sum += idx_i32;
        creature_active_index_xor ^= idx_i32;

        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, creature.type_id)));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.pos.x))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.pos.y))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.target.x))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.target.y))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ6(creature.heading))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ6(creature.target_heading))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.phase_seed))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.vel.x))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.vel.y))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.move_scale))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, creature.force_target)));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, creature.ai_mode)));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, creature.link_index)));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ6(creature.orbit_angle))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.orbit_radius))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.hp))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.max_hp))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.move_speed))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.reward_value))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.size))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.contact_damage))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.lifecycle_stage))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, quantizeQ4(creature.attack_cooldown))));
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, creature.last_hit_owner_id)));
        creature_state_hash = hashMix(creature_state_hash, creature.flags);
    }

    var bonus_active_count: usize = 0;
    var bonus0_id: i32 = 0;
    var bonus0_amount: i32 = 0;
    var bonus1_id: i32 = 0;
    var bonus1_amount: i32 = 0;
    for (bonuses.entries) |entry| {
        if (entry.bonus_id == 0) continue;
        if (bonus_active_count == 0) {
            bonus0_id = entry.bonus_id;
            bonus0_amount = entry.amount;
        } else if (bonus_active_count == 1) {
            bonus1_id = entry.bonus_id;
            bonus1_amount = entry.amount;
        }
        bonus_active_count += 1;
    }

    return .{
        .tick = tick_index,
        .rng_state = state.rng.state,
        .rng_after_perk_effects = rng_after_perk_effects,
        .rng_after_creatures = rng_after_creatures,
        .rng_after_projectiles = rng_after_projectiles,
        .rng_after_secondary_projectiles = rng_after_secondary_projectiles,
        .rng_after_particles = rng_after_particles,
        .rng_after_player_update = rng_after_player_update,
        .rng_after_stage_spawns = rng_after_stage_spawns,
        .rng_after_wave_spawns = rng_after_wave_spawns,
        .rng_after_spawns = rng_after_spawns,
        .rng_after_bonus_update = rng_after_bonus_update,
        .elapsed_ms = @intFromFloat(@round(elapsed_ms_sim)),
        .score_xp = player.experience,
        .kills = creatures.kill_count,
        .shots_fired_p0 = if (state.shots_fired.len > 0) state.shots_fired[0] else 0,
        .creature_count = creatures.activeCount(),
        .creature_active_index_sum = creature_active_index_sum,
        .creature_active_index_xor = creature_active_index_xor,
        .creature_state_hash = creature_state_hash,
        .perk_pending = state.perk_selection.pending_count,
        .player_weapon_id = @intFromEnum(player.weapon_id),
        .player_ammo_q4 = quantizeQ4(player.ammo),
        .player_health_q4 = quantizeQ4(player.health),
        .player_pos_x_q4 = quantizeQ4(player.pos.x),
        .player_pos_y_q4 = quantizeQ4(player.pos.y),
        .player_aim_x_q4 = quantizeQ4(player.aim.x),
        .player_aim_y_q4 = quantizeQ4(player.aim.y),
        .player_heading_q6 = quantizeQ6(player.heading),
        .player_aim_heading_q6 = quantizeQ6(player.aim_heading),
        .player_move_speed_q4 = quantizeQ4(player.move_speed),
        .player_turn_speed_q4 = quantizeQ4(player.turn_speed),
        .player_level = player.level,
        .player_experience = player.experience,
        .player_reload_active = player.reload_active,
        .player_reload_timer_q4 = quantizeQ4(player.reload_timer),
        .player_shot_cooldown_q4 = quantizeQ4(player.shot_cooldown),
        .player_shot_seq = player.shot_seq,
        .player_perk31_count = player.perk_counts[@intCast(survival_perks.PerkId.hot_tempered)],
        .player_perk53_count = player.perk_counts[@intCast(survival_perks.PerkId.man_bomb)],
        .player_perk54_count = player.perk_counts[@intCast(survival_perks.PerkId.fire_caugh)],
        .player_perk55_count = player.perk_counts[@intCast(survival_perks.PerkId.living_fortress)],
        .player_hot_tempered_timer_q6 = quantizeQ6(player.hot_tempered_timer),
        .player_shield_timer_q4 = quantizeQ4(player.shield_timer),
        .player_man_bomb_timer_q6 = quantizeQ6(player.man_bomb_timer),
        .player_fire_cough_timer_q6 = quantizeQ6(player.fire_cough_timer),
        .player_living_fortress_timer_q6 = quantizeQ6(player.living_fortress_timer),
        .perk_interval_hot_tempered_q6 = quantizeQ6(state.perk_interval_hot_tempered),
        .perk_interval_man_bomb_q6 = quantizeQ6(state.perk_interval_man_bomb),
        .perk_interval_fire_cough_q6 = quantizeQ6(state.perk_interval_fire_cough),
        .bonus_weapon_power_up_ms = bonusTimerMs(state.bonuses.weapon_power_up),
        .bonus_reflex_boost_ms = bonusTimerMs(state.bonuses.reflex_boost),
        .bonus_energizer_ms = bonusTimerMs(state.bonuses.energizer),
        .bonus_double_experience_ms = bonusTimerMs(state.bonuses.double_experience),
        .bonus_freeze_ms = bonusTimerMs(state.bonuses.freeze),
        .bonus_active_count = bonus_active_count,
        .bonus0_id = bonus0_id,
        .bonus0_amount = bonus0_amount,
        .bonus1_id = bonus1_id,
        .bonus1_amount = bonus1_amount,
        .projectile_state_hash = projectile_state_hash,
        .projectile_count = projectile_count,
        .projectile_active_index_sum = projectile_active_index_sum,
        .projectile_active_index_xor = projectile_active_index_xor,
        .projectile_type45_count = projectile_type45_count,
        .projectile0_pos_x_q4 = if (projectile0_found) quantizeQ4(projectile0.pos.x) else 0,
        .projectile0_pos_y_q4 = if (projectile0_found) quantizeQ4(projectile0.pos.y) else 0,
        .projectile0_origin_x_q4 = if (projectile0_found) quantizeQ4(projectile0.origin.x) else 0,
        .projectile0_origin_y_q4 = if (projectile0_found) quantizeQ4(projectile0.origin.y) else 0,
        .projectile0_life_timer_q4 = if (projectile0_found) quantizeQ4(projectile0.life_timer) else 0,
        .projectile0_type_id = if (projectile0_found) projectile0.type_id else 0,
        .projectile0_angle_q6 = if (projectile0_found) quantizeQ6(projectile0.angle) else 0,
        .projectile0_speed_scale_q4 = if (projectile0_found) quantizeQ4(projectile0.speed_scale) else 0,
        .projectile1_active = projectile1.active,
        .projectile1_pos_x_q4 = quantizeQ4(projectile1.pos.x),
        .projectile1_pos_y_q4 = quantizeQ4(projectile1.pos.y),
        .projectile1_origin_x_q4 = quantizeQ4(projectile1.origin.x),
        .projectile1_origin_y_q4 = quantizeQ4(projectile1.origin.y),
        .projectile1_life_timer_q4 = quantizeQ4(projectile1.life_timer),
        .projectile1_type_id = projectile1.type_id,
        .projectile1_angle_q6 = quantizeQ6(projectile1.angle),
        .projectile1_damage_pool_q4 = quantizeQ4(projectile1.damage_pool),
        .projectile6_active = projectile6.active,
        .projectile6_type_id = projectile6.type_id,
        .projectile6_pos_x_q4 = quantizeQ4(projectile6.pos.x),
        .projectile6_pos_y_q4 = quantizeQ4(projectile6.pos.y),
        .projectile6_origin_x_q4 = quantizeQ4(projectile6.origin.x),
        .projectile6_origin_y_q4 = quantizeQ4(projectile6.origin.y),
        .projectile6_life_timer_q4 = quantizeQ4(projectile6.life_timer),
        .projectile6_damage_pool_q4 = quantizeQ4(projectile6.damage_pool),
        .projectile6_angle_q6 = quantizeQ6(projectile6.angle),
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
        .projectile_type21_count = projectile_type21_count,
        .projectile_type21_pos_x_q4 = if (projectile_type21_found) quantizeQ4(projectile_type21.pos.x) else 0,
        .projectile_type21_pos_y_q4 = if (projectile_type21_found) quantizeQ4(projectile_type21.pos.y) else 0,
        .projectile_type21_origin_x_q4 = if (projectile_type21_found) quantizeQ4(projectile_type21.origin.x) else 0,
        .projectile_type21_origin_y_q4 = if (projectile_type21_found) quantizeQ4(projectile_type21.origin.y) else 0,
        .projectile_type21_life_timer_q4 = if (projectile_type21_found) quantizeQ4(projectile_type21.life_timer) else 0,
        .projectile_type21_angle_q6 = if (projectile_type21_found) quantizeQ6(projectile_type21.angle) else 0,
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
        .creature0_lifecycle_stage_q4 = quantizeQ4(creatures.entries[0].lifecycle_stage),
        .creature1_active = creatures.entries[1].active,
        .creature1_pos_x_q4 = quantizeQ4(creatures.entries[1].pos.x),
        .creature1_pos_y_q4 = quantizeQ4(creatures.entries[1].pos.y),
        .creature1_hp_q4 = quantizeQ4(creatures.entries[1].hp),
        .creature1_lifecycle_stage_q4 = quantizeQ4(creatures.entries[1].lifecycle_stage),
        .creature2_active = creatures.entries[2].active,
        .creature2_pos_x_q4 = quantizeQ4(creatures.entries[2].pos.x),
        .creature2_pos_y_q4 = quantizeQ4(creatures.entries[2].pos.y),
        .creature2_hp_q4 = quantizeQ4(creatures.entries[2].hp),
        .creature2_lifecycle_stage_q4 = quantizeQ4(creatures.entries[2].lifecycle_stage),
        .creature10_active = creatures.entries[10].active,
        .creature10_pos_x_q4 = quantizeQ4(creatures.entries[10].pos.x),
        .creature10_pos_y_q4 = quantizeQ4(creatures.entries[10].pos.y),
        .creature10_hp_q4 = quantizeQ4(creatures.entries[10].hp),
        .creature10_lifecycle_stage_q4 = quantizeQ4(creatures.entries[10].lifecycle_stage),
        .creature12_active = creatures.entries[12].active,
        .creature12_pos_x_q4 = quantizeQ4(creatures.entries[12].pos.x),
        .creature12_pos_y_q4 = quantizeQ4(creatures.entries[12].pos.y),
        .creature12_hp_q4 = quantizeQ4(creatures.entries[12].hp),
        .creature12_lifecycle_stage_q4 = quantizeQ4(creatures.entries[12].lifecycle_stage),
        .creature14_active = creatures.entries[14].active,
        .creature14_pos_x_q4 = quantizeQ4(creatures.entries[14].pos.x),
        .creature14_pos_y_q4 = quantizeQ4(creatures.entries[14].pos.y),
        .creature14_hp_q4 = quantizeQ4(creatures.entries[14].hp),
        .creature14_lifecycle_stage_q4 = quantizeQ4(creatures.entries[14].lifecycle_stage),
        .creature14_size_q4 = quantizeQ4(creatures.entries[14].size),
        .creature14_target_x_q4 = quantizeQ4(creatures.entries[14].target.x),
        .creature14_target_y_q4 = quantizeQ4(creatures.entries[14].target.y),
        .creature14_heading_q6 = quantizeQ6(creatures.entries[14].heading),
        .creature14_target_heading_q6 = quantizeQ6(creatures.entries[14].target_heading),
        .creature15_active = creatures.entries[15].active,
        .creature15_pos_x_q4 = quantizeQ4(creatures.entries[15].pos.x),
        .creature15_pos_y_q4 = quantizeQ4(creatures.entries[15].pos.y),
        .creature15_hp_q4 = quantizeQ4(creatures.entries[15].hp),
        .creature15_lifecycle_stage_q4 = quantizeQ4(creatures.entries[15].lifecycle_stage),
        .creature18_active = creatures.entries[18].active,
        .creature18_pos_x_q4 = quantizeQ4(creatures.entries[18].pos.x),
        .creature18_pos_y_q4 = quantizeQ4(creatures.entries[18].pos.y),
        .creature18_hp_q4 = quantizeQ4(creatures.entries[18].hp),
        .creature18_lifecycle_stage_q4 = quantizeQ4(creatures.entries[18].lifecycle_stage),
        .creature18_target_x_q4 = quantizeQ4(creatures.entries[18].target.x),
        .creature18_target_y_q4 = quantizeQ4(creatures.entries[18].target.y),
        .creature18_heading_q6 = quantizeQ6(creatures.entries[18].heading),
        .creature18_target_heading_q6 = quantizeQ6(creatures.entries[18].target_heading),
        .creature18_type_id = creatures.entries[18].type_id,
        .creature18_flags = @bitCast(creatures.entries[18].flags),
        .creature18_link_index = creatures.entries[18].link_index,
        .creature18_ai_mode = creatures.entries[18].ai_mode,
        .creature26_active = creatures.entries[26].active,
        .creature26_hp_q4 = quantizeQ4(creatures.entries[26].hp),
        .creature26_lifecycle_stage_q4 = quantizeQ4(creatures.entries[26].lifecycle_stage),
        .creature26_type_id = creatures.entries[26].type_id,
        .creature26_flags = @bitCast(creatures.entries[26].flags),
        .creature26_link_index = creatures.entries[26].link_index,
        .creature26_ai_mode = creatures.entries[26].ai_mode,
        .creature31_active = creatures.entries[31].active,
        .creature31_hp_q4 = quantizeQ4(creatures.entries[31].hp),
        .creature31_lifecycle_stage_q4 = quantizeQ4(creatures.entries[31].lifecycle_stage),
        .creature32_active = creatures.entries[32].active,
        .creature32_pos_x_q4 = quantizeQ4(creatures.entries[32].pos.x),
        .creature32_pos_y_q4 = quantizeQ4(creatures.entries[32].pos.y),
        .creature32_hp_q4 = quantizeQ4(creatures.entries[32].hp),
        .creature32_lifecycle_stage_q4 = quantizeQ4(creatures.entries[32].lifecycle_stage),
        .creature32_type_id = creatures.entries[32].type_id,
        .creature32_flags = @bitCast(creatures.entries[32].flags),
        .creature32_heading_q6 = quantizeQ6(creatures.entries[32].heading),
        .creature32_target_heading_q6 = quantizeQ6(creatures.entries[32].target_heading),
        .creature32_target_x_q4 = quantizeQ4(creatures.entries[32].target.x),
        .creature32_target_y_q4 = quantizeQ4(creatures.entries[32].target.y),
        .creature32_link_index = creatures.entries[32].link_index,
        .creature32_ai_mode = creatures.entries[32].ai_mode,
        .creature39_active = creatures.entries[39].active,
        .creature39_hp_q4 = quantizeQ4(creatures.entries[39].hp),
        .creature39_lifecycle_stage_q4 = quantizeQ4(creatures.entries[39].lifecycle_stage),
        .creature39_type_id = creatures.entries[39].type_id,
        .creature39_flags = @bitCast(creatures.entries[39].flags),
        .creature39_link_index = creatures.entries[39].link_index,
        .creature39_ai_mode = creatures.entries[39].ai_mode,
        .creature45_active = creatures.entries[45].active,
        .creature45_pos_x_q4 = quantizeQ4(creatures.entries[45].pos.x),
        .creature45_pos_y_q4 = quantizeQ4(creatures.entries[45].pos.y),
        .creature45_hp_q4 = quantizeQ4(creatures.entries[45].hp),
        .creature45_lifecycle_stage_q4 = quantizeQ4(creatures.entries[45].lifecycle_stage),
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

fn hashMix(seed: u64, value: u64) u64 {
    var h = seed ^ value;
    h *%= 1099511628211;
    return h;
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
        .x = asF32F64(@as(f32, @floatFromInt(mag_x))),
        .y = asF32F64(@as(f32, @floatFromInt(mag_y))),
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

    const pending_fireblast_count_i32 = @min(state.pending_fireblast_count, @as(i32, @intCast(state.pending_fireblast_origins.len)));
    var pending_fireblast_idx: i32 = 0;
    while (pending_fireblast_idx < pending_fireblast_count_i32) : (pending_fireblast_idx += 1) {
        const origin = state.pending_fireblast_origins[@intCast(pending_fireblast_idx)];
        applyFireblastBonus(
            state,
            projectiles,
            origin,
        );
    }
    state.pending_fireblast_count = 0;

    const pending_shock_chain_count_i32 = @min(state.pending_shock_chain_count, @as(i32, @intCast(state.pending_shock_chain_origins.len)));
    var pending_shock_chain_idx: i32 = 0;
    while (pending_shock_chain_idx < pending_shock_chain_count_i32) : (pending_shock_chain_idx += 1) {
        const origin = state.pending_shock_chain_origins[@intCast(pending_shock_chain_idx)];
        applyShockChainBonus(
            state,
            projectiles,
            creatures,
            origin,
        );
    }
    state.pending_shock_chain_count = 0;

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

fn applyPendingCreatureProjectiles(
    state: *survival_state.GameplayState,
    projectiles: *survival_projectiles.ProjectilePool,
) void {
    if (state.pending_creature_projectile_count <= 0) {
        state.pending_creature_projectile_count = 0;
        return;
    }

    const pending_count_i32 = @min(
        state.pending_creature_projectile_count,
        @as(i32, @intCast(state.pending_creature_projectile_type_ids.len)),
    );

    var idx_i32: i32 = 0;
    while (idx_i32 < pending_count_i32) : (idx_i32 += 1) {
        const idx: usize = @intCast(idx_i32);
        const type_id = state.pending_creature_projectile_type_ids[idx];
        if (type_id <= 0) continue;
        const angle = state.pending_creature_projectile_angles[idx];
        const pos = state.pending_creature_projectile_positions[idx];
        const owner_id = state.pending_creature_projectile_owner_ids[idx];
        const meta = survival_state.weaponProjectileMeta(type_id);
        _ = projectiles.spawn(pos, angle, type_id, owner_id, meta, true);
    }
    state.pending_creature_projectile_count = 0;
}

fn applyFireblastBonus(
    state: *survival_state.GameplayState,
    projectiles: *survival_projectiles.ProjectilePool,
    origin: survival_state.Vec2,
) void {
    const projectile_owner_id: i32 = -100;
    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    const count: usize = 16;
    const step = std.math.tau / @as(f64, @floatFromInt(count));
    for (0..count) |idx| {
        const angle = @as(f64, @floatFromInt(idx)) * step;
        const type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle);
        const meta = survival_state.weaponProjectileMeta(type_id);
        _ = projectiles.spawn(origin, angle, type_id, projectile_owner_id, meta, false);
    }
}

fn applyShockChainBonus(
    state: *survival_state.GameplayState,
    projectiles: *survival_projectiles.ProjectilePool,
    creatures: *survival_creatures.CreaturePool,
    origin: survival_state.Vec2,
) void {
    if (creatures.entries.len == 0) return;

    var best_idx: usize = 0;
    var best_dist_sq: f64 = 1e12;
    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        if (creature.lifecycle_stage != creature_lifecycle_stage_alive) continue;
        const d_sq = distanceSq(origin, creature.pos);
        if (d_sq < best_dist_sq) {
            best_dist_sq = d_sq;
            best_idx = idx;
        }
    }

    const target = creatures.entries[best_idx];
    const angle = survival_state.Vec2.sub(target.pos, origin).toHeading();
    const projectile_owner_id: i32 = -100;
    const type_id = @intFromEnum(game_ids.ProjectileTypeId.ion_rifle);
    const meta = survival_state.weaponProjectileMeta(type_id);

    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    state.shock_chain_links_left = 0x20;
    const proj_idx = projectiles.spawn(origin, angle, type_id, projectile_owner_id, meta, false);
    state.shock_chain_projectile_id = @intCast(proj_idx);
}

fn distanceSq(a: survival_state.Vec2, b: survival_state.Vec2) f64 {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    return dx * dx + dy * dy;
}

fn applyPyrokineticEffects(
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    creatures: *survival_creatures.CreaturePool,
    particles: *survival_particles.ParticlePool,
    dt: f64,
) void {
    if (!(dt > 0.0)) return;
    if (players.len == 0) return;

    const burn_intensities = [_]f64{ 0.8, 0.6, 0.4, 0.3, 0.2 };

    if (state.preserve_bugs) {
        const player0 = &players[0];
        if (!perkActive(player0.*, survival_perks.PerkId.pyrokinetic)) return;

        const target_idx = creatureFindInRadius(creatures.entries[0..], player0.aim, 12.0, 0);
        if (target_idx == -1) return;

        var creature = &creatures.entries[@intCast(target_idx)];
        creature.collision_timer = asF32F64(creature.collision_timer - dt);
        if (creature.collision_timer < 0.0) {
            creature.collision_timer = 0.5;
            for (burn_intensities) |intensity| {
                const angle = asF32F64(@as(f64, @floatFromInt(state.rng.rand() % 0x274)) * 0.01);
                _ = particles.spawnParticle(state, creature.pos, angle, intensity, -100);
            }
            // Consume native fx_queue_add_random RNG even though verifier does not render decals.
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
            _ = state.rng.rand();
        }
        return;
    }

    for (players) |*player| {
        if (player.health <= 0.0) continue;
        if (!perkActive(player.*, survival_perks.PerkId.pyrokinetic)) continue;

        const target_idx = creatureFindInRadius(creatures.entries[0..], player.aim, 12.0, 0);
        if (target_idx == -1) continue;

        var creature = &creatures.entries[@intCast(target_idx)];
        creature.collision_timer = asF32F64(creature.collision_timer - dt);
        if (creature.collision_timer >= 0.0) continue;

        creature.collision_timer = 0.5;
        for (burn_intensities) |intensity| {
            const angle = asF32F64(@as(f64, @floatFromInt(state.rng.rand() % 0x274)) * 0.01);
            _ = particles.spawnParticle(state, creature.pos, angle, intensity, -100);
        }
        // Consume native fx_queue_add_random RNG even though verifier does not render decals.
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
    }
}

fn updateEvilEyesTargets(
    state: *const survival_state.GameplayState,
    players: []survival_state.PlayerState,
    creatures: []const survival_creatures.CreatureState,
) void {
    if (players.len == 0) return;
    if (state.preserve_bugs) {
        var player0 = &players[0];
        if (!perkActive(player0.*, survival_perks.PerkId.evil_eyes)) {
            player0.evil_eyes_target_creature = -1;
            return;
        }
        player0.evil_eyes_target_creature = creatureFindInRadius(creatures, player0.aim, 12.0, 0);
        return;
    }

    for (players) |*player| {
        if (player.health <= 0.0 or !perkActive(player.*, survival_perks.PerkId.evil_eyes)) {
            player.evil_eyes_target_creature = -1;
            continue;
        }
        player.evil_eyes_target_creature = creatureFindInRadius(creatures, player.aim, 12.0, 0);
    }
}

fn creatureFindInRadius(
    creatures: []const survival_creatures.CreatureState,
    pos: survival_state.Vec2,
    radius: f64,
    start_index: usize,
) i32 {
    var idx = start_index;
    const max_index = @min(creatures.len, survival_creatures.max_creatures);
    while (idx < max_index) : (idx += 1) {
        const creature = creatures[idx];
        if (!creature.active) continue;
        if (!(creature.lifecycle_stage > 5.0)) continue;
        const dist = asF32F64(survival_state.Vec2.sub(creature.pos, pos).length() - radius);
        const threshold = asF32F64(creature.size * 0.14285715 + 3.0);
        if (threshold < dist) continue;
        return @intCast(idx);
    }
    return -1;
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
        const angle = @as(f64, @floatFromInt(state.rng.rand() % 0x274)) * 0.01;
        var type_id = @intFromEnum(game_ids.ProjectileTypeId.pistol);
        applyPlayerProjectileSpawnRules(state, players, projectile_owner_id, &type_id);
        const meta = survival_state.weaponProjectileMeta(type_id);
        const proj_idx = projectiles.spawn(origin, angle, type_id, projectile_owner_id, meta, false);
        const speed_scale = @as(f64, @floatFromInt(state.rng.rand() % 0x32)) * 0.01 + 0.5;
        projectiles.entries[proj_idx].speed_scale *= speed_scale;
    }

    for (0..2) |_| {
        const angle = @as(f64, @floatFromInt(state.rng.rand() % 0x274)) * 0.01;
        var type_id = @intFromEnum(game_ids.ProjectileTypeId.gauss_gun);
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
            .{},
            damage_owner_id,
            dt,
            world_size,
            null,
        );
        if (xp > 0) {
            state.debug_nuke_kill_index_sum += @intCast(idx);
            nuke_kill_count += 1;
        }
    }
    state.debug_nuke_kills_last = nuke_kill_count;
    state.debug_nuke_tick_last = @intCast(tick_index);
}

fn applyFinalRevengeOnDeathTransition(
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    player_index: usize,
    health_before: f64,
    creatures: *survival_creatures.CreaturePool,
    bonuses: *survival_bonuses.BonusPool,
    dt: f64,
    world_size: f64,
    detail_preset: i32,
) void {
    if (player_index >= players.len) return;
    const player = &players[player_index];
    if (!(health_before > 0.0) or !(player.health <= 0.0)) return;
    if (!perkActive(player.*, survival_perks.PerkId.final_revenge)) return;

    consumeExplosionBurstRng(state, detail_preset);
    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    const owner_id: i32 = -1 - player.index;
    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        const dx = asF32F64(creature.pos.x - player.pos.x);
        const dy = asF32F64(creature.pos.y - player.pos.y);
        if (@abs(dx) > 512.0 or @abs(dy) > 512.0) continue;
        const distance = asF32F64(std.math.sqrt(asF32F64(dx * dx + dy * dy)));
        const remaining = asF32F64(512.0 - distance);
        if (!(remaining > 0.0)) continue;
        const damage = asF32F64(remaining * 5.0);
        _ = creatures.applyExplosionDamage(
            state,
            players,
            bonuses,
            idx,
            damage,
            .{},
            owner_id,
            dt,
            world_size,
            null,
        );
    }
}

fn applyPlayerProjectileSpawnRules(
    state: *survival_state.GameplayState,
    players: []const survival_state.PlayerState,
    owner_id: i32,
    type_id: *i32,
) void {
    if (state.bonus_spawn_guard) return;
    if (owner_id != -100 and owner_id != -1 and owner_id != -2 and owner_id != -3) return;

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

    var shot_credit: i32 = 1;
    if (player_index) |idx| {
        if (type_id.* != @intFromEnum(game_ids.ProjectileTypeId.fire_bullets) and
            players[idx].fire_bullets_timer > 0.0)
        {
            type_id.* = @intFromEnum(game_ids.ProjectileTypeId.fire_bullets);
            shot_credit = 2;
        }
        if (idx < state.shots_fired.len) {
            state.shots_fired[idx] += shot_credit;
        }
    }
    state.shots_fired_total += shot_credit;
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

fn resolveDtFrame(
    overrides: ?[]const DtFrameOverride,
    tick_index: usize,
    default_dt: f64,
) f64 {
    if (overrides) |entries| {
        for (entries) |entry| {
            if (entry.tick_index == tick_index) return entry.dt_frame;
        }
    }
    return default_dt;
}

fn applyQuestStageFromHeader(
    state: *survival_state.GameplayState,
    header: replay_codec.ReplayHeader,
) void {
    if (resolveQuestLevelKey(header)) |level_key| {
        state.quest_stage_major = @divTrunc(level_key, 100);
        state.quest_stage_minor = @mod(level_key, 100);
        return;
    }
    state.quest_stage_major = 0;
    state.quest_stage_minor = 0;
}

const ParsedQuestLevel = struct {
    major: i32,
    minor: i32,
};

fn parseQuestLevel(value: []const u8) ?ParsedQuestLevel {
    const dot = std.mem.indexOfScalar(u8, value, '.') orelse return null;
    if (dot == 0 or dot + 1 >= value.len) return null;
    const major = std.fmt.parseInt(i32, value[0..dot], 10) catch return null;
    const minor = std.fmt.parseInt(i32, value[dot + 1 ..], 10) catch return null;
    return .{
        .major = major,
        .minor = minor,
    };
}

fn resolveQuestLevelKey(header: replay_codec.ReplayHeader) ?i32 {
    if (parseQuestLevel(header.quest_level)) |parsed| {
        if (parsed.major >= 1 and parsed.major <= 5 and parsed.minor >= 1 and parsed.minor <= 10) {
            return parsed.major * 100 + parsed.minor;
        }
    }
    const seed_i32: i32 = @intCast(header.seed);
    const major = @divTrunc(seed_i32, 100);
    const minor = @mod(seed_i32, 100);
    if (major < 1 or major > 5 or minor < 1 or minor > 10) return null;
    return major * 100 + minor;
}

fn enforceRushLoadout(players: []survival_state.PlayerState) void {
    for (players) |*player| {
        if (player.weapon_id != game_ids.WeaponId.assault_rifle) {
            survival_state.weaponAssignPlayer(player, game_ids.WeaponId.assault_rifle);
        }
        player.ammo = @floatFromInt(@max(0, player.clip_size));
    }
}

fn applyReplayEvent(
    event: replay_codec.ReplayEvent,
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    creatures: *survival_creatures.CreaturePool,
    dt_frame: f64,
    quest_spawn_timeline_ms: *f64,
    quest_no_creatures_timer_ms: *f64,
    quest_completion_transition_ms: *f64,
    pending_capture_state_reset: *bool,
    game_mode: i32,
    player_count: i32,
    quest_unlock_index: i32,
    strict_events: bool,
    perk_menu_open_count: *usize,
    perk_pick_count: *usize,
    menu_open_seen_this_tick: *bool,
) ReplayRunnerError!void {
    switch (event) {
        .perk_menu_open => |open| {
            menu_open_seen_this_tick.* = true;
            if (game_mode == game_mode_rush) {
                if (strict_events) return error.UnsupportedEventKind;
                return;
            }
            if (open.player_index < 0 or open.player_index >= @as(i32, @intCast(players.len))) {
                return error.UnsupportedEventPlayerIndex;
            }
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
            if (game_mode == game_mode_rush) {
                if (strict_events) return error.UnsupportedEventKind;
                return;
            }
            if (pick.player_index < 0 or pick.player_index >= @as(i32, @intCast(players.len))) {
                return error.UnsupportedEventPlayerIndex;
            }
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
                if (!strict_events) {
                    return;
                }
                if (menu_open_seen_this_tick.* and state.perk_selection.pending_count <= 0) {
                    return;
                }
                return error.InvalidPerkPickEvent;
            }
            applyReplayPerkCreatureEffects(
                applied.?,
                state,
                creatures,
                dt_frame,
            );
            perk_pick_count.* += 1;
        },
        .capture_bootstrap => |bootstrap| {
            applyCaptureBootstrapEvent(
                bootstrap,
                state,
                players,
                quest_spawn_timeline_ms,
                quest_no_creatures_timer_ms,
                quest_completion_transition_ms,
            );
        },
        .capture_perk_apply => |capture_perk_apply| {
            if (game_mode == game_mode_rush) {
                if (strict_events) return error.UnsupportedEventKind;
                return;
            }
            if (players.len == 0) return;
            var rng_state_before: ?u32 = null;
            if (capture_perk_apply.outside_before) {
                if (capture_perk_apply.pending_before) |pending_before| {
                    state.perk_selection.pending_count = pending_before;
                }
                rng_state_before = state.rng.state;
            }
            survival_perks.applyPerk(state, players, capture_perk_apply.perk_id) catch |err| switch (err) {
                error.UnsupportedPerkApplyHandler => return error.UnsupportedPerkApplyHandler,
            };
            applyReplayPerkCreatureEffects(
                capture_perk_apply.perk_id,
                state,
                creatures,
                dt_frame,
            );
            if (capture_perk_apply.outside_before) {
                if (capture_perk_apply.pending_after) |pending_after| {
                    state.perk_selection.pending_count = pending_after;
                }
                if (state.perk_selection.pending_count > 0) {
                    state.perk_selection.pending_count -= 1;
                }
                if (rng_state_before) |rng_state| {
                    state.rng.srand(rng_state);
                }
            }
        },
        .capture_perk_pending => |capture_perk_pending| {
            if (game_mode == game_mode_rush) {
                if (strict_events) return error.UnsupportedEventKind;
                return;
            }
            if (capture_perk_pending.perk_pending < 0) {
                if (strict_events) return error.UnsupportedEventKind;
                return;
            }
            state.perk_selection.pending_count = capture_perk_pending.perk_pending;
            state.perk_selection.choices_dirty = true;
        },
        .capture_creature_spawn => |capture_spawn| {
            try applyCaptureCreatureSpawnEvent(
                state,
                creatures,
                capture_spawn,
            );
        },
        .capture_state_transition => |capture_state_transition| {
            for (capture_state_transition.transitions[0..capture_state_transition.transition_count]) |transition| {
                if (transition.target_state == 12) {
                    pending_capture_state_reset.* = true;
                    break;
                }
            }
        },
    }
}

fn classifyTickEvent(
    event: replay_codec.ReplayEvent,
    defer_menu_open: bool,
) TickEventPhase {
    if (!defer_menu_open) return .pre_step;
    return switch (event) {
        .perk_menu_open => .post_menu_open,
        .capture_creature_spawn => .post_spawn_hook,
        .capture_state_transition => .post_state_transition,
        else => .pre_step,
    };
}

fn applyReplayPerkCreatureEffects(
    perk_id: i32,
    state: *survival_state.GameplayState,
    creatures: *survival_creatures.CreaturePool,
    dt_frame: f64,
) void {
    switch (perk_id) {
        survival_perks.PerkId.breathing_room => {
            for (&creatures.entries) |*creature| {
                if (!creature.active) continue;
                creature.lifecycle_stage = asF32F64(creature.lifecycle_stage - dt_frame);
            }
        },
        survival_perks.PerkId.lifeline_50_50 => {
            var kill_toggle = false;
            for (&creatures.entries) |*creature| {
                if (kill_toggle and
                    creature.active and
                    creature.hp <= 500.0 and
                    (creature.flags & survival_spawn.CreatureFlags.anim_ping_pong) == 0)
                {
                    creature.active = false;
                    consumeSpawnBurstRng(state, 4);
                }
                kill_toggle = !kill_toggle;
            }
        },
        else => {},
    }
}

fn applyCaptureBootstrapEvent(
    bootstrap: replay_codec.CaptureBootstrapEvent,
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    quest_spawn_timeline_ms: *f64,
    quest_no_creatures_timer_ms: *f64,
    quest_completion_transition_ms: *f64,
) void {
    const player_count = @min(players.len, bootstrap.player_count);
    for (0..player_count) |idx| {
        const payload = bootstrap.players[idx];
        if (payload.weapon_id > 0) {
            if (survival_state.weaponIdFromInt(payload.weapon_id)) |weapon_id| {
                if (players[idx].weapon_id != weapon_id) {
                    survival_state.weaponAssignPlayer(&players[idx], weapon_id);
                }
            }
        }
        players[idx].pos.x = asF32F64(payload.pos_x);
        players[idx].pos.y = asF32F64(payload.pos_y);
        players[idx].health = asF32F64(payload.health);
        players[idx].ammo = asF32F64(payload.ammo);
        players[idx].experience = payload.experience;
        if (payload.level > 0) {
            players[idx].level = payload.level;
        }
        if (payload.clip_size) |clip_size| {
            if (clip_size >= 0) players[idx].clip_size = clip_size;
        }
        if (payload.reload_active) |reload_active| {
            players[idx].reload_active = reload_active;
        }
        if (payload.reload_timer) |reload_timer| {
            players[idx].reload_timer = @max(0.0, asF32F64(reload_timer));
        }
        if (payload.reload_timer_max) |reload_timer_max| {
            players[idx].reload_timer_max = @max(0.0, asF32F64(reload_timer_max));
        }
        if (payload.shot_cooldown) |shot_cooldown| {
            players[idx].shot_cooldown = @max(0.0, asF32F64(shot_cooldown));
        }
        if (payload.spread_heat) |spread_heat| {
            players[idx].spread_heat = @max(0.0, asF32F64(spread_heat));
        }
        if (payload.aim_x) |aim_x| {
            players[idx].aim.x = asF32F64(aim_x);
        }
        if (payload.aim_y) |aim_y| {
            players[idx].aim.y = asF32F64(aim_y);
        }
        if (payload.aim_heading) |aim_heading| {
            players[idx].aim_heading = asF32F64(aim_heading);
            players[idx].aim_dir = survival_state.Vec2.fromAngle(players[idx].aim_heading);
        }
        if (payload.alt_weapon_id) |alt_weapon_id| {
            players[idx].alt_weapon_id = if (alt_weapon_id > 0) survival_state.weaponIdFromInt(alt_weapon_id) else null;
        }
        if (payload.alt_clip_size) |alt_clip_size| {
            if (alt_clip_size >= 0) players[idx].alt_clip_size = alt_clip_size;
        }
        if (payload.alt_ammo) |alt_ammo| {
            players[idx].alt_ammo = asF32F64(alt_ammo);
        }
        if (payload.alt_reload_active) |alt_reload_active| {
            players[idx].alt_reload_active = alt_reload_active;
        }
        if (payload.alt_reload_timer) |alt_reload_timer| {
            players[idx].alt_reload_timer = @max(0.0, asF32F64(alt_reload_timer));
        }
        if (payload.alt_reload_timer_max) |alt_reload_timer_max| {
            players[idx].alt_reload_timer_max = @max(0.0, asF32F64(alt_reload_timer_max));
        }
        if (payload.alt_shot_cooldown) |alt_shot_cooldown| {
            players[idx].alt_shot_cooldown = @max(0.0, asF32F64(alt_shot_cooldown));
        }
        if (payload.shield_ms) |shield_ms| {
            players[idx].shield_timer = @max(0.0, asF32F64(@as(f32, @floatFromInt(shield_ms)) / 1000.0));
        }
        if (payload.fire_bullets_ms) |fire_bullets_ms| {
            players[idx].fire_bullets_timer = @max(0.0, asF32F64(@as(f32, @floatFromInt(fire_bullets_ms)) / 1000.0));
        }
        if (payload.speed_bonus_ms) |speed_bonus_ms| {
            players[idx].speed_bonus_timer = @max(0.0, asF32F64(@as(f32, @floatFromInt(speed_bonus_ms)) / 1000.0));
        }
        if (payload.hot_tempered_timer) |hot_tempered_timer| {
            players[idx].hot_tempered_timer = @max(0.0, asF32F64(hot_tempered_timer));
        }
        if (payload.man_bomb_timer) |man_bomb_timer| {
            players[idx].man_bomb_timer = @max(0.0, asF32F64(man_bomb_timer));
        }
        if (payload.living_fortress_timer) |living_fortress_timer| {
            players[idx].living_fortress_timer = @max(0.0, asF32F64(living_fortress_timer));
        }
        if (payload.fire_cough_timer) |fire_cough_timer| {
            players[idx].fire_cough_timer = @max(0.0, asF32F64(fire_cough_timer));
        }
    }

    state.perk_selection.pending_count = @max(0, bootstrap.perk_pending_count);
    state.perk_selection.choice_count = bootstrap.perk_choice_count;
    state.perk_selection.choices_dirty = bootstrap.perk_choices_dirty;
    for (0..state.perk_selection.choices.len) |idx| {
        state.perk_selection.choices[idx] = bootstrap.perk_choices[idx];
    }
    for (players, 0..) |*player, player_idx| {
        for (&player.perk_counts) |*count| {
            count.* = 0;
        }
        const perk_counts = bootstrap.player_perk_counts[player_idx];
        for (0..perk_counts.pair_count) |pair_idx| {
            const pair = perk_counts.pairs[pair_idx];
            if (pair.perk_id < 0 or pair.perk_id >= player.perk_counts.len) continue;
            player.perk_counts[@intCast(pair.perk_id)] = pair.count;
        }
    }

    if (bootstrap.weapon_power_up_ms) |timer_ms| {
        state.bonuses.weapon_power_up = @max(0.0, @as(f32, @floatFromInt(timer_ms)) / 1000.0);
    }
    if (bootstrap.reflex_boost_ms) |timer_ms| {
        state.bonuses.reflex_boost = @max(0.0, @as(f32, @floatFromInt(timer_ms)) / 1000.0);
    }
    if (bootstrap.energizer_ms) |timer_ms| {
        state.bonuses.energizer = @max(0.0, @as(f32, @floatFromInt(timer_ms)) / 1000.0);
    }
    if (bootstrap.double_experience_ms) |timer_ms| {
        state.bonuses.double_experience = @max(0.0, @as(f32, @floatFromInt(timer_ms)) / 1000.0);
    }
    if (bootstrap.freeze_ms) |timer_ms| {
        state.bonuses.freeze = @max(0.0, @as(f32, @floatFromInt(timer_ms)) / 1000.0);
    }
    state.time_scale_active = state.bonuses.reflex_boost > 0.0;

    if (bootstrap.perk_interval_man_bomb) |value| {
        state.perk_interval_man_bomb = @max(0.0, asF32F64(value));
    }
    if (bootstrap.perk_interval_fire_cough) |value| {
        state.perk_interval_fire_cough = @max(0.0, asF32F64(value));
    }
    if (bootstrap.perk_interval_hot_tempered) |value| {
        state.perk_interval_hot_tempered = @max(0.0, asF32F64(value));
    }

    if (bootstrap.quest_session) |quest_session| {
        quest_spawn_timeline_ms.* = @max(0.0, asF32F64(quest_session.spawn_timeline_ms));
        quest_no_creatures_timer_ms.* = @max(0.0, asF32F64(quest_session.no_creatures_timer_ms));
        if (quest_session.completion_transition_ms < 0.0) {
            quest_completion_transition_ms.* = -1.0;
        } else {
            quest_completion_transition_ms.* = @max(0.0, asF32F64(quest_session.completion_transition_ms));
        }
    }
}

fn applyCaptureCreatureSpawnEvent(
    state: *survival_state.GameplayState,
    creatures: *survival_creatures.CreaturePool,
    event: replay_codec.CaptureCreatureSpawnEvent,
) ReplayRunnerError!void {
    var spawned_indices = [_]bool{false} ** survival_creatures.max_creatures;
    var active_before = [_]bool{false} ** survival_creatures.max_creatures;
    for (creatures.entries, 0..) |entry, idx| {
        active_before[idx] = entry.active;
    }

    for (event.spawns[0..event.spawn_count]) |spawn_row| {
        creatures.spawnTemplateCall(
            .{
                .template_id = spawn_row.template_id,
                .pos = .{
                    .x = spawn_row.pos_x,
                    .y = spawn_row.pos_y,
                },
                .heading = spawn_row.heading,
            },
            &state.rng,
        ) catch |err| switch (err) {
            error.UnsupportedSpawnTemplate => return error.UnsupportedSpawnTemplate,
        };
        for (creatures.entries, 0..) |entry, idx| {
            if (!active_before[idx] and entry.active) {
                spawned_indices[idx] = true;
            }
            active_before[idx] = entry.active;
        }
    }

    for (event.added_head[0..event.added_head_count]) |row| {
        if (row.index < 0 or row.index >= creatures.entries.len) continue;
        const idx: usize = @intCast(row.index);
        const entry = &creatures.entries[idx];
        if (!entry.active) continue;

        const flags_i32 = if (row.has_flags) row.flags else @as(i32, @intCast(entry.flags));
        if (spawned_indices[idx] and
            row.has_link_index and
            row.link_index >= -1723 and
            row.link_index <= -700 and
            (flags_i32 & @as(i32, @intCast(survival_spawn.CreatureFlags.ai7_link_timer))) != 0)
        {
            _ = state.rng.rand();
        }

        if (row.has_pos) {
            entry.pos = .{
                .x = asF32F64(row.pos_x),
                .y = asF32F64(row.pos_y),
            };
        }
        if (row.has_heading) entry.heading = asF32F64(row.heading);
        if (row.has_target_heading) entry.target_heading = asF32F64(row.target_heading);
        if (row.has_ai_mode) entry.ai_mode = row.ai_mode;
        if (row.has_link_index) entry.link_index = row.link_index;
        if (row.has_hp) entry.hp = asF32F64(row.hp);
        if (row.has_lifecycle_stage) entry.lifecycle_stage = asF32F64(row.lifecycle_stage);
        if (row.has_orbit_angle) entry.orbit_angle = asF32F64(row.orbit_angle);
        if (row.has_orbit_radius) entry.orbit_radius = asF32F64(row.orbit_radius);
        if (row.has_flags) entry.flags = @intCast(@max(0, flags_i32));
        if (row.has_type_id) entry.type_id = row.type_id;
    }
}

fn applyCaptureStateReset(
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    creatures: *survival_creatures.CreaturePool,
    world_size: f64,
    quest_start_weapon_id: i32,
    capture_spawn_events_authoritative: bool,
    quest_spawn_entries_storage: []survival_spawn.QuestSpawnEntry,
    reset_quest_spawn_entries_len: usize,
    quest_spawn_entries: *[]survival_spawn.QuestSpawnEntry,
    quest_spawn_timeline_ms: *f64,
    quest_no_creatures_timer_ms: *f64,
    quest_completion_transition_ms: *f64,
) void {
    const rng_state = state.rng.state;
    const status_quest_unlock_index = state.status_quest_unlock_index;
    const status_quest_unlock_index_full = state.status_quest_unlock_index_full;
    const status_weapon_usage_counts = state.status_weapon_usage_counts;
    const game_mode = state.game_mode;
    const demo_mode_active = state.demo_mode_active;
    const hardcore = state.hardcore;
    const preserve_bugs = state.preserve_bugs;
    const quest_stage_major = state.quest_stage_major;
    const quest_stage_minor = state.quest_stage_minor;
    const perk_pending_count = state.perk_selection.pending_count;
    const perk_choice_count = state.perk_selection.choice_count;
    const perk_choices_dirty = state.perk_selection.choices_dirty;
    const perk_choices = state.perk_selection.choices;
    const perk_interval_man_bomb = state.perk_interval_man_bomb;
    const perk_interval_fire_cough = state.perk_interval_fire_cough;
    const perk_interval_hot_tempered = state.perk_interval_hot_tempered;

    state.* = survival_state.GameplayState.init(rng_state);
    state.status_quest_unlock_index = status_quest_unlock_index;
    state.status_quest_unlock_index_full = status_quest_unlock_index_full;
    state.status_weapon_usage_counts = status_weapon_usage_counts;
    state.game_mode = game_mode;
    state.demo_mode_active = demo_mode_active;
    state.hardcore = hardcore;
    state.preserve_bugs = preserve_bugs;
    state.quest_stage_major = quest_stage_major;
    state.quest_stage_minor = quest_stage_minor;
    state.perk_selection.pending_count = perk_pending_count;
    state.perk_selection.choice_count = perk_choice_count;
    state.perk_selection.choices_dirty = perk_choices_dirty;
    state.perk_selection.choices = perk_choices;
    state.perk_interval_man_bomb = perk_interval_man_bomb;
    state.perk_interval_fire_cough = perk_interval_fire_cough;
    state.perk_interval_hot_tempered = perk_interval_hot_tempered;

    survival_state.resetPlayers(players, asF32F64(world_size), null);
    for (players) |*player| {
        const quest_weapon = survival_state.weaponIdFromInt(quest_start_weapon_id) orelse game_ids.WeaponId.pistol;
        survival_state.weaponAssignPlayer(player, quest_weapon);
        if (quest_start_weapon_id == @intFromEnum(game_ids.WeaponId.pistol)) {
            player.clip_size = @max(12, player.clip_size);
            if (player.ammo < 12.0) {
                player.ammo = 12.0;
            }
        }
    }

    creatures.reset();
    creatures.capture_spawn_events_authoritative = capture_spawn_events_authoritative;
    quest_spawn_entries.* = quest_spawn_entries_storage[0..reset_quest_spawn_entries_len];
    quest_spawn_timeline_ms.* = 0.0;
    quest_no_creatures_timer_ms.* = 0.0;
    quest_completion_transition_ms.* = -1.0;
}

fn applyJinxedEffects(
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    creatures: *survival_creatures.CreaturePool,
    dt: f64,
) void {
    if (state.jinxed_timer >= 0.0) {
        state.jinxed_timer = asF32F64(state.jinxed_timer - asF32F64(dt));
    }
    if (state.jinxed_timer >= 0.0) return;
    if (players.len == 0) return;
    if (!perkActive(players[0], perk_id_jinxed)) return;

    if ((state.rng.rand() % 10) == 3) {
        const target_idx = selectJinxedAccidentTarget(state, players);
        players[target_idx].health = asF32F64(players[target_idx].health - 5.0);
    }

    const timer_roll = @as(f64, @floatFromInt(state.rng.rand() % 0x14));
    state.jinxed_timer = asF32F64(asF32F64(timer_roll * 0.1) + state.jinxed_timer + 2.0);

    if (state.bonuses.freeze > 0.0) return;

    const pool_limit: usize = if (state.preserve_bugs) 0x17F else 0x180;
    const pool_mod = @min(pool_limit, creatures.entries.len);
    if (pool_mod == 0) return;

    var idx: usize = @intCast(state.rng.rand() % @as(u32, @intCast(pool_mod)));
    var attempts: usize = 0;
    while (attempts < 10 and !creatures.entries[idx].active) : (attempts += 1) {
        idx = @intCast(state.rng.rand() % @as(u32, @intCast(pool_mod)));
    }
    if (!creatures.entries[idx].active) return;

    creatures.entries[idx].hp = -1.0;
    creatures.entries[idx].lifecycle_stage = asF32F64(
        creatures.entries[idx].lifecycle_stage - asF32F64(dt * 20.0),
    );
    awardExperienceFromReward(state, &players[0], creatures.entries[idx].reward_value);
}

fn selectJinxedAccidentTarget(
    state: *survival_state.GameplayState,
    players: []const survival_state.PlayerState,
) usize {
    if (players.len == 0) return 0;
    if (state.preserve_bugs) return 0;

    var alive_indices = [_]usize{0} ** survival_state.max_players;
    var alive_count: usize = 0;
    for (players, 0..) |player, idx| {
        if (player.health <= 0.0) continue;
        if (alive_count >= alive_indices.len) break;
        alive_indices[alive_count] = idx;
        alive_count += 1;
    }
    if (alive_count == 0) return 0;
    if (alive_count == 1) return alive_indices[0];
    const pick = state.rng.rand() % @as(u32, @intCast(alive_count));
    return alive_indices[@intCast(pick)];
}

fn awardExperienceFromReward(
    state: *survival_state.GameplayState,
    player: *survival_state.PlayerState,
    reward_value: f64,
) void {
    const first_gain = awardExperienceOnceFromReward(player, reward_value);
    if (first_gain <= 0) return;
    if (state.bonuses.double_experience > 0.0) {
        _ = awardExperienceOnceFromReward(player, reward_value);
    }
}

fn awardExperienceOnceFromReward(
    player: *survival_state.PlayerState,
    reward_value: f64,
) i32 {
    const reward_f32 = asF32F64(reward_value);
    if (reward_f32 <= 0.0) return 0;

    const before = player.experience;
    const before_f32 = asF32F64(@as(f32, @floatFromInt(before)));
    const total_f32 = asF32F64(before_f32 + reward_f32);
    const after: i32 = @intFromFloat(total_f32);
    player.experience = after;
    return after - before;
}

fn consumeSpawnBurstRng(
    state: *survival_state.GameplayState,
    count: usize,
) void {
    for (0..count) |_| {
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
    }
}

fn applyFreezePickupCorpseCleanupRng(
    state: *survival_state.GameplayState,
    creatures: *survival_creatures.CreaturePool,
    freeze_corpse_at_tick_start: []const bool,
) void {
    for (&creatures.entries, 0..) |*creature, idx| {
        if (!creature.active) continue;
        if (creature.hp > 0.0) continue;

        if (creature.lifecycle_stage < -10.0) {
            creature.active = false;
            continue;
        }

        if (idx < freeze_corpse_at_tick_start.len and freeze_corpse_at_tick_start[idx]) {
            // `bonus_apply` freeze pickup corpse pass: 8 freeze shards + 1 freeze shatter.
            for (0..8) |_| {
                _ = state.rng.rand() % 0x264;
                for (0..6) |_| {
                    _ = state.rng.rand();
                }
            }
            _ = state.rng.rand() % 0x264;
            for (0..4) |_| {
                _ = state.rng.rand();
                _ = state.rng.rand();
            }
            for (0..4) |_| {
                _ = state.rng.rand() % 0x264;
                for (0..6) |_| {
                    _ = state.rng.rand();
                }
            }
        }

        creature.active = false;
    }
}

fn updatePlayerFromReplayInput(
    player: *survival_state.PlayerState,
    input: replay_codec.ReplayPlayerInput,
    flags: replay_codec.InputFlags,
    state: *const survival_state.GameplayState,
    dt: f64,
) void {
    const prev_pos = player.pos;
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

    const move_mode = resolveMoveModeForUpdate(flags, state);
    const aim_scheme = resolveAimSchemeForUpdate(flags, state);

    var raw_move = survival_state.Vec2{
        .x = asF32F64(input.move_x),
        .y = asF32F64(input.move_y),
    };
    const raw_mag = raw_move.length();
    var move = directionFromHeadingNative(player.heading);

    var speed_multiplier = player.speed_multiplier;
    if (player.speed_bonus_timer > 0.0) {
        speed_multiplier += 1.0;
    }

    var speed: f64 = 0.0;
    var phase_sign: f64 = 1.0;
    var move_delta_override: ?survival_state.Vec2 = null;
    const player_controlled_movement =
        !state.demo_mode_active and
        move_mode != movement_control_computer and
        aim_scheme != aim_scheme_computer;

    if (player_controlled_movement) {
        if (move_mode == movement_control_relative) {
            const turning_left = flags.turn_left_pressed orelse false;
            const turning_right = flags.turn_right_pressed orelse false;
            const moving_forward = flags.move_forward_pressed orelse false;
            const moving_backward = flags.move_backward_pressed orelse false;
            var turned = false;

            if (player.turn_speed < 1.0) player.turn_speed = 1.0;
            if (player.turn_speed > 7.0) player.turn_speed = 7.0;

            if (turning_left) {
                player.turn_speed = asF32F64(player.turn_speed + movement_dt * 10.0);
                const turn_step = asF32F64(player.turn_speed * movement_dt * 0.5);
                player.heading = asF32F64(player.heading - turn_step);
                player.aim_heading = asF32F64(player.aim_heading - turn_step);
                turned = true;
            } else if (turning_right) {
                player.turn_speed = asF32F64(player.turn_speed + movement_dt * 10.0);
                const turn_step = asF32F64(player.turn_speed * movement_dt * 0.5);
                player.heading = asF32F64(player.heading + turn_step);
                player.aim_heading = asF32F64(player.aim_heading + turn_step);
                turned = true;
            }

            if (moving_forward) {
                playerAccelerateMoveSpeed(player, movement_dt);
                playerApplyMoveSpeedCaps(player);
                move_delta_override = playerMoveDeltaFromHeading(player, movement_dt, 25.0);
            } else if (moving_backward) {
                playerAccelerateMoveSpeed(player, movement_dt);
                phase_sign = -1.0;
                move_delta_override = playerMoveDeltaFromHeading(player, movement_dt, -25.0);
            } else {
                if (!turned) {
                    player.turn_speed = 1.0;
                }
                playerDecelerateMoveSpeed(player, movement_dt);
                move_delta_override = playerMoveDeltaFromHeading(player, movement_dt, 25.0);
            }
        } else if (move_mode == movement_control_static) {
            const moving_forward = flags.move_forward_pressed orelse (raw_move.y < -0.5);
            const moving_backward = flags.move_backward_pressed orelse (raw_move.y > 0.5);
            const turning_left = flags.turn_left_pressed orelse (raw_move.x < -0.5);
            const turning_right = flags.turn_right_pressed orelse (raw_move.x > 0.5);

            var target_heading = relative_move_heading_none;
            if (turning_left) target_heading = relative_move_heading_left;
            if (turning_right) target_heading = relative_move_heading_right;

            if (moving_forward) {
                if (turning_left) {
                    target_heading = relative_move_heading_forward_left;
                } else if (turning_right) {
                    target_heading = relative_move_heading_forward_right;
                } else {
                    target_heading = relative_move_heading_forward;
                }
            }
            if (moving_backward) {
                if (turning_left) {
                    target_heading = relative_move_heading_backward_left;
                } else if (turning_right) {
                    target_heading = relative_move_heading_backward_right;
                } else {
                    target_heading = relative_move_heading_backward;
                }
            }

            if (!moving_backward and target_heading == relative_move_heading_none) {
                playerDecelerateMoveSpeed(player, movement_dt);
                move = directionFromHeadingNative(player.heading);
                const move_dx = asF32F64(move.x * player.move_speed * speed_multiplier * 25.0);
                const move_dy = asF32F64(move.y * player.move_speed * speed_multiplier * 25.0);
                move_delta_override = .{
                    .x = asF32F64(movement_dt * move_dx),
                    .y = asF32F64(movement_dt * move_dy),
                };
            } else {
                const heading_result = playerHeadingApproachTargetWithDelta(
                    player,
                    target_heading,
                    movement_dt,
                );
                player.aim_heading = asF32F64(player.aim_heading + heading_result.turn_delta);
                playerAccelerateMoveSpeed(player, movement_dt);
                playerApplyMoveSpeedCaps(player);
                move = directionFromHeadingNative(player.heading);
                const turn_align =
                    (native_pi - heading_result.diff) *
                    speed_multiplier *
                    relative_move_turn_align_scale;
                const move_dx = asF32F64(move.x * player.move_speed * turn_align);
                const move_dy = asF32F64(move.y * player.move_speed * turn_align);
                move_delta_override = .{
                    .x = asF32F64(movement_dt * move_dx),
                    .y = asF32F64(movement_dt * move_dy),
                };
            }
        } else {
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
            speed = player.move_speed * speed_multiplier * 25.0;
            if (moving_input) {
                speed *= @min(1.0, raw_mag);
                speed *= turn_alignment_scale;
            }
        }
    } else {
        const move_input_threshold: f64 = if (state.demo_mode_active) 0.0 else 0.2;
        const moving_input = raw_mag > move_input_threshold;
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
        speed = player.move_speed * speed_multiplier * 25.0;
        if (moving_input) {
            speed *= @min(1.0, raw_mag);
            speed *= turn_alignment_scale;
        }
    }

    var delta = if (move_delta_override) |override|
        override
    else
        survival_state.Vec2{
            .x = asF32F64(move.x * asF32F64(speed * movement_dt)),
            .y = asF32F64(move.y * asF32F64(speed * movement_dt)),
        };
    if (perkActive(player.*, survival_perks.PerkId.alternate_weapon)) {
        delta = .{
            .x = asF32F64(delta.x * 0.8),
            .y = asF32F64(delta.y * 0.8),
        };
    }
    const pos_after_move = survival_state.Vec2{
        .x = asF32F64(player.pos.x + delta.x),
        .y = asF32F64(player.pos.y + delta.y),
    };
    player.pos = .{
        .x = asF32F64(pos_after_move.x),
        .y = asF32F64(pos_after_move.y),
    };

    const move_delta = survival_state.Vec2.sub(player.pos, prev_pos);
    const reload_stationary = @abs(move_delta.x) <= 1e-9 and @abs(move_delta.y) <= 1e-9;
    player.reload_stationary_latch = reload_stationary;
    if (!reload_stationary) {
        // Native clears these post-perk-tick timers after movement when position changed.
        player.man_bomb_timer = 0.0;
        player.living_fortress_timer = 0.0;
    }
    player.move_phase = asF32F64(player.move_phase + asF32F64(phase_sign * movement_dt * player.move_speed * 19.0));

    player.aim = .{
        .x = asF32F64(input.aim_x),
        .y = asF32F64(input.aim_y),
    };
    var aim_dir = survival_state.Vec2.sub(player.aim, player.pos);
    const aim_len_sq = aim_dir.lengthSq();
    if (aim_len_sq > 0.0) {
        aim_dir = aim_dir.mul(1.0 / std.math.sqrt(aim_len_sq));
        player.aim_dir = aim_dir;
        player.aim_heading = player.aim_dir.toHeading();
    }
}

fn finalizePlayerPostUpdate(
    player: *survival_state.PlayerState,
    world_size: f64,
) void {
    while (player.move_phase > 14.0) {
        player.move_phase = asF32F64(player.move_phase - 14.0);
    }
    while (player.move_phase < 0.0) {
        player.move_phase = asF32F64(player.move_phase + 14.0);
    }

    const half_size = @max(0.0, player.size * 0.5);
    const clamped_pos = player.pos.clampRect(
        half_size,
        half_size,
        asF32F64(world_size - half_size),
        asF32F64(world_size - half_size),
    );
    player.pos = .{
        .x = asF32F64(clamped_pos.x),
        .y = asF32F64(clamped_pos.y),
    };
    if (player.muzzle_flash_alpha > 0.8) {
        player.muzzle_flash_alpha = 0.8;
    }
}

fn resolveMoveModeForUpdate(
    flags: replay_codec.InputFlags,
    state: *const survival_state.GameplayState,
) i32 {
    if (flags.move_mode) |mode| return mode;
    if (state.demo_mode_active) return movement_control_computer;
    if (flags.move_forward_pressed != null and
        flags.move_backward_pressed != null and
        flags.turn_left_pressed != null and
        flags.turn_right_pressed != null)
    {
        return movement_control_static;
    }
    return movement_control_dual_action_pad;
}

fn resolveAimSchemeForUpdate(
    flags: replay_codec.InputFlags,
    state: *const survival_state.GameplayState,
) i32 {
    if (flags.aim_scheme) |scheme| return scheme;
    if (state.demo_mode_active) return aim_scheme_computer;
    return aim_scheme_mouse;
}

fn playerMoveDeltaFromHeading(
    player: *const survival_state.PlayerState,
    movement_dt: f64,
    speed_scale: f64,
) survival_state.Vec2 {
    const move = directionFromHeadingNative(player.heading);
    const move_dx = asF32F64(move.x * player.move_speed * speed_scale);
    const move_dy = asF32F64(move.y * player.move_speed * speed_scale);
    return .{
        .x = asF32F64(movement_dt * move_dx),
        .y = asF32F64(movement_dt * move_dy),
    };
}

fn directionFromHeadingNative(heading: f64) survival_state.Vec2 {
    const radians = asF32F64(heading - native_half_pi);
    return .{
        .x = asF32F64(survival_math.cos(radians)),
        .y = asF32F64(survival_math.sin(radians)),
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
    if (player.weapon_id == game_ids.WeaponId.mean_minigun and player.move_speed > 0.8) {
        player.move_speed = 0.8;
    }
}

const HeadingApproachResult = struct {
    diff: f64,
    turn_delta: f64,
};

fn playerHeadingApproachTargetWithDelta(
    player: *survival_state.PlayerState,
    target_heading: f64,
    dt: f64,
) HeadingApproachResult {
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
    return .{
        .diff = diff,
        .turn_delta = turn_delta,
    };
}

fn playerHeadingApproachTarget(
    player: *survival_state.PlayerState,
    target_heading: f64,
    dt: f64,
) f64 {
    return playerHeadingApproachTargetWithDelta(player, target_heading, dt).diff;
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

fn applyPerkWorldDtSteps(
    players: []const survival_state.PlayerState,
    dt: f64,
) f64 {
    const dt_f32 = asF32F64(dt);
    if (!(dt_f32 > 0.0)) return dt_f32;
    if (players.len == 0) return dt_f32;
    if (!perkActive(players[0], survival_perks.PerkId.reflex_boosted)) return dt_f32;
    return asF32F64(dt_f32 * 0.9);
}

fn playerFrameDtAfterRoundtrip(
    dt: f64,
    time_scale_active: bool,
    reflex_boost_timer: f64,
) f64 {
    const dt_f32 = asF32F64(dt);
    if (!time_scale_active or dt_f32 <= 0.0) {
        return dt_f32;
    }

    const reflex_f32 = asF32F64(reflex_boost_timer);
    var time_scale_factor = asF32F64(0.3);
    if (reflex_f32 < 1.0) {
        time_scale_factor = asF32F64((1.0 - reflex_f32) * 0.7 + 0.3);
    }
    if (time_scale_factor <= 0.0) {
        return dt_f32;
    }

    const movement_dt = asF32F64((0.6 / time_scale_factor) * dt_f32);
    return asF32F64(time_scale_factor * movement_dt * 1.6666666);
}

fn perkActive(player: survival_state.PlayerState, perk_id: i32) bool {
    if (perk_id < 0 or perk_id >= player.perk_counts.len) return false;
    return player.perk_counts[@intCast(perk_id)] > 0;
}

test "survival scaffold tracks event and input counters" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
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

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(usize, 2), result.ticks);
    try std.testing.expectEqual(@as(i64, 33), result.elapsed_ms_nominal);
    try std.testing.expectEqual(@as(i64, 33), result.elapsed_ms_sim);
    try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
    try std.testing.expectEqual(@as(usize, 0), result.perk_pick_count);
    try std.testing.expectEqual(@as(usize, 1), result.fire_pressed_count);
    try std.testing.expectEqual(@as(usize, 1), result.reload_pressed_count);
    try std.testing.expectEqual(@as(usize, 0), result.stage_spawn_count);
    try std.testing.expectEqual(@as(usize, 1), result.wave_spawn_count);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.pistol), result.player_weapon_id);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.pistol), result.most_used_weapon_id);
    try std.testing.expectEqual(@as(i32, 0), result.shots_fired);
    try std.testing.expectEqual(@as(i32, 0), result.shots_hit);
    try std.testing.expectEqual(@as(i32, 1), result.player_level);
    try std.testing.expectEqual(@as(i32, 0), result.perk_pending_count);
    try std.testing.expect(!result.survival_reward_fire_seen);
}

test "survival scaffold rejects unsupported event player index" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag},
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 1 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.UnsupportedEventPlayerIndex,
        runReplayScaffold(replay),
    );
}

test "survival scaffold accepts multiplayer event player indices" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplayMulti(allocator, .{
        .tick_rate = 60,
        .player_count = 2,
        .inputs = &.{
            &.{ replay_codec.fire_pressed_flag, replay_codec.reload_pressed_flag },
        },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 1 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
    try std.testing.expectEqual(@as(usize, 1), result.fire_pressed_count);
    try std.testing.expectEqual(@as(usize, 1), result.reload_pressed_count);
}

test "survival scaffold rejects multiplayer event player index out of bounds" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplayMulti(allocator, .{
        .tick_rate = 60,
        .player_count = 2,
        .inputs = &.{
            &.{ 0, 0 },
        },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 2 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.UnsupportedEventPlayerIndex,
        runReplayScaffold(replay),
    );
}

test "survival scaffold rejects invalid perk pick event in strict mode" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag},
        .events = &.{
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.InvalidPerkPickEvent,
        runReplayScaffold(replay),
    );
}

test "survival scaffold can skip invalid perk pick event in non-strict mode" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag},
        .events = &.{
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .strict_events = false,
    });
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@as(usize, 0), result.perk_pick_count);
    try std.testing.expectEqual(@as(i32, 0), result.perk_pending_count);
}

test "survival scaffold treats same-tick stale perk pick after menu open as strict no-op" {
    const allocator = std.testing.allocator;

    const menu_only = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 0 } },
        },
    });
    defer menu_only.deinit(allocator);

    const with_stale_pick = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 0 } },
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 1 } },
        },
    });
    defer with_stale_pick.deinit(allocator);

    const menu_result = try runReplayScaffold(menu_only);
    const stale_result = try runReplayScaffold(with_stale_pick);

    try std.testing.expectEqual(menu_result.wave_spawn_rng_state, stale_result.wave_spawn_rng_state);
    try std.testing.expectEqual(menu_result.perk_pending_count, stale_result.perk_pending_count);
    try std.testing.expectEqual(@as(usize, 0), stale_result.perk_pick_count);
}

test "tick event classification defers state transition then spawn then menu in capture mode" {
    var transition = replay_codec.CaptureStateTransitionEvent{
        .tick_index = 0,
    };
    transition.transition_count = 1;
    transition.transitions[0] = .{
        .target_state = 6,
        .has_before_state = false,
        .before_state = 0,
        .has_after_state = false,
        .after_state = 0,
    };
    const events = [_]replay_codec.ReplayEvent{
        .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 0 } },
        .{ .capture_creature_spawn = .{ .tick_index = 0 } },
        .{ .capture_state_transition = transition },
    };

    var pre_count: usize = 0;
    for (events) |event| {
        if (classifyTickEvent(event, true) == .pre_step) pre_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), pre_count);

    var ordered = [_]TickEventPhase{.pre_step} ** 3;
    var ordered_count: usize = 0;
    for ([_]TickEventPhase{
        .post_state_transition,
        .post_spawn_hook,
        .post_menu_open,
    }) |phase| {
        for (events) |event| {
            if (classifyTickEvent(event, true) != phase) continue;
            ordered[ordered_count] = phase;
            ordered_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 3), ordered_count);
    try std.testing.expectEqual(TickEventPhase.post_state_transition, ordered[0]);
    try std.testing.expectEqual(TickEventPhase.post_spawn_hook, ordered[1]);
    try std.testing.expectEqual(TickEventPhase.post_menu_open, ordered[2]);
}

test "survival scaffold defers menu-open processing in original capture replays" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            menu_before_pick: bool,
        ) !ReplayScaffoldResult {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.perk_pending_count = 1;
            bootstrap.perk_choices_dirty = true;

            const menu_event = replay_codec.ReplayEvent{
                .perk_menu_open = .{
                    .tick_index = 0,
                    .player_index = 0,
                },
            };
            const pick_event = replay_codec.ReplayEvent{
                .perk_pick = .{
                    .tick_index = 0,
                    .player_index = 0,
                    .choice_index = 0,
                },
            };

            const replay = try buildTestReplay(allocator_inner, .{
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{0},
                .events = if (menu_before_pick)
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                        menu_event,
                        pick_event,
                    }
                else
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                        pick_event,
                        menu_event,
                    },
            });
            defer replay.deinit(allocator_inner);
            return runReplayScaffold(replay);
        }
    }.runCase;

    const menu_first = try run(allocator, true);
    const pick_first = try run(allocator, false);

    try std.testing.expectEqual(menu_first.wave_spawn_rng_state, pick_first.wave_spawn_rng_state);
    try std.testing.expectEqual(menu_first.perk_pick_count, pick_first.perk_pick_count);
    try std.testing.expectEqual(menu_first.perk_menu_open_count, pick_first.perk_menu_open_count);
    try std.testing.expectEqual(menu_first.perk_pending_count, pick_first.perk_pending_count);
}

test "survival scaffold tracks weapon runtime counters" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{
            replay_codec.fire_down_flag,
            replay_codec.fire_down_flag,
        },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(i32, 1), result.shots_fired);
    try std.testing.expectEqual(@as(i32, 0), result.shots_hit);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.pistol), result.most_used_weapon_id);
}

test "survival scaffold honors dt overrides for elapsed_ms" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .dt_frame_overrides = &.{
            .{ .tick_index = 0, .dt_frame = 0.5 },
        },
    });
    try std.testing.expectEqual(@as(i64, 500), result.elapsed_ms_sim);
}

test "survival scaffold inter-tick rand draws shift rng deterministically" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const baseline = try runReplayScaffold(replay);
    const shifted = try runReplayScaffoldWithOptions(replay, .{
        .inter_tick_rand_draws = 1,
    });
    const shifted_again = try runReplayScaffoldWithOptions(replay, .{
        .inter_tick_rand_draws = 1,
    });

    try std.testing.expectEqual(@as(usize, 3), baseline.ticks);
    try std.testing.expectEqual(shifted.wave_spawn_rng_state, shifted_again.wave_spawn_rng_state);
    try std.testing.expect(shifted.wave_spawn_rng_state != baseline.wave_spawn_rng_state);
}

test "survival scaffold applies capture bootstrap payload state" {
    const allocator = std.testing.allocator;

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 9,
        .pos_x = 600.0,
        .pos_y = 600.0,
        .health = 75.0,
        .ammo = 4.0,
        .experience = 321,
        .level = 5,
    };
    bootstrap.perk_pending_count = 2;
    bootstrap.double_experience_ms = 1500;

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@as(i32, 321), result.player_experience);
    try std.testing.expectEqual(@as(i32, 5), result.player_level);
    try std.testing.expectEqual(@as(i32, 2), result.perk_pending_count);
}

test "survival scaffold applies terminal tick events" {
    const allocator = std.testing.allocator;

    const with_terminal_event = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 3, .player_index = 0 } },
        },
    });
    defer with_terminal_event.deinit(allocator);

    const without_terminal_event = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{},
    });
    defer without_terminal_event.deinit(allocator);

    const with_result = try runReplayScaffold(with_terminal_event);
    const without_result = try runReplayScaffold(without_terminal_event);
    try std.testing.expect(with_result.wave_spawn_rng_state != without_result.wave_spawn_rng_state);
}

test "survival scaffold bootstrap player shot cooldown blocks first-tick fire" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            include_shot_cooldown: bool,
        ) !struct { shots_fired: i32, ammo_q4: i32 } {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.players[0] = .{
                .weapon_id = 1,
                .ammo = 12.0,
                .reload_active = false,
                .reload_timer = 0.0,
                .reload_timer_max = 1.0,
                .spread_heat = 0.0,
            };
            if (include_shot_cooldown) {
                bootstrap.players[0].shot_cooldown = 0.5;
            }

            var replay = try buildTestReplay(allocator_inner, .{
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{replay_codec.fire_down_flag},
                .events = &.{
                    .{ .capture_bootstrap = bootstrap },
                },
            });
            defer replay.deinit(allocator_inner);
            replay.inputs[0][0].aim_x = 700.0;
            replay.inputs[0][0].aim_y = 512.0;

            var trace: std.ArrayList(ReplayTickTrace) = .empty;
            defer trace.deinit(allocator_inner);
            const result = try runReplayScaffoldWithTrace(
                replay,
                &trace,
                allocator_inner,
                .{},
            );
            try std.testing.expectEqual(@as(usize, 1), trace.items.len);
            return .{
                .shots_fired = result.shots_fired,
                .ammo_q4 = trace.items[0].player_ammo_q4,
            };
        }
    }.runCase;

    const without_cooldown = try run(allocator, false);
    const with_cooldown = try run(allocator, true);
    try std.testing.expect(without_cooldown.shots_fired > with_cooldown.shots_fired);
    try std.testing.expectEqual(@as(i32, 0), with_cooldown.shots_fired);
    try std.testing.expect(without_cooldown.ammo_q4 < with_cooldown.ammo_q4);
    try std.testing.expectEqual(quantizeQ4(12.0), with_cooldown.ammo_q4);
}

test "survival scaffold bootstrap perk counts enable alternate weapon swap" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            include_perk_counts: bool,
        ) !i32 {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.players[0] = .{
                .weapon_id = 11,
                .ammo = 0.0,
                .reload_active = false,
                .reload_timer = 0.0,
                .reload_timer_max = 1.0,
                .alt_weapon_id = 1,
                .alt_clip_size = 12,
                .alt_ammo = 12.0,
                .alt_reload_active = false,
                .alt_reload_timer = 0.0,
                .alt_reload_timer_max = 1.2,
                .alt_shot_cooldown = 0.0,
            };
            if (include_perk_counts) {
                bootstrap.player_perk_counts[0].pair_count = 1;
                bootstrap.player_perk_counts[0].pairs[0] = .{
                    .perk_id = survival_perks.PerkId.alternate_weapon,
                    .count = 1,
                };
            }

            const replay = try buildTestReplay(allocator_inner, .{
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{replay_codec.reload_pressed_flag},
                .events = &.{
                    .{ .capture_bootstrap = bootstrap },
                },
            });
            defer replay.deinit(allocator_inner);

            const result = try runReplayScaffold(replay);
            return result.player_weapon_id;
        }
    }.runCase;

    const without_counts = try run(allocator, false);
    const with_counts = try run(allocator, true);
    try std.testing.expectEqual(@as(i32, 11), without_counts);
    try std.testing.expectEqual(@as(i32, 1), with_counts);
}

test "capture perk pending event sets pending without shifting rng in survival and quest modes" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            game_mode_id: i32,
            apply_pending_event: bool,
        ) !struct { rng_state: u32, pending: i32 } {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.perk_pending_count = 2;
            const pending_event = replay_codec.ReplayEvent{
                .capture_perk_pending = .{
                    .tick_index = 0,
                    .perk_pending = 0,
                },
            };
            const replay = try buildTestReplay(allocator_inner, .{
                .game_mode_id = game_mode_id,
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{0},
                .events = if (apply_pending_event)
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                        pending_event,
                    }
                else
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                    },
            });
            defer replay.deinit(allocator_inner);

            const result = try runReplayScaffoldWithOptions(replay, .{
                .quest_spawn_entries = if (game_mode_id == game_mode_quests) &.{} else null,
            });
            return .{
                .rng_state = result.wave_spawn_rng_state,
                .pending = result.perk_pending_count,
            };
        }
    }.runCase;

    for ([_]i32{ game_mode_survival, game_mode_quests }) |mode| {
        const baseline = try run(allocator, mode, false);
        const with_pending = try run(allocator, mode, true);
        try std.testing.expectEqual(baseline.rng_state, with_pending.rng_state);
        try std.testing.expectEqual(@as(i32, 0), with_pending.pending);
    }
}

test "capture perk apply outside-before keeps rng anchored and consumes pending-after" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            include_perk_apply: bool,
        ) !ReplayScaffoldResult {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.perk_pending_count = 1;
            bootstrap.players[0] = .{
                .weapon_id = @intFromEnum(game_ids.WeaponId.assault_rifle),
                .ammo = 6.0,
            };

            const apply_event = replay_codec.ReplayEvent{
                .capture_perk_apply = .{
                    .tick_index = 0,
                    .perk_id = survival_perks.PerkId.random_weapon,
                    .outside_before = true,
                    .pending_before = 1,
                    .pending_after = 4,
                },
            };

            const replay = try buildTestReplay(allocator_inner, .{
                .game_mode_id = game_mode_survival,
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{0},
                .events = if (include_perk_apply)
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                        apply_event,
                    }
                else
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                    },
            });
            defer replay.deinit(allocator_inner);
            return runReplayScaffold(replay);
        }
    }.runCase;

    const baseline = try run(allocator, false);
    const applied = try run(allocator, true);

    try std.testing.expectEqual(baseline.wave_spawn_rng_state, applied.wave_spawn_rng_state);
    try std.testing.expectEqual(@as(i32, 3), applied.perk_pending_count);
}

test "rush scaffold is deterministic and enforces assault rifle loadout" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_rush,
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result0 = try runReplayScaffold(replay);
    const result1 = try runReplayScaffold(replay);
    try std.testing.expectEqual(result0.wave_spawn_rng_state, result1.wave_spawn_rng_state);
    try std.testing.expectEqual(@as(usize, 10), result0.ticks);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result0.player_weapon_id);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result0.most_used_weapon_id);
}

test "rush scaffold honors dt overrides for elapsed_ms" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_rush,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .dt_frame_overrides = &.{
            .{ .tick_index = 0, .dt_frame = 0.5 },
        },
    });
    try std.testing.expectEqual(@as(i64, 500), result.elapsed_ms_sim);
}

test "rush scaffold spawn cadence uses raw frame dt, not sim dt" {
    const allocator = std.testing.allocator;

    const inputs = [_]u32{0} ** 15;
    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_rush,
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = inputs[0..],
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    // Rush starts with one immediate spawn batch (2 creatures). A second batch should
    // not land until tick 15 at 60Hz.
    try std.testing.expectEqual(@as(usize, 2), result.wave_spawn_count);
}

test "rush scaffold inter-tick rand draws shift rng deterministically" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_rush,
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const baseline = try runReplayScaffold(replay);
    const shifted = try runReplayScaffoldWithOptions(replay, .{
        .inter_tick_rand_draws = 1,
    });
    const shifted_again = try runReplayScaffoldWithOptions(replay, .{
        .inter_tick_rand_draws = 1,
    });

    try std.testing.expectEqual(@as(usize, 3), baseline.ticks);
    try std.testing.expectEqual(shifted.wave_spawn_rng_state, shifted_again.wave_spawn_rng_state);
    try std.testing.expect(shifted.wave_spawn_rng_state != baseline.wave_spawn_rng_state);
}

test "rush scaffold rejects replay events" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_rush,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(error.UnsupportedEventKind, runReplayScaffold(replay));
}

test "rush scaffold accepts capture bootstrap events" {
    const allocator = std.testing.allocator;

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 17,
        .pos_x = 256.0,
        .pos_y = 256.0,
        .health = 100.0,
        .ammo = 6.0,
        .experience = 123,
        .level = 2,
    };

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_rush,
        .seed = 42,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.player_weapon_id);
    try std.testing.expectEqual(@as(i32, 123), result.player_experience);
}

test "rush scaffold original capture bootstrap keeps packed move vector behavior" {
    const allocator = std.testing.allocator;

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = @intFromEnum(game_ids.WeaponId.assault_rifle),
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 100.0,
        .ammo = 50.0,
    };
    bootstrap.digital_move_enabled_by_player[0] = true;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_rush,
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);
    replay.inputs[0][0].move_x = 1.0;
    replay.inputs[0][0].move_y = 0.0;
    replay.inputs[0][0].aim_x = 600.0;
    replay.inputs[0][0].aim_y = 512.0;

    var trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer trace.deinit(allocator);
    _ = try runReplayScaffoldWithTrace(
        replay,
        &trace,
        allocator,
        .{},
    );
    try std.testing.expectEqual(@as(usize, 1), trace.items.len);
    try std.testing.expect(trace.items[0].player_pos_x_q4 > quantizeQ4(512.0));
}

test "rush scaffold supports multiplayer replays" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplayMulti(allocator, .{
        .game_mode_id = game_mode_rush,
        .seed = 0x1234,
        .tick_rate = 60,
        .player_count = 2,
        .inputs = &.{
            &.{ 0, 0 },
            &.{ replay_codec.fire_down_flag, 0 },
            &.{ 0, replay_codec.reload_pressed_flag },
        },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(usize, 3), result.ticks);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.player_weapon_id);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.most_used_weapon_id);
}

test "rush scaffold disables progression updates even above level threshold" {
    const allocator = std.testing.allocator;

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = @intFromEnum(game_ids.WeaponId.assault_rifle),
        .experience = 2060,
        .level = 1,
        .ammo = 50.0,
        .health = 100.0,
    };

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_rush,
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffold(replay);
    try std.testing.expectEqual(@as(i32, 2060), result.player_experience);
    try std.testing.expectEqual(@as(i32, 1), result.player_level);
    try std.testing.expectEqual(@as(i32, 0), result.perk_pending_count);
}

test "survival scaffold supports player counts 1 through 4" {
    const allocator = std.testing.allocator;

    var player_count: i32 = 1;
    while (player_count <= 4) : (player_count += 1) {
        const players_len: usize = @intCast(player_count);
        const fire_player: usize = players_len - 1;

        const row0_storage = [_]u32{0} ** survival_state.max_players;
        var row1_storage = [_]u32{0} ** survival_state.max_players;
        row1_storage[fire_player] = replay_codec.fire_down_flag;

        const rows = [_][]const u32{
            row0_storage[0..players_len],
            row1_storage[0..players_len],
        };

        const replay = try buildTestReplayMulti(allocator, .{
            .game_mode_id = game_mode_survival,
            .seed = 0x1234,
            .tick_rate = 60,
            .player_count = player_count,
            .inputs = rows[0..],
            .events = &.{
                .{ .perk_menu_open = .{
                    .tick_index = 1,
                    .player_index = @intCast(player_count - 1),
                } },
            },
        });
        defer replay.deinit(allocator);

        const result = try runReplayScaffold(replay);
        try std.testing.expectEqual(@as(usize, 2), result.ticks);
        try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
    }
}

test "rush scaffold supports player counts 1 through 4" {
    const allocator = std.testing.allocator;

    var player_count: i32 = 1;
    while (player_count <= 4) : (player_count += 1) {
        const players_len: usize = @intCast(player_count);

        const row0_storage = [_]u32{0} ** survival_state.max_players;
        const row1_storage = [_]u32{replay_codec.fire_down_flag} ** survival_state.max_players;
        const rows = [_][]const u32{
            row0_storage[0..players_len],
            row1_storage[0..players_len],
        };

        const replay = try buildTestReplayMulti(allocator, .{
            .game_mode_id = game_mode_rush,
            .seed = 0x1234,
            .tick_rate = 60,
            .player_count = player_count,
            .inputs = rows[0..],
            .events = &.{},
        });
        defer replay.deinit(allocator);

        const result = try runReplayScaffold(replay);
        try std.testing.expectEqual(@as(usize, 2), result.ticks);
        try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.player_weapon_id);
        try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.most_used_weapon_id);
    }
}

test "quest scaffold is deterministic with explicit spawn entries" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_quests,
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const quest_entries = [_]survival_spawn.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = survival_spawn.SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 5000,
            .count = 1,
        },
    };
    const result0 = try runReplayScaffoldWithOptions(replay, .{
        .quest_spawn_entries = quest_entries[0..],
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
    });
    const result1 = try runReplayScaffoldWithOptions(replay, .{
        .quest_spawn_entries = quest_entries[0..],
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
    });
    try std.testing.expectEqual(result0.wave_spawn_rng_state, result1.wave_spawn_rng_state);
    try std.testing.expectEqual(@as(usize, 10), result0.ticks);
}

test "quest scaffold timeline uses frame dt even when reflex boost is active" {
    const allocator = std.testing.allocator;

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 100.0,
        .ammo = 11.0,
    };
    bootstrap.reflex_boost_ms = 500;

    const quest_entries = [_]survival_spawn.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = survival_spawn.SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 100_000,
            .count = 1,
        },
    };

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_quests,
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .quest_spawn_entries = quest_entries[0..],
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
    });
    try std.testing.expectEqual(@as(i64, 16), result.elapsed_ms_sim);
}

test "quest scaffold advances spawn timeline and fires entries" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_quests,
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const quest_entries = [_]survival_spawn.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = survival_spawn.SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 200,
            .count = 1,
        },
    };
    const result = try runReplayScaffoldWithOptions(replay, .{
        .quest_spawn_entries = quest_entries[0..],
        .dt_frame_overrides = &.{
            .{ .tick_index = 0, .dt_frame = 0.5 },
        },
    });
    try std.testing.expectEqual(@as(i64, 500), result.elapsed_ms_sim);
    try std.testing.expect(result.wave_spawn_count > 0);
    try std.testing.expect(result.creature_active_count > 0);
}

test "quest scaffold supports multiplayer replays with explicit start weapon" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplayMulti(allocator, .{
        .game_mode_id = game_mode_quests,
        .seed = 101,
        .tick_rate = 60,
        .player_count = 2,
        .inputs = &.{
            &.{ 0, 0 },
            &.{ replay_codec.fire_pressed_flag, replay_codec.reload_pressed_flag },
        },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 1, .player_index = 1 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.ion_cannon),
    });
    try std.testing.expectEqual(@as(usize, 2), result.ticks);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.ion_cannon), result.player_weapon_id);
    try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
}

test "quest scaffold resolves native quest preset and start weapon from replay header" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_quests,
        .seed = 205,
        .tick_rate = 60,
        .quest_level = "2.5",
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .dt_frame_overrides = &.{
            .{ .tick_index = 0, .dt_frame = 3.0 },
        },
    });
    try std.testing.expectEqual(@as(i32, 6), result.player_weapon_id);
    try std.testing.expect(result.wave_spawn_count > 0);
}

test "quest scaffold supports dynamic quest seed variants when no spawn entries are provided" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_quests,
        .seed = 999,
        .tick_rate = 60,
        .quest_level = "2.5",
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplayScaffoldWithOptions(replay, .{
        .dt_frame_overrides = &.{
            .{ .tick_index = 0, .dt_frame = 3.0 },
        },
    });
    try std.testing.expectEqual(@as(i32, 6), result.player_weapon_id);
    try std.testing.expect(result.wave_spawn_count > 0);
}

test "quest scaffold rejects unknown quest level when no spawn entries are provided" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_quests,
        .seed = 999,
        .tick_rate = 60,
        .quest_level = "9.9",
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(error.UnsupportedQuestSpawnTable, runReplayScaffold(replay));
}

test "quest scaffold supports player counts 1 through 4 across static and dynamic levels" {
    const allocator = std.testing.allocator;
    const level_cases = [_]struct {
        quest_level: []const u8,
        seed: u32,
        expected_start_weapon: i32,
    }{
        .{ .quest_level = "1.1", .seed = 101, .expected_start_weapon = @intFromEnum(game_ids.WeaponId.pistol) },
        .{ .quest_level = "2.5", .seed = 205, .expected_start_weapon = 6 },
        .{ .quest_level = "3.3", .seed = 205, .expected_start_weapon = @intFromEnum(game_ids.WeaponId.pistol) },
        .{ .quest_level = "3.9", .seed = 999, .expected_start_weapon = 6 },
    };

    for (level_cases) |case| {
        var player_count: i32 = 1;
        while (player_count <= 4) : (player_count += 1) {
            const players_len: usize = @intCast(player_count);
            const row_storage = [_]u32{0} ** survival_state.max_players;
            const rows = [_][]const u32{row_storage[0..players_len]};

            const replay = try buildTestReplayMulti(allocator, .{
                .game_mode_id = game_mode_quests,
                .seed = case.seed,
                .tick_rate = 60,
                .player_count = player_count,
                .quest_level = case.quest_level,
                .inputs = rows[0..],
                .events = &.{},
            });
            defer replay.deinit(allocator);

            const result = try runReplayScaffoldWithOptions(replay, .{
                .dt_frame_overrides = &.{
                    .{ .tick_index = 0, .dt_frame = 3.0 },
                },
            });
            try std.testing.expectEqual(@as(usize, 1), result.ticks);
            try std.testing.expectEqual(case.expected_start_weapon, result.player_weapon_id);
            try std.testing.expect(result.wave_spawn_count > 0);
        }
    }
}

test "quest scaffold applies capture bootstrap quest session timers" {
    const allocator = std.testing.allocator;

    const inputs = [_]u32{0} ** 20;
    const replay_baseline = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_quests,
        .seed = 101,
        .tick_rate = 60,
        .inputs = inputs[0..],
        .events = &.{},
    });
    defer replay_baseline.deinit(allocator);

    const quest_entries = [_]survival_spawn.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = survival_spawn.SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 5000,
            .count = 1,
        },
    };

    var dt_overrides: [20]DtFrameOverride = undefined;
    for (&dt_overrides, 0..) |*entry, idx| {
        entry.* = .{
            .tick_index = idx,
            .dt_frame = 0.1,
        };
    }

    var baseline_trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer baseline_trace.deinit(allocator);
    _ = try runReplayScaffoldWithTrace(
        replay_baseline,
        &baseline_trace,
        allocator,
        .{
            .quest_spawn_entries = quest_entries[0..],
            .dt_frame_overrides = dt_overrides[0..],
        },
    );
    try std.testing.expectEqual(@as(usize, 20), baseline_trace.items.len);
    try std.testing.expectEqual(@as(usize, 0), baseline_trace.items[19].creature_count);

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 1,
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 100.0,
        .ammo = 11.0,
        .experience = 0,
        .level = 1,
    };
    bootstrap.quest_session = .{
        .spawn_timeline_ms = 1701.0,
        .no_creatures_timer_ms = 3100.0,
        .completion_transition_ms = -1.0,
    };
    const events = [_]replay_codec.ReplayEvent{
        .{ .capture_bootstrap = bootstrap },
    };
    const replay_bootstrapped = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_quests,
        .seed = 101,
        .tick_rate = 60,
        .inputs = inputs[0..],
        .events = events[0..],
    });
    defer replay_bootstrapped.deinit(allocator);

    var bootstrapped_trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer bootstrapped_trace.deinit(allocator);
    _ = try runReplayScaffoldWithTrace(
        replay_bootstrapped,
        &bootstrapped_trace,
        allocator,
        .{
            .quest_spawn_entries = quest_entries[0..],
            .dt_frame_overrides = dt_overrides[0..],
        },
    );
    try std.testing.expectEqual(@as(usize, 20), bootstrapped_trace.items.len);
    try std.testing.expect(bootstrapped_trace.items[19].creature_count > 0);
}

test "quest scaffold disables runtime spawn slot ticks when capture spawns are authoritative" {
    const allocator = std.testing.allocator;

    const inputs = [_]u32{0} ** 40;
    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 1,
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 100.0,
        .ammo = 11.0,
        .experience = 0,
        .level = 1,
    };
    bootstrap.quest_session = .{
        .spawn_timeline_ms = 0.0,
        .no_creatures_timer_ms = 0.0,
        .completion_transition_ms = -1.0,
    };

    var capture_spawn = replay_codec.CaptureCreatureSpawnEvent{
        .tick_index = 0,
    };
    capture_spawn.spawn_count = 1;
    capture_spawn.spawns[0] = .{
        .template_id = 0x0A,
        .pos_x = 900.0,
        .pos_y = 900.0,
        .heading = 0.0,
    };
    const events = [_]replay_codec.ReplayEvent{
        .{ .capture_bootstrap = bootstrap },
        .{ .capture_creature_spawn = capture_spawn },
    };

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_quests,
        .seed = 101,
        .tick_rate = 60,
        .inputs = inputs[0..],
        .events = events[0..],
    });
    defer replay.deinit(allocator);

    var dt_overrides: [40]DtFrameOverride = undefined;
    for (&dt_overrides, 0..) |*entry, idx| {
        entry.* = .{
            .tick_index = idx,
            .dt_frame = 0.1,
        };
    }

    const empty_entries = [_]survival_spawn.QuestSpawnEntry{};
    var trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer trace.deinit(allocator);
    _ = try runReplayScaffoldWithTrace(
        replay,
        &trace,
        allocator,
        .{
            .quest_spawn_entries = empty_entries[0..],
            .dt_frame_overrides = dt_overrides[0..],
        },
    );
    try std.testing.expectEqual(@as(usize, 40), trace.items.len);
    try std.testing.expectEqual(@as(usize, 1), trace.items[39].creature_count);
}

test "capture creature spawn event applies added head overrides" {
    var state = survival_state.GameplayState.init(1);
    var creatures = survival_creatures.CreaturePool{};
    creatures.reset();

    var event = replay_codec.CaptureCreatureSpawnEvent{
        .tick_index = 0,
    };
    event.spawn_count = 1;
    event.spawns[0] = .{
        .template_id = 0x18,
        .pos_x = -256.0,
        .pos_y = 256.0,
        .heading = -4.083981990814209,
    };
    event.added_head_count = 1;
    event.added_head[0] = .{
        .index = 1,
        .has_heading = true,
        .heading = 1.1278764009475708,
        .has_target_heading = true,
        .target_heading = 0.621416449546814,
        .has_ai_mode = true,
        .ai_mode = 3,
        .has_link_index = true,
        .link_index = 0,
        .has_hp = true,
        .hp = 123.5,
        .has_lifecycle_stage = true,
        .lifecycle_stage = 9.5,
        .has_orbit_angle = true,
        .orbit_angle = 0.25,
        .has_orbit_radius = true,
        .orbit_radius = 0.75,
        .has_flags = true,
        .flags = 17,
        .has_type_id = true,
        .type_id = 7,
        .has_pos = true,
        .pos_x = 12.25,
        .pos_y = 34.5,
    };

    try applyCaptureCreatureSpawnEvent(&state, &creatures, event);
    const creature = creatures.entries[1];
    try std.testing.expect(creature.active);
    try std.testing.expectApproxEqAbs(@as(f64, 1.1278764009475708), creature.heading, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 0.621416449546814), creature.target_heading, 1e-6);
    try std.testing.expectEqual(@as(i32, 3), creature.ai_mode);
    try std.testing.expectEqual(@as(i32, 0), creature.link_index);
    try std.testing.expectApproxEqAbs(@as(f64, 123.5), creature.hp, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 9.5), creature.lifecycle_stage, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 0.25), creature.orbit_angle, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 0.75), creature.orbit_radius, 1e-6);
    try std.testing.expectEqual(@as(u32, 17), creature.flags);
    try std.testing.expectEqual(@as(i32, 7), creature.type_id);
    try std.testing.expectApproxEqAbs(@as(f64, 12.25), creature.pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 34.5), creature.pos.y, 1e-6);
}

test "capture creature spawn event backfills ai7 rollover rng draw for spawned rows" {
    var base_state = survival_state.GameplayState.init(0x1234ABCD);
    var base_creatures = survival_creatures.CreaturePool{};
    base_creatures.reset();
    var base_event = replay_codec.CaptureCreatureSpawnEvent{
        .tick_index = 0,
    };
    base_event.spawn_count = 1;
    base_event.spawns[0] = .{
        .template_id = 0x20,
        .pos_x = 256.0,
        .pos_y = 256.0,
        .heading = -100.0,
    };
    try applyCaptureCreatureSpawnEvent(&base_state, &base_creatures, base_event);
    const rng_after_base = base_state.rng.state;

    var rollover_state = survival_state.GameplayState.init(0x1234ABCD);
    var rollover_creatures = survival_creatures.CreaturePool{};
    rollover_creatures.reset();
    var rollover_event = base_event;
    rollover_event.added_head_count = 1;
    rollover_event.added_head[0] = .{
        .index = 0,
        .has_flags = true,
        .flags = @intCast(survival_spawn.CreatureFlags.ai7_link_timer),
        .has_link_index = true,
        .link_index = -975,
    };
    try applyCaptureCreatureSpawnEvent(&rollover_state, &rollover_creatures, rollover_event);
    const rng_after_rollover = rollover_state.rng.state;

    var probe_rng = survival_spawn.Crand.init(rng_after_base);
    _ = probe_rng.rand();
    try std.testing.expectEqual(probe_rng.state, rng_after_rollover);
    try std.testing.expectEqual(@as(i32, -975), rollover_creatures.entries[0].link_index);
}

test "capture creature spawn event applies added head rows without spawn rows" {
    var state = survival_state.GameplayState.init(1);
    var creatures = survival_creatures.CreaturePool{};
    creatures.reset();

    var seed_event = replay_codec.CaptureCreatureSpawnEvent{
        .tick_index = 0,
    };
    seed_event.spawn_count = 1;
    seed_event.spawns[0] = .{
        .template_id = 0x24,
        .pos_x = 256.0,
        .pos_y = 256.0,
        .heading = 0.0,
    };
    try applyCaptureCreatureSpawnEvent(&state, &creatures, seed_event);

    var update_event = replay_codec.CaptureCreatureSpawnEvent{
        .tick_index = 0,
    };
    update_event.added_head_count = 1;
    update_event.added_head[0] = .{
        .index = 0,
        .has_heading = true,
        .heading = 0.28999999165534973,
        .has_target_heading = true,
        .target_heading = 0.521416425704956,
        .has_ai_mode = true,
        .ai_mode = 0,
        .has_link_index = true,
        .link_index = 1,
        .has_orbit_radius = true,
        .orbit_radius = 1.25,
        .has_flags = true,
        .flags = 5,
    };
    try applyCaptureCreatureSpawnEvent(&state, &creatures, update_event);

    const creature = creatures.entries[0];
    try std.testing.expect(creature.active);
    try std.testing.expectApproxEqAbs(@as(f64, 0.28999999165534973), creature.heading, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 0.521416425704956), creature.target_heading, 1e-6);
    try std.testing.expectEqual(@as(i32, 0), creature.ai_mode);
    try std.testing.expectEqual(@as(i32, 1), creature.link_index);
    try std.testing.expectApproxEqAbs(@as(f64, 1.25), creature.orbit_radius, 1e-6);
    try std.testing.expectEqual(@as(u32, 5), creature.flags);
}

test "quest scaffold resets run state on capture transition to terminal state" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = game_mode_quests,
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{ 0, replay_codec.fire_down_flag },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    var bootstrap = replay_codec.CaptureBootstrapEvent{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 17,
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 0.0,
        .ammo = 6.0,
        .experience = 11581,
        .level = 4,
    };
    bootstrap.reflex_boost_ms = 1769;
    bootstrap.player_perk_counts[0].pair_count = 1;
    bootstrap.player_perk_counts[0].pairs[0] = .{
        .perk_id = 54,
        .count = 1,
    };

    var transition = replay_codec.CaptureStateTransitionEvent{
        .tick_index = 0,
    };
    transition.transition_count = 1;
    transition.transitions[0] = .{
        .target_state = 12,
        .has_before_state = true,
        .before_state = 9,
        .has_after_state = true,
        .after_state = 12,
    };

    replay.events = blk: {
        const events = try allocator.alloc(replay_codec.ReplayEvent, 2);
        events[0] = .{ .capture_bootstrap = bootstrap };
        events[1] = .{ .capture_state_transition = transition };
        allocator.free(replay.events);
        break :blk events;
    };

    var trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer trace.deinit(allocator);
    const result = try runReplayScaffoldWithTrace(
        replay,
        &trace,
        allocator,
        .{
            .dt_frame_overrides = &.{
                .{ .tick_index = 0, .dt_frame = 0.1 },
                .{ .tick_index = 1, .dt_frame = 0.1 },
            },
            .quest_spawn_entries = &.{},
        },
    );

    try std.testing.expectEqual(@as(i32, 1), result.player_weapon_id);
    try std.testing.expectEqual(@as(i32, 0), result.player_experience);
    try std.testing.expectEqual(@as(i32, 1), result.player_level);
    try std.testing.expectEqual(@as(usize, 0), result.creature_active_count);
    try std.testing.expectEqual(@as(usize, 2), trace.items.len);
    try std.testing.expectEqual(@as(i32, 0), trace.items[1].bonus_reflex_boost_ms);
    try std.testing.expectEqual(@as(i32, 0), trace.items[1].player_perk54_count);
}

test "quest scaffold disables world dt perk steps for original capture dt overrides" {
    const allocator = std.testing.allocator;

    const bootstrap_event = replay_codec.ReplayEvent{
        .capture_bootstrap = blk: {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.players[0] = .{
                .weapon_id = 1,
                .pos_x = 512.0,
                .pos_y = 512.0,
                .health = 100.0,
                .ammo = 11.0,
                .experience = 0,
                .level = 1,
            };
            break :blk bootstrap;
        },
    };
    const reflex_apply_event = replay_codec.ReplayEvent{
        .capture_perk_apply = .{
            .tick_index = 0,
            .perk_id = survival_perks.PerkId.reflex_boosted,
            .outside_before = true,
        },
    };

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            bootstrap: replay_codec.ReplayEvent,
            reflex_apply: replay_codec.ReplayEvent,
            include_reflex_boosted: bool,
            dt_overrides: ?[]const DtFrameOverride,
        ) !struct { x_q4: i32, y_q4: i32 } {
            const events = [_]replay_codec.ReplayEvent{ bootstrap, reflex_apply };
            var replay = try buildTestReplay(allocator_inner, .{
                .game_mode_id = game_mode_quests,
                .seed = 101,
                .tick_rate = 60,
                .inputs = &.{0},
                .events = if (include_reflex_boosted) events[0..2] else events[0..1],
            });
            defer replay.deinit(allocator_inner);

            replay.inputs[0][0].move_x = 1.0;
            replay.inputs[0][0].move_y = 0.0;
            replay.inputs[0][0].aim_x = 700.0;
            replay.inputs[0][0].aim_y = 512.0;

            var trace: std.ArrayList(ReplayTickTrace) = .empty;
            defer trace.deinit(allocator_inner);
            _ = try runReplayScaffoldWithTrace(
                replay,
                &trace,
                allocator_inner,
                .{
                    .quest_spawn_entries = &.{},
                    .dt_frame_overrides = dt_overrides,
                },
            );
            try std.testing.expectEqual(@as(usize, 1), trace.items.len);
            return .{
                .x_q4 = trace.items[0].player_pos_x_q4,
                .y_q4 = trace.items[0].player_pos_y_q4,
            };
        }
    }.runCase;

    const no_override_without_perk = try run(
        allocator,
        bootstrap_event,
        reflex_apply_event,
        false,
        null,
    );
    const no_override_with_perk = try run(
        allocator,
        bootstrap_event,
        reflex_apply_event,
        true,
        null,
    );
    try std.testing.expect(no_override_with_perk.x_q4 != no_override_without_perk.x_q4);

    const dt_override_rows = [_]DtFrameOverride{
        .{ .tick_index = 0, .dt_frame = 0.1 },
    };
    const override_without_perk = try run(
        allocator,
        bootstrap_event,
        reflex_apply_event,
        false,
        dt_override_rows[0..],
    );
    const override_with_perk = try run(
        allocator,
        bootstrap_event,
        reflex_apply_event,
        true,
        dt_override_rows[0..],
    );
    try std.testing.expectEqual(override_without_perk.x_q4, override_with_perk.x_q4);
    try std.testing.expectEqual(override_without_perk.y_q4, override_with_perk.y_q4);
}

test "evil eyes targeting defaults to alive player slot in non-preserve mode" {
    var state = survival_state.GameplayState.init(1);
    state.preserve_bugs = false;
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 0.0 },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[1].perk_counts[@intCast(survival_perks.PerkId.evil_eyes)] = 1;

    var creatures = [_]survival_creatures.CreatureState{
        .{
            .active = true,
            .pos = .{ .x = 100.0, .y = 200.0 },
            .lifecycle_stage = 16.0,
            .size = 50.0,
            .hp = 100.0,
        },
    };

    updateEvilEyesTargets(&state, players[0..], creatures[0..]);
    try std.testing.expectEqual(@as(i32, -1), players[0].evil_eyes_target_creature);
    try std.testing.expectEqual(@as(i32, 0), players[1].evil_eyes_target_creature);
}

test "evil eyes targeting preserve bugs keeps player zero ownership" {
    var state = survival_state.GameplayState.init(1);
    state.preserve_bugs = true;
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 0.0 },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[1].perk_counts[@intCast(survival_perks.PerkId.evil_eyes)] = 1;

    var creatures = [_]survival_creatures.CreatureState{
        .{
            .active = true,
            .pos = .{ .x = 100.0, .y = 200.0 },
            .lifecycle_stage = 16.0,
            .size = 50.0,
            .hp = 100.0,
        },
    };

    updateEvilEyesTargets(&state, players[0..], creatures[0..]);
    try std.testing.expectEqual(@as(i32, -1), players[0].evil_eyes_target_creature);
}

test "evil eyes targeting assigns each alive owner in non-preserve mode" {
    var state = survival_state.GameplayState.init(1);
    state.preserve_bugs = false;
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 140.0, .y = 200.0 },
        },
    };
    players[0].perk_counts[@intCast(survival_perks.PerkId.evil_eyes)] = 1;
    players[1].perk_counts[@intCast(survival_perks.PerkId.evil_eyes)] = 1;

    var creatures = [_]survival_creatures.CreatureState{
        .{
            .active = true,
            .pos = .{ .x = 100.0, .y = 200.0 },
            .lifecycle_stage = 16.0,
            .size = 50.0,
            .hp = 100.0,
        },
        .{
            .active = true,
            .pos = .{ .x = 140.0, .y = 200.0 },
            .lifecycle_stage = 16.0,
            .size = 50.0,
            .hp = 100.0,
        },
    };

    updateEvilEyesTargets(&state, players[0..], creatures[0..]);
    try std.testing.expectEqual(@as(i32, 0), players[0].evil_eyes_target_creature);
    try std.testing.expectEqual(@as(i32, 1), players[1].evil_eyes_target_creature);
}

fn activeParticleCount(particles: *const survival_particles.ParticlePool) usize {
    var count: usize = 0;
    for (particles.entries) |entry| {
        if (entry.active) count += 1;
    }
    return count;
}

test "pyrokinetic spawns particle burst when collision timer wraps" {
    var state = survival_state.GameplayState.init(0);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[0].perk_counts[@intCast(survival_perks.PerkId.pyrokinetic)] = 1;

    var creatures = survival_creatures.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = 16.0,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };

    var particles = survival_particles.ParticlePool{};

    applyPyrokineticEffects(&state, players[0..], &creatures, &particles, 0.2);
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 5), activeParticleCount(&particles));

    const expected_intensities = [_]f64{ 0.8, 0.6, 0.4, 0.3, 0.2 };
    for (expected_intensities, 0..) |expected, idx| {
        try std.testing.expectApproxEqAbs(expected, particles.entries[idx].intensity, 1e-6);
    }
}

test "pyrokinetic uses f32 timer threshold before wrapping" {
    var state = survival_state.GameplayState.init(0);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[0].perk_counts[@intCast(survival_perks.PerkId.pyrokinetic)] = 1;

    var creatures = survival_creatures.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = 16.0,
        .collision_timer = 0.034000009298324585,
        .size = 50.0,
        .hp = 100.0,
    };

    var particles = survival_particles.ParticlePool{};

    applyPyrokineticEffects(
        &state,
        players[0..],
        &creatures,
        &particles,
        0.03400000184774399,
    );
    try std.testing.expect(creatures.entries[0].collision_timer > 0.0);
    try std.testing.expect(creatures.entries[0].collision_timer < 1e-6);
    try std.testing.expectEqual(@as(usize, 0), activeParticleCount(&particles));

    applyPyrokineticEffects(
        &state,
        players[0..],
        &creatures,
        &particles,
        0.03200000151991844,
    );
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 5), activeParticleCount(&particles));
}

test "pyrokinetic defaults to first alive player slot in non-preserve mode" {
    var state = survival_state.GameplayState.init(0);
    state.preserve_bugs = false;
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 0.0 },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[1].perk_counts[@intCast(survival_perks.PerkId.pyrokinetic)] = 1;

    var creatures = survival_creatures.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = 16.0,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };
    var particles = survival_particles.ParticlePool{};

    applyPyrokineticEffects(&state, players[0..], &creatures, &particles, 0.2);
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 5), activeParticleCount(&particles));
}

test "pyrokinetic preserve bugs keeps player zero only targeting" {
    var state = survival_state.GameplayState.init(0);
    state.preserve_bugs = true;
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 0.0 },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[1].perk_counts[@intCast(survival_perks.PerkId.pyrokinetic)] = 1;

    var creatures = survival_creatures.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = 16.0,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };
    var particles = survival_particles.ParticlePool{};

    applyPyrokineticEffects(&state, players[0..], &creatures, &particles, 0.2);
    try std.testing.expectApproxEqAbs(@as(f64, 0.1), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 0), activeParticleCount(&particles));
}

test "pyrokinetic targets all alive owners in default mode" {
    var state = survival_state.GameplayState.init(0);
    state.preserve_bugs = false;
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 140.0, .y = 200.0 },
        },
    };
    players[0].perk_counts[@intCast(survival_perks.PerkId.pyrokinetic)] = 1;
    players[1].perk_counts[@intCast(survival_perks.PerkId.pyrokinetic)] = 1;

    var creatures = survival_creatures.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = 16.0,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };
    creatures.entries[1] = .{
        .active = true,
        .pos = .{ .x = 140.0, .y = 200.0 },
        .lifecycle_stage = 16.0,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };
    var particles = survival_particles.ParticlePool{};

    applyPyrokineticEffects(&state, players[0..], &creatures, &particles, 0.2);
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), creatures.entries[1].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 10), activeParticleCount(&particles));
}

test "long distance runner ramps speed above base cap and coasts on release" {
    const dt = 0.1;
    const steps: usize = 12;
    var state = survival_state.GameplayState.init(1);
    var base_player = survival_state.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = (survival_state.Vec2{ .x = 1.0, .y = 0.0 }).toHeading(),
    };
    var perk_player = survival_state.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = (survival_state.Vec2{ .x = 1.0, .y = 0.0 }).toHeading(),
    };
    perk_player.perk_counts[@intCast(survival_perks.PerkId.long_distance_runner)] = 1;

    const move_input = replay_codec.ReplayPlayerInput{
        .move_x = 1.0,
        .move_y = 0.0,
        .aim_x = 101.0,
        .aim_y = 100.0,
        .flags = 0,
    };
    const move_flags = replay_codec.unpackInputFlags(0);

    for (0..steps) |_| {
        updatePlayerFromReplayInput(&base_player, move_input, move_flags, &state, dt);
        finalizePlayerPostUpdate(&base_player, 1024.0);
        updatePlayerFromReplayInput(&perk_player, move_input, move_flags, &state, dt);
        finalizePlayerPostUpdate(&perk_player, 1024.0);
    }

    var expected_perk_speed: f64 = 0.0;
    const dt_f32 = asF32F64(dt);
    for (0..steps) |_| {
        if (expected_perk_speed < 2.0) {
            expected_perk_speed = asF32F64(expected_perk_speed + dt_f32 * 4.0);
        }
        expected_perk_speed = asF32F64(expected_perk_speed + dt_f32);
        if (expected_perk_speed > 2.8) {
            expected_perk_speed = 2.8;
        }
    }

    try std.testing.expectApproxEqAbs(@as(f64, 2.0), base_player.move_speed, 1e-6);
    try std.testing.expectApproxEqAbs(expected_perk_speed, perk_player.move_speed, 1e-6);
    try std.testing.expect(perk_player.pos.x > base_player.pos.x);

    const prev_x = perk_player.pos.x;
    const coast_input = replay_codec.ReplayPlayerInput{
        .move_x = 0.0,
        .move_y = 0.0,
        .aim_x = perk_player.pos.x + 1.0,
        .aim_y = perk_player.pos.y,
        .flags = 0,
    };
    updatePlayerFromReplayInput(&perk_player, coast_input, move_flags, &state, dt);
    finalizePlayerPostUpdate(&perk_player, 1024.0);

    const expected_coast_speed = asF32F64(expected_perk_speed - dt_f32 * 15.0);
    try std.testing.expectApproxEqAbs(expected_coast_speed, perk_player.move_speed, 1e-6);
    try std.testing.expect(perk_player.pos.x > prev_x);
}

test "alternate weapon slows movement by 20 percent" {
    var state = survival_state.GameplayState.init(1);
    const move_heading = (survival_state.Vec2{ .x = 1.0, .y = 0.0 }).toHeading();
    var base_player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
        .move_speed = 2.0,
        .heading = move_heading,
    };
    var perk_player = survival_state.PlayerState{
        .index = 0,
        .pos = .{},
        .move_speed = 2.0,
        .heading = move_heading,
    };
    perk_player.perk_counts[@intCast(survival_perks.PerkId.alternate_weapon)] = 1;

    const input = replay_codec.ReplayPlayerInput{
        .move_x = 1.0,
        .move_y = 0.0,
        .aim_x = 0.0,
        .aim_y = 0.0,
        .flags = 0,
    };
    const flags = replay_codec.unpackInputFlags(0);

    updatePlayerFromReplayInput(&base_player, input, flags, &state, 1.0);
    finalizePlayerPostUpdate(&base_player, 1024.0);
    updatePlayerFromReplayInput(&perk_player, input, flags, &state, 1.0);
    finalizePlayerPostUpdate(&perk_player, 1024.0);

    try std.testing.expectApproxEqAbs(@as(f64, 100.0), base_player.pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 80.0), perk_player.pos.x, 1e-6);
}

test "fire cough projectile uses pre-move player position for muzzle origin" {
    var state = survival_state.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};
    var player = survival_state.PlayerState{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .aim = .{ .x = 200.0, .y = 100.0 },
        .aim_heading = 0.0,
        .fire_cough_timer = 1.95,
    };
    player.perk_counts[@intCast(survival_perks.PerkId.fire_caugh)] = 1;

    const before_pos = player.pos;
    survival_weapon_runtime.applyPlayerPerkTicks(
        &state,
        &player,
        &projectiles,
        0.1,
    );

    const move_input = replay_codec.ReplayPlayerInput{
        .move_x = 1.0,
        .move_y = 0.0,
        .aim_x = 200.0,
        .aim_y = 100.0,
        .flags = 0,
    };
    const move_flags = replay_codec.unpackInputFlags(0);
    updatePlayerFromReplayInput(&player, move_input, move_flags, &state, 0.1);
    finalizePlayerPostUpdate(&player, 1024.0);

    try std.testing.expect(player.pos.x > before_pos.x);

    const proj = projectiles.entries[0];
    try std.testing.expect(proj.active);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.fire_bullets), proj.type_id);

    const muzzle_dir = blk: {
        const dir = directionFromHeadingNative(0.0);
        const cos_theta = survival_math.cos(-0.150915);
        const sin_theta = survival_math.sin(-0.150915);
        break :blk survival_state.Vec2{
            .x = dir.x * cos_theta - dir.y * sin_theta,
            .y = dir.x * sin_theta + dir.y * cos_theta,
        };
    };
    const expected_pos = survival_state.Vec2.add(before_pos, muzzle_dir.mul(16.0));
    try std.testing.expectApproxEqAbs(expected_pos.x, proj.pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(expected_pos.y, proj.pos.y, 1e-6);
}

test "pending fireblast spawns sixteen plasma rifle projectiles" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var projectiles = survival_projectiles.ProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = survival_bonuses.BonusPool{};

    state.pending_fireblast_origins[0] = players[0].pos;
    state.pending_fireblast_count = 1;

    applyPendingBonusEffects(
        &state,
        players[0..],
        &projectiles,
        &creatures,
        &bonuses,
        0.016,
        1024.0,
        1,
    );

    var active_count: i32 = 0;
    for (projectiles.entries) |entry| {
        if (!entry.active) continue;
        active_count += 1;
        try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), entry.type_id);
    }
    try std.testing.expectEqual(@as(i32, 16), active_count);
    try std.testing.expectEqual(@as(i32, 0), state.pending_fireblast_count);
}

test "pending fireblast does not convert into fire bullets while guard is active" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .fire_bullets_timer = 1.0,
        },
    };
    var projectiles = survival_projectiles.ProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = survival_bonuses.BonusPool{};

    state.pending_fireblast_origins[0] = players[0].pos;
    state.pending_fireblast_count = 1;

    applyPendingBonusEffects(
        &state,
        players[0..],
        &projectiles,
        &creatures,
        &bonuses,
        0.016,
        1024.0,
        1,
    );

    var plasma_count: i32 = 0;
    var fire_bullets_count: i32 = 0;
    for (projectiles.entries) |entry| {
        if (!entry.active) continue;
        if (entry.type_id == @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle)) plasma_count += 1;
        if (entry.type_id == @intFromEnum(game_ids.ProjectileTypeId.fire_bullets)) fire_bullets_count += 1;
    }
    try std.testing.expectEqual(@as(i32, 16), plasma_count);
    try std.testing.expectEqual(@as(i32, 0), fire_bullets_count);
}

test "pending nuke damage is limited to radius" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var projectiles = survival_projectiles.ProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = survival_bonuses.BonusPool{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 612.0, .y = 512.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 812.0, .y = 512.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    state.pending_nuke_origins[0] = players[0].pos;
    state.pending_nuke_count = 1;

    applyPendingBonusEffects(
        &state,
        players[0..],
        &projectiles,
        &creatures,
        &bonuses,
        0.016,
        1024.0,
        1,
    );

    try std.testing.expect(creatures.entries[0].hp <= 0.0);
    try std.testing.expectApproxEqAbs(@as(f64, 10.0), creatures.entries[1].hp, 1e-6);
    try std.testing.expectEqual(@as(i32, 0), state.pending_nuke_count);
}

test "poison bullets does not trigger on pending nuke radius damage" {
    var state = survival_state.GameplayState.init(1);
    state.rng.state = 1; // Mirrors poison-hit seed but nuke path must not set poison flags.
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    players[0].perk_counts[@intCast(survival_perks.PerkId.poison_bullets)] = 1;
    var projectiles = survival_projectiles.ProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = survival_bonuses.BonusPool{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 612.0, .y = 512.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = survival_spawn.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 2000.0,
        .max_health = 2000.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    state.pending_nuke_origins[0] = players[0].pos;
    state.pending_nuke_count = 1;

    applyPendingBonusEffects(
        &state,
        players[0..],
        &projectiles,
        &creatures,
        &bonuses,
        0.016,
        1024.0,
        1,
    );

    try std.testing.expect((creatures.entries[0].flags & survival_spawn.CreatureFlags.self_damage_tick) == 0);
}

test "pending nuke spawns pistol and gauss projectiles with native meta ranges" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var projectiles = survival_projectiles.ProjectilePool{};
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = survival_bonuses.BonusPool{};

    state.pending_nuke_origins[0] = players[0].pos;
    state.pending_nuke_count = 1;

    applyPendingBonusEffects(
        &state,
        players[0..],
        &projectiles,
        &creatures,
        &bonuses,
        0.016,
        1024.0,
        1,
    );

    var pistol_count: i32 = 0;
    var gauss_count: i32 = 0;
    for (projectiles.entries) |entry| {
        if (!entry.active) continue;
        if (entry.type_id == @intFromEnum(game_ids.ProjectileTypeId.pistol)) {
            pistol_count += 1;
            try std.testing.expectApproxEqAbs(@as(f64, 55.0), entry.base_damage, 1e-6);
            try std.testing.expect(entry.speed_scale >= 0.5);
            try std.testing.expect(entry.speed_scale < 1.0);
        } else if (entry.type_id == @intFromEnum(game_ids.ProjectileTypeId.gauss_gun)) {
            gauss_count += 1;
            try std.testing.expectApproxEqAbs(@as(f64, 215.0), entry.base_damage, 1e-6);
            try std.testing.expectApproxEqAbs(@as(f64, 1.0), entry.speed_scale, 1e-6);
        }
    }

    try std.testing.expect(pistol_count >= 4);
    try std.testing.expect(pistol_count <= 7);
    try std.testing.expectEqual(@as(i32, 2), gauss_count);
}

test "pending creature projectile queue materializes hostile shots before projectile step" {
    var state = survival_state.GameplayState.init(1);
    var projectiles = survival_projectiles.ProjectilePool{};

    state.pending_creature_projectile_count = 1;
    state.pending_creature_projectile_type_ids[0] = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle);
    state.pending_creature_projectile_owner_ids[0] = 17;
    state.pending_creature_projectile_angles[0] = native_half_pi;
    state.pending_creature_projectile_positions[0] = .{ .x = 100.0, .y = 200.0 };

    applyPendingCreatureProjectiles(&state, &projectiles);

    try std.testing.expectEqual(@as(i32, 0), state.pending_creature_projectile_count);
    try std.testing.expect(projectiles.entries[0].active);
    try std.testing.expect(projectiles.entries[0].hits_players);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), projectiles.entries[0].type_id);
    try std.testing.expectEqual(@as(i32, 17), projectiles.entries[0].owner_id);
    try std.testing.expectApproxEqAbs(@as(f64, 100.0), projectiles.entries[0].pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 200.0), projectiles.entries[0].pos.y, 1e-6);
}

test "lifeline 50-50 replay perk effect deactivates every other eligible creature slot" {
    var state = survival_state.GameplayState.init(1);
    const before_rng = state.rng.state;
    var creatures = survival_creatures.CreaturePool{};

    for (0..8) |idx| {
        creatures.entries[idx].active = true;
        creatures.entries[idx].hp = 100.0;
        creatures.entries[idx].pos = .{
            .x = @floatFromInt(idx),
            .y = @as(f32, @floatFromInt(idx)) * 10.0,
        };
        creatures.entries[idx].flags = 0;
    }
    creatures.entries[3].flags = survival_spawn.CreatureFlags.anim_ping_pong;
    creatures.entries[5].hp = 600.0;

    applyReplayPerkCreatureEffects(
        survival_perks.PerkId.lifeline_50_50,
        &state,
        &creatures,
        0.016,
    );

    const expected = [_]bool{ true, false, true, true, true, true, true, false };
    for (expected, 0..) |active_expected, idx| {
        try std.testing.expectEqual(active_expected, creatures.entries[idx].active);
    }
    try std.testing.expect(before_rng != state.rng.state);
}

fn findSeedForRandModSequence(
    moduli: []const u32,
    targets: []const u32,
    max_seed: u32,
) ?u32 {
    if (moduli.len == 0 or moduli.len != targets.len) return null;

    var seed: u32 = 0;
    while (seed < max_seed) : (seed += 1) {
        var rng = survival_spawn.Crand.init(seed);
        var matches = true;
        for (moduli, targets) |modulus, target| {
            if (modulus == 0) return null;
            if ((rng.rand() % modulus) != target) {
                matches = false;
                break;
            }
        }
        if (matches) return seed;
    }
    return null;
}

test "jinxed kills creature and awards base reward" {
    const seed = findSeedForRandModSequence(
        &.{ 10, 0x14, 0x180 },
        &.{ 0, 0, 2 },
        500_000,
    ) orelse unreachable;
    const dt = 0.2;

    var state = survival_state.GameplayState.init(seed);
    state.jinxed_timer = 0.0;
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 50.0,
            .experience = 100,
        },
    };
    players[0].perk_counts[@intCast(perk_id_jinxed)] = 1;
    var creatures = survival_creatures.CreaturePool{};
    creatures.entries[2].active = true;
    creatures.entries[2].hp = 100.0;
    creatures.entries[2].lifecycle_stage = 16.0;
    creatures.entries[2].reward_value = 12.7;

    applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f64, 1.8), state.jinxed_timer, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, -1.0), creatures.entries[2].hp, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 12.0), creatures.entries[2].lifecycle_stage, 1e-6);
    try std.testing.expectEqual(@as(i32, 112), players[0].experience);
}

test "jinxed reward uses float32 sum before truncation" {
    const seed = findSeedForRandModSequence(
        &.{ 10, 0x14, 0x180 },
        &.{ 0, 0, 2 },
        500_000,
    ) orelse unreachable;
    const dt = 0.2;

    var state = survival_state.GameplayState.init(seed);
    state.jinxed_timer = 0.0;
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 50.0,
            .experience = 139_451,
        },
    };
    players[0].perk_counts[@intCast(perk_id_jinxed)] = 1;
    var creatures = survival_creatures.CreaturePool{};
    creatures.entries[2].active = true;
    creatures.entries[2].hp = 100.0;
    creatures.entries[2].lifecycle_stage = 16.0;
    creatures.entries[2].reward_value = 97.99636190476191;

    applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectEqual(@as(i32, 139_549), players[0].experience);
}

test "jinxed accident can target another alive player outside preserve bugs mode" {
    const seed = findSeedForRandModSequence(
        &.{ 10, 2, 0x14 },
        &.{ 3, 1, 0 },
        500_000,
    ) orelse unreachable;
    const dt = 0.2;

    var state = survival_state.GameplayState.init(seed);
    state.jinxed_timer = 0.0;
    state.preserve_bugs = false;
    state.bonuses.freeze = 1.0;
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 50.0,
        },
        .{
            .index = 1,
            .pos = .{ .x = 20.0, .y = 20.0 },
            .health = 70.0,
        },
    };
    players[0].perk_counts[@intCast(perk_id_jinxed)] = 1;
    var creatures = survival_creatures.CreaturePool{};

    applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f64, 1.8), state.jinxed_timer, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 50.0), players[0].health, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 65.0), players[1].health, 1e-6);
}

test "jinxed preserve bugs keeps accident damage on player zero" {
    const seed = findSeedForRandModSequence(
        &.{ 10, 0x14 },
        &.{ 3, 0 },
        500_000,
    ) orelse unreachable;
    const dt = 0.2;

    var state = survival_state.GameplayState.init(seed);
    state.jinxed_timer = 0.0;
    state.preserve_bugs = true;
    state.bonuses.freeze = 1.0;
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 50.0,
        },
        .{
            .index = 1,
            .pos = .{ .x = 20.0, .y = 20.0 },
            .health = 70.0,
        },
    };
    players[0].perk_counts[@intCast(perk_id_jinxed)] = 1;
    var creatures = survival_creatures.CreaturePool{};

    applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f64, 1.8), state.jinxed_timer, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 45.0), players[0].health, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 70.0), players[1].health, 1e-6);
}

test "jinxed timer uses f32 underflow threshold before proc" {
    const dt = 0.03400000184774399;
    var state = survival_state.GameplayState.init(7);
    state.jinxed_timer = 0.034000836312770844;
    const rng_before = state.rng.state;
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 50.0,
        },
    };
    players[0].perk_counts[@intCast(perk_id_jinxed)] = 1;
    var creatures = survival_creatures.CreaturePool{};

    applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f64, 8.344650268554688e-07), state.jinxed_timer, 1e-12);
    try std.testing.expectApproxEqAbs(@as(f64, 50.0), players[0].health, 1e-6);
    try std.testing.expectEqual(rng_before, state.rng.state);
}

test "jinxed preserve-bugs mode uses 383-slot pool while default uses 384-slot pool" {
    const seed = findSeedForRandModSequence(
        &.{ 10, 0x14, 0x180 },
        &.{ 0, 0, 0x17F },
        1_000_000,
    ) orelse unreachable;
    const dt = 0.2;

    var default_state = survival_state.GameplayState.init(seed);
    default_state.jinxed_timer = 0.0;
    default_state.preserve_bugs = false;
    var default_players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 50.0,
            .experience = 100,
        },
    };
    default_players[0].perk_counts[@intCast(perk_id_jinxed)] = 1;
    var default_creatures = survival_creatures.CreaturePool{};
    default_creatures.entries[0x17F].active = true;
    default_creatures.entries[0x17F].hp = 100.0;
    default_creatures.entries[0x17F].lifecycle_stage = 16.0;
    default_creatures.entries[0x17F].reward_value = 12.7;

    applyJinxedEffects(&default_state, default_players[0..], &default_creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f64, -1.0), default_creatures.entries[0x17F].hp, 1e-6);
    try std.testing.expectEqual(@as(i32, 112), default_players[0].experience);

    var bug_state = survival_state.GameplayState.init(seed);
    bug_state.jinxed_timer = 0.0;
    bug_state.preserve_bugs = true;
    var bug_players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 50.0,
            .experience = 100,
        },
    };
    bug_players[0].perk_counts[@intCast(perk_id_jinxed)] = 1;
    var bug_creatures = survival_creatures.CreaturePool{};
    bug_creatures.entries[0x17F].active = true;
    bug_creatures.entries[0x17F].hp = 100.0;
    bug_creatures.entries[0x17F].lifecycle_stage = 16.0;
    bug_creatures.entries[0x17F].reward_value = 12.7;

    applyJinxedEffects(&bug_state, bug_players[0..], &bug_creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f64, 100.0), bug_creatures.entries[0x17F].hp, 1e-6);
    try std.testing.expectEqual(@as(i32, 100), bug_players[0].experience);
}

test "reflex boosted perk scales world dt by 0.9" {
    const base_players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    var perk_players = [_]survival_state.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    perk_players[0].perk_counts[@intCast(survival_perks.PerkId.reflex_boosted)] = 1;

    try std.testing.expectApproxEqAbs(@as(f64, 1.0), applyPerkWorldDtSteps(base_players[0..], 1.0), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 0.9), applyPerkWorldDtSteps(perk_players[0..], 1.0), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), applyPerkWorldDtSteps(perk_players[0..], 0.0), 1e-6);
}

test "final revenge explosion applies radial damage on death transition" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = -0.5,
        },
    };
    players[0].perk_counts[@intCast(survival_perks.PerkId.final_revenge)] = 1;
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = survival_bonuses.BonusPool{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = 0,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 10000.0,
        .max_health = 10000.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });

    applyFinalRevengeOnDeathTransition(
        &state,
        players[0..],
        0,
        0.5,
        &creatures,
        &bonuses,
        0.2,
        1024.0,
        5,
    );

    try std.testing.expectApproxEqAbs(@as(f64, 7440.0), creatures.entries[0].hp, 1e-6);
}

test "final revenge aoe includes active non-positive hp entries" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = -1.0,
        },
    };
    players[0].perk_counts[@intCast(survival_perks.PerkId.final_revenge)] = 1;
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = survival_bonuses.BonusPool{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = 0,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 1.0,
        .max_health = 1.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });
    creatures.entries[0].hp = 0.0;
    creatures.entries[0].lifecycle_stage = 16.0;

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = 0,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 2000.0, .y = 2000.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = 0,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });

    applyFinalRevengeOnDeathTransition(
        &state,
        players[0..],
        0,
        1.0,
        &creatures,
        &bonuses,
        0.1,
        1024.0,
        5,
    );

    try std.testing.expectApproxEqAbs(@as(f64, 14.5), creatures.entries[0].lifecycle_stage, 1e-6);
    try std.testing.expect(creatures.entries[1].hp < 10.0);
    try std.testing.expectApproxEqAbs(@as(f64, 10.0), creatures.entries[2].hp, 1e-6);
}

const TestReplayConfig = struct {
    game_mode_id: i32 = game_mode_survival,
    seed: u32 = 1,
    tick_rate: i32,
    quest_level: []const u8 = "",
    inputs: []const u32,
    events: []const replay_codec.ReplayEvent,
};

const TestReplayMultiConfig = struct {
    game_mode_id: i32 = game_mode_survival,
    seed: u32 = 1,
    tick_rate: i32,
    player_count: i32,
    quest_level: []const u8 = "",
    inputs: []const []const u32,
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
            .game_mode_id = cfg.game_mode_id,
            .seed = cfg.seed,
            .replay_format_version = replay_codec.replay_format_version,
            .quest_level = try allocator.dupe(u8, cfg.quest_level),
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

fn buildTestReplayMulti(
    allocator: std.mem.Allocator,
    cfg: TestReplayMultiConfig,
) !replay_codec.Replay {
    const ticks = try allocator.alloc(replay_codec.ReplayTickInputs, cfg.inputs.len);
    errdefer allocator.free(ticks);
    const players_len: usize = @intCast(cfg.player_count);

    for (cfg.inputs, 0..) |tick_flags, tick_index| {
        std.debug.assert(tick_flags.len == players_len);
        const input_tick = try allocator.alloc(replay_codec.ReplayPlayerInput, players_len);
        for (tick_flags, 0..) |flags, player_index| {
            input_tick[player_index] = .{
                .move_x = 0.0,
                .move_y = 0.0,
                .aim_x = 0.0,
                .aim_y = 0.0,
                .flags = flags,
            };
        }
        ticks[tick_index] = input_tick;
    }

    const events = try allocator.alloc(replay_codec.ReplayEvent, cfg.events.len);
    for (cfg.events, 0..) |event, idx| {
        events[idx] = event;
    }

    return .{
        .header = .{
            .game_mode_id = cfg.game_mode_id,
            .seed = cfg.seed,
            .replay_format_version = replay_codec.replay_format_version,
            .quest_level = try allocator.dupe(u8, cfg.quest_level),
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
            .player_count = cfg.player_count,
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
