const std = @import("std");

const bonus_runtime = @import("../bonuses.zig");
const creatures_mod = @import("../creatures.zig");
const native_math = @import("../native_math.zig");
const perks = @import("../perks.zig");
const projectiles_mod = @import("../projectiles.zig");
const state_mod = @import("../state.zig");

const narrowF32 = native_math.roundF32;
const PerkId = perks.PerkId;

pub const replay_tick_trace_schema_version: i32 = 2;

pub const ProjectileTraceEntry = struct {
    index: usize,
    type_id: i32,
    pos_x_q4: i32,
    pos_y_q4: i32,
    origin_x_q4: i32,
    origin_y_q4: i32,
    life_timer_q4: i32,
    damage_pool_q4: i32,
    angle_q6: i32,
    speed_scale_q4: i32,
    owner_legacy: i32,
    hits_players: bool,
};

pub const CreatureTraceEntry = struct {
    index: usize,
    type_id: i32,
    flags: i32,
    ai_mode: i32,
    link_index: i32,
    pos_x_q4: i32,
    pos_y_q4: i32,
    target_x_q4: i32,
    target_y_q4: i32,
    heading_q6: i32,
    target_heading_q6: i32,
    hp_q4: i32,
    lifecycle_stage_q4: i32,
    size_q4: i32,
    attack_cooldown_q6: i32,
};

pub const ReplayTickTimingV2 = struct {
    elapsed_ms: i64,
};

pub const ReplayTickRngV2 = struct {
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
};

pub const ReplayTickSummaryV2 = struct {
    elapsed_ms: i64 = 0,
    score_xp: i32,
    kills: i32,
    shots_fired_p0: i32,
    creature_count: usize,
    creature_active_index_sum: i32,
    creature_active_index_xor: i32,
    creature_state_hash: u64,
    perk_pending: i32,
};

pub const ReplayTickSummaryJsonV2 = struct {
    score_xp: i32,
    kills: i32,
    shots_fired_p0: i32,
    creature_count: usize,
    creature_active_index_sum: i32,
    creature_active_index_xor: i32,
    creature_state_hash: u64,
    perk_pending: i32,
};

pub const ReplayTickPlayerV2 = struct {
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
};

pub const ReplayTickBonusesV2 = struct {
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
};

pub const ReplayTickProjectilesV2 = struct {
    projectile_state_hash: u64,
    projectile_count: usize,
    projectile_active_index_sum: i32,
    projectile_active_index_xor: i32,
    projectile_type45_count: usize,
    projectile_hit_count: i32,
    projectile_type1_count: usize,
    projectile_type6_count: usize,
    projectile_type11_count: usize,
    projectile_type21_count: usize,
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
    entries_len: usize,
    entries: [projectiles_mod.main_projectile_pool_size]ProjectileTraceEntry,
};

pub const ReplayTickCreaturesV2 = struct {
    entries_len: usize,
    entries: [creatures_mod.max_creatures]CreatureTraceEntry,
};

pub const ReplayTickDebugV2 = struct {
    debug_pending_nuke: i32,
    debug_nuke_kills_last: i32,
    debug_nuke_tick_last: i32,
    debug_nuke_kill_index_sum: i32,
    debug_last_picked_bonus_id: i32,
    debug_last_picked_bonus_amount: i32,
};

pub const ReplayTickTraceV2 = struct {
    tick: usize = 0,
    tick_index: usize,
    timing: ReplayTickTimingV2,
    rng: ReplayTickRngV2,
    summary: ReplayTickSummaryV2,
    player: ReplayTickPlayerV2,
    bonuses: ReplayTickBonusesV2,
    projectiles: ReplayTickProjectilesV2,
    creatures: ReplayTickCreaturesV2,
    debug: ReplayTickDebugV2,
};

pub const ReplayTickProjectilesJsonV2 = struct {
    projectile_state_hash: u64,
    projectile_count: usize,
    projectile_active_index_sum: i32,
    projectile_active_index_xor: i32,
    projectile_type45_count: usize,
    projectile_hit_count: i32,
    projectile_type1_count: usize,
    projectile_type6_count: usize,
    projectile_type11_count: usize,
    projectile_type21_count: usize,
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
    entries: []const ProjectileTraceEntry,
};

pub const ReplayTickCreaturesJsonV2 = struct {
    entries: []const CreatureTraceEntry,
};

pub const ReplayTickTraceJsonRowV2 = struct {
    schema_version: i32,
    tick_index: usize,
    timing: ReplayTickTimingV2,
    rng: ReplayTickRngV2,
    summary: ReplayTickSummaryJsonV2,
    player: ReplayTickPlayerV2,
    bonuses: ReplayTickBonusesV2,
    projectiles: ReplayTickProjectilesJsonV2,
    creatures: ReplayTickCreaturesJsonV2,
    debug: ReplayTickDebugV2,
};

pub fn toJsonRowV2(trace: anytype) ReplayTickTraceJsonRowV2 {
    const projectile_entries = trace.projectiles.entries[0..trace.projectiles.entries_len];
    const creature_entries = trace.creatures.entries[0..trace.creatures.entries_len];
    return .{
        .schema_version = replay_tick_trace_schema_version,
        .tick_index = traceTickIndex(trace),
        .timing = .{
            .elapsed_ms = traceElapsedMs(trace),
        },
        .rng = .{
            .rng_state = trace.rng.rng_state,
            .rng_after_perk_effects = trace.rng.rng_after_perk_effects,
            .rng_after_creatures = trace.rng.rng_after_creatures,
            .rng_after_projectiles = trace.rng.rng_after_projectiles,
            .rng_after_secondary_projectiles = trace.rng.rng_after_secondary_projectiles,
            .rng_after_particles = trace.rng.rng_after_particles,
            .rng_after_player_update = trace.rng.rng_after_player_update,
            .rng_after_stage_spawns = trace.rng.rng_after_stage_spawns,
            .rng_after_wave_spawns = trace.rng.rng_after_wave_spawns,
            .rng_after_spawns = trace.rng.rng_after_spawns,
            .rng_after_bonus_update = trace.rng.rng_after_bonus_update,
        },
        .summary = .{
            .score_xp = trace.summary.score_xp,
            .kills = trace.summary.kills,
            .shots_fired_p0 = trace.summary.shots_fired_p0,
            .creature_count = trace.summary.creature_count,
            .creature_active_index_sum = trace.summary.creature_active_index_sum,
            .creature_active_index_xor = trace.summary.creature_active_index_xor,
            .creature_state_hash = trace.summary.creature_state_hash,
            .perk_pending = trace.summary.perk_pending,
        },
        .player = .{
            .player_weapon_id = trace.player.player_weapon_id,
            .player_ammo_q4 = trace.player.player_ammo_q4,
            .player_health_q4 = trace.player.player_health_q4,
            .player_pos_x_q4 = trace.player.player_pos_x_q4,
            .player_pos_y_q4 = trace.player.player_pos_y_q4,
            .player_aim_x_q4 = trace.player.player_aim_x_q4,
            .player_aim_y_q4 = trace.player.player_aim_y_q4,
            .player_heading_q6 = trace.player.player_heading_q6,
            .player_aim_heading_q6 = trace.player.player_aim_heading_q6,
            .player_move_speed_q4 = trace.player.player_move_speed_q4,
            .player_turn_speed_q4 = trace.player.player_turn_speed_q4,
            .player_level = trace.player.player_level,
            .player_experience = trace.player.player_experience,
            .player_reload_active = trace.player.player_reload_active,
            .player_reload_timer_q4 = trace.player.player_reload_timer_q4,
            .player_shot_cooldown_q4 = trace.player.player_shot_cooldown_q4,
            .player_shot_seq = trace.player.player_shot_seq,
            .player_perk31_count = trace.player.player_perk31_count,
            .player_perk53_count = trace.player.player_perk53_count,
            .player_perk54_count = trace.player.player_perk54_count,
            .player_perk55_count = trace.player.player_perk55_count,
            .player_hot_tempered_timer_q6 = trace.player.player_hot_tempered_timer_q6,
            .player_shield_timer_q4 = trace.player.player_shield_timer_q4,
            .player_man_bomb_timer_q6 = trace.player.player_man_bomb_timer_q6,
            .player_fire_cough_timer_q6 = trace.player.player_fire_cough_timer_q6,
            .player_living_fortress_timer_q6 = trace.player.player_living_fortress_timer_q6,
            .perk_interval_hot_tempered_q6 = trace.player.perk_interval_hot_tempered_q6,
            .perk_interval_man_bomb_q6 = trace.player.perk_interval_man_bomb_q6,
            .perk_interval_fire_cough_q6 = trace.player.perk_interval_fire_cough_q6,
        },
        .bonuses = .{
            .bonus_weapon_power_up_ms = trace.bonuses.bonus_weapon_power_up_ms,
            .bonus_reflex_boost_ms = trace.bonuses.bonus_reflex_boost_ms,
            .bonus_energizer_ms = trace.bonuses.bonus_energizer_ms,
            .bonus_double_experience_ms = trace.bonuses.bonus_double_experience_ms,
            .bonus_freeze_ms = trace.bonuses.bonus_freeze_ms,
            .bonus_active_count = trace.bonuses.bonus_active_count,
            .bonus0_id = trace.bonuses.bonus0_id,
            .bonus0_amount = trace.bonuses.bonus0_amount,
            .bonus1_id = trace.bonuses.bonus1_id,
            .bonus1_amount = trace.bonuses.bonus1_amount,
        },
        .projectiles = .{
            .projectile_state_hash = trace.projectiles.projectile_state_hash,
            .projectile_count = trace.projectiles.projectile_count,
            .projectile_active_index_sum = trace.projectiles.projectile_active_index_sum,
            .projectile_active_index_xor = trace.projectiles.projectile_active_index_xor,
            .projectile_type45_count = trace.projectiles.projectile_type45_count,
            .projectile_hit_count = trace.projectiles.projectile_hit_count,
            .projectile_type1_count = trace.projectiles.projectile_type1_count,
            .projectile_type6_count = trace.projectiles.projectile_type6_count,
            .projectile_type11_count = trace.projectiles.projectile_type11_count,
            .projectile_type21_count = trace.projectiles.projectile_type21_count,
            .projectile_first_hit_creature_index = trace.projectiles.projectile_first_hit_creature_index,
            .projectile_first_hit_projectile_index = trace.projectiles.projectile_first_hit_projectile_index,
            .projectile_first_hit_type_id = trace.projectiles.projectile_first_hit_type_id,
            .projectile_first_hit_origin_x_q4 = trace.projectiles.projectile_first_hit_origin_x_q4,
            .projectile_first_hit_origin_y_q4 = trace.projectiles.projectile_first_hit_origin_y_q4,
            .projectile_first_hit_pos_x_q4 = trace.projectiles.projectile_first_hit_pos_x_q4,
            .projectile_first_hit_pos_y_q4 = trace.projectiles.projectile_first_hit_pos_y_q4,
            .projectile_first_hit_target_size_q4 = trace.projectiles.projectile_first_hit_target_size_q4,
            .projectile_first_hit_target_x_q4 = trace.projectiles.projectile_first_hit_target_x_q4,
            .projectile_first_hit_target_y_q4 = trace.projectiles.projectile_first_hit_target_y_q4,
            .entries = @ptrCast(projectile_entries),
        },
        .creatures = .{
            .entries = @ptrCast(creature_entries),
        },
        .debug = .{
            .debug_pending_nuke = trace.debug.debug_pending_nuke,
            .debug_nuke_kills_last = trace.debug.debug_nuke_kills_last,
            .debug_nuke_tick_last = trace.debug.debug_nuke_tick_last,
            .debug_nuke_kill_index_sum = trace.debug.debug_nuke_kill_index_sum,
            .debug_last_picked_bonus_id = trace.debug.debug_last_picked_bonus_id,
            .debug_last_picked_bonus_amount = trace.debug.debug_last_picked_bonus_amount,
        },
    };
}

fn traceTickIndex(trace: anytype) usize {
    const trace_type = @TypeOf(trace.*);
    if (@hasField(trace_type, "tick_index") and @hasField(trace_type, "tick")) {
        return if (trace.tick_index != 0) trace.tick_index else trace.tick;
    }
    if (@hasField(trace_type, "tick_index")) return trace.tick_index;
    if (@hasField(trace_type, "tick")) return trace.tick;
    @compileError("toJsonRowV2 expects a trace with tick_index or tick");
}

fn traceElapsedMs(trace: anytype) i64 {
    const trace_type = @TypeOf(trace.*);
    if (@hasField(trace_type, "timing") and @hasField(@TypeOf(trace.summary), "elapsed_ms")) {
        return if (trace.timing.elapsed_ms != 0) trace.timing.elapsed_ms else trace.summary.elapsed_ms;
    }
    if (@hasField(trace_type, "timing")) return trace.timing.elapsed_ms;
    if (@hasField(trace_type, "summary")) return trace.summary.elapsed_ms;
    @compileError("toJsonRowV2 expects a trace with timing.elapsed_ms or summary.elapsed_ms");
}

pub fn buildReplayTickTraceV2(
    tick_index: usize,
    elapsed_ms_sim: f32,
    state: *const state_mod.GameplayState,
    player: state_mod.PlayerState,
    creatures: *const creatures_mod.CreaturePool,
    bonuses: *const bonus_runtime.BonusPool,
    projectiles: *const projectiles_mod.ProjectilePool,
    projectile_tick_stats: projectiles_mod.ProjectileTickStats,
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
) ReplayTickTraceV2 {
    var projectile_count: usize = 0;
    var projectile_state_hash: u64 = 1469598103934665603;
    var projectile_type1_count: usize = 0;
    var projectile_type6_count: usize = 0;
    var projectile_type11_count: usize = 0;
    var projectile_type21_count: usize = 0;
    var projectile_type45_count: usize = 0;
    var projectile_active_index_sum: i32 = 0;
    var projectile_active_index_xor: i32 = 0;
    var projectile_entries: [projectiles_mod.main_projectile_pool_size]ProjectileTraceEntry = undefined;
    var projectile_entries_len: usize = 0;
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
        projectile_state_hash = hashMix(projectile_state_hash, @bitCast(@as(i64, entry.owner.toLegacy())));
        projectile_state_hash = hashMix(projectile_state_hash, if (entry.hits_players) 1 else 0);
        projectile_count += 1;
        if (entry.type_id == 1) {
            projectile_type1_count += 1;
        }
        if (entry.type_id == 6) {
            projectile_type6_count += 1;
        }
        if (entry.type_id == 11) {
            projectile_type11_count += 1;
        }
        if (entry.type_id == 21) {
            projectile_type21_count += 1;
        }
        if (entry.type_id == 45) {
            projectile_type45_count += 1;
        }
        projectile_entries[projectile_entries_len] = .{
            .index = idx,
            .type_id = entry.type_id,
            .pos_x_q4 = quantizeQ4(entry.pos.x),
            .pos_y_q4 = quantizeQ4(entry.pos.y),
            .origin_x_q4 = quantizeQ4(entry.origin.x),
            .origin_y_q4 = quantizeQ4(entry.origin.y),
            .life_timer_q4 = quantizeQ4(entry.life_timer),
            .damage_pool_q4 = quantizeQ4(entry.damage_pool),
            .angle_q6 = quantizeQ6(entry.angle),
            .speed_scale_q4 = quantizeQ4(entry.speed_scale),
            .owner_legacy = entry.owner.toLegacy(),
            .hits_players = entry.hits_players,
        };
        projectile_entries_len += 1;
    }

    var creature_active_index_sum: i32 = 0;
    var creature_active_index_xor: i32 = 0;
    var creature_state_hash: u64 = 1469598103934665603;
    var creature_entries: [creatures_mod.max_creatures]CreatureTraceEntry = undefined;
    var creature_entries_len: usize = 0;
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
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, @intFromEnum(creature.ai_mode))));
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
        creature_state_hash = hashMix(creature_state_hash, @bitCast(@as(i64, creature.last_hit_owner.toLegacy())));
        creature_state_hash = hashMix(creature_state_hash, creature.flags);
        creature_entries[creature_entries_len] = .{
            .index = idx,
            .type_id = creature.type_id,
            .flags = @bitCast(creature.flags),
            .ai_mode = @intFromEnum(creature.ai_mode),
            .link_index = creature.link_index,
            .pos_x_q4 = quantizeQ4(creature.pos.x),
            .pos_y_q4 = quantizeQ4(creature.pos.y),
            .target_x_q4 = quantizeQ4(creature.target.x),
            .target_y_q4 = quantizeQ4(creature.target.y),
            .heading_q6 = quantizeQ6(creature.heading),
            .target_heading_q6 = quantizeQ6(creature.target_heading),
            .hp_q4 = quantizeQ4(creature.hp),
            .lifecycle_stage_q4 = quantizeQ4(creature.lifecycle_stage),
            .size_q4 = quantizeQ4(creature.size),
            .attack_cooldown_q6 = quantizeQ6(creature.attack_cooldown),
        };
        creature_entries_len += 1;
    }

    var bonus_active_count: usize = 0;
    var bonus0_id: i32 = 0;
    var bonus0_amount: i32 = 0;
    var bonus1_id: i32 = 0;
    var bonus1_amount: i32 = 0;
    for (bonuses.entries) |entry| {
        if (entry.bonus_id == .unused) continue;
        if (bonus_active_count == 0) {
            bonus0_id = @intFromEnum(entry.bonus_id);
            bonus0_amount = entry.amount;
        } else if (bonus_active_count == 1) {
            bonus1_id = @intFromEnum(entry.bonus_id);
            bonus1_amount = entry.amount;
        }
        bonus_active_count += 1;
    }

    return .{
        .tick = tick_index,
        .tick_index = tick_index,
        .timing = .{
            .elapsed_ms = @intFromFloat(@round(elapsed_ms_sim)),
        },
        .rng = .{
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
        },
        .summary = .{
            .elapsed_ms = @intFromFloat(@round(elapsed_ms_sim)),
            .score_xp = player.experience,
            .kills = creatures.kill_count,
            .shots_fired_p0 = if (state.shots_fired.len > 0) state.shots_fired[0] else 0,
            .creature_count = creatures.activeCount(),
            .creature_active_index_sum = creature_active_index_sum,
            .creature_active_index_xor = creature_active_index_xor,
            .creature_state_hash = creature_state_hash,
            .perk_pending = state.perk_selection.pending_count,
        },
        .player = .{
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
            .player_perk31_count = player.perk_counts.get(PerkId.hot_tempered),
            .player_perk53_count = player.perk_counts.get(PerkId.man_bomb),
            .player_perk54_count = player.perk_counts.get(PerkId.fire_caugh),
            .player_perk55_count = player.perk_counts.get(PerkId.living_fortress),
            .player_hot_tempered_timer_q6 = quantizeQ6(player.hot_tempered_timer),
            .player_shield_timer_q4 = quantizeQ4(player.shield_timer),
            .player_man_bomb_timer_q6 = quantizeQ6(player.man_bomb_timer),
            .player_fire_cough_timer_q6 = quantizeQ6(player.fire_cough_timer),
            .player_living_fortress_timer_q6 = quantizeQ6(player.living_fortress_timer),
            .perk_interval_hot_tempered_q6 = quantizeQ6(state.perk_interval_hot_tempered),
            .perk_interval_man_bomb_q6 = quantizeQ6(state.perk_interval_man_bomb),
            .perk_interval_fire_cough_q6 = quantizeQ6(state.perk_interval_fire_cough),
        },
        .bonuses = .{
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
        },
        .projectiles = .{
            .projectile_state_hash = projectile_state_hash,
            .projectile_count = projectile_count,
            .projectile_active_index_sum = projectile_active_index_sum,
            .projectile_active_index_xor = projectile_active_index_xor,
            .projectile_type45_count = projectile_type45_count,
            .projectile_hit_count = projectile_tick_stats.hit_count,
            .projectile_type1_count = projectile_type1_count,
            .projectile_type6_count = projectile_type6_count,
            .projectile_type11_count = projectile_type11_count,
            .projectile_type21_count = projectile_type21_count,
            .projectile_first_hit_creature_index = projectile_tick_stats.first_hit_creature_index,
            .projectile_first_hit_projectile_index = projectile_tick_stats.first_hit_projectile_index,
            .projectile_first_hit_type_id = projectile_tick_stats.first_hit_type_id,
            .projectile_first_hit_origin_x_q4 = quantizeQ4(projectile_tick_stats.first_hit_origin.x),
            .projectile_first_hit_origin_y_q4 = quantizeQ4(projectile_tick_stats.first_hit_origin.y),
            .projectile_first_hit_pos_x_q4 = quantizeQ4(projectile_tick_stats.first_hit_pos.x),
            .projectile_first_hit_pos_y_q4 = quantizeQ4(projectile_tick_stats.first_hit_pos.y),
            .projectile_first_hit_target_size_q4 = quantizeQ4(narrowF32(projectile_tick_stats.first_hit_target_size)),
            .projectile_first_hit_target_x_q4 = quantizeQ4(narrowF32(projectile_tick_stats.first_hit_target_x)),
            .projectile_first_hit_target_y_q4 = quantizeQ4(narrowF32(projectile_tick_stats.first_hit_target_y)),
            .entries_len = projectile_entries_len,
            .entries = projectile_entries,
        },
        .creatures = .{
            .entries_len = creature_entries_len,
            .entries = creature_entries,
        },
        .debug = .{
            .debug_pending_nuke = state.pending_nuke_count,
            .debug_nuke_kills_last = state.debug_nuke_kills_last,
            .debug_nuke_tick_last = state.debug_nuke_tick_last,
            .debug_nuke_kill_index_sum = state.debug_nuke_kill_index_sum,
            .debug_last_picked_bonus_id = @intFromEnum(state.debug_last_picked_bonus_id),
            .debug_last_picked_bonus_amount = state.debug_last_picked_bonus_amount,
        },
    };
}

fn quantizeQ4(value: f32) i32 {
    const scaled = @round(value * 10000.0);
    if (scaled <= @as(f32, @floatFromInt(std.math.minInt(i32)))) return std.math.minInt(i32);
    if (scaled >= @as(f32, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(scaled);
}

fn quantizeQ6(value: f32) i32 {
    const scaled = @round(value * 1_000_000.0);
    if (scaled <= @as(f32, @floatFromInt(std.math.minInt(i32)))) return std.math.minInt(i32);
    if (scaled >= @as(f32, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(scaled);
}

fn bonusTimerMs(seconds: f32) i32 {
    if (!(seconds > 0.0)) return 0;
    const ms = @round(seconds * 1000.0);
    if (ms <= 0.0) return 0;
    if (ms >= @as(f32, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(ms);
}

fn hashMix(seed: u64, value: u64) u64 {
    var h = seed ^ value;
    h *%= 1099511628211;
    return h;
}
