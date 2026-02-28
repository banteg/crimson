const std = @import("std");

const game_ids = @import("../../game_ids.zig");
const bonus_runtime = @import("../bonuses.zig");
const creatures_mod = @import("../creatures.zig");
const native_math = @import("../native_math.zig");
const perks = @import("../perks.zig");
const projectiles_mod = @import("../projectiles.zig");
const state_mod = @import("../state.zig");

const narrowF32 = native_math.roundF32;
const PerkId = perks.PerkId;

pub const replay_tick_trace_schema_version: i32 = 3;
pub const perk_count_size: usize = state_mod.perk_count_size;
pub const bonus_id_count: usize = @typeInfo(game_ids.BonusId).@"enum".fields.len;

pub const ProjectileTraceEntry = struct {
    index: usize,
    type_id: i32,
    pos_x_bits: u32,
    pos_y_bits: u32,
    origin_x_bits: u32,
    origin_y_bits: u32,
    life_timer_bits: u32,
    damage_pool_bits: u32,
    angle_bits: u32,
    speed_scale_bits: u32,
    owner_legacy: i32,
    hits_players: bool,
};

pub const CreatureTraceEntry = struct {
    index: usize,
    type_id: i32,
    flags: i32,
    ai_mode: i32,
    link_index: i32,
    pos_x_bits: u32,
    pos_y_bits: u32,
    target_x_bits: u32,
    target_y_bits: u32,
    heading_bits: u32,
    target_heading_bits: u32,
    hp_bits: u32,
    lifecycle_stage_bits: u32,
    size_bits: u32,
    attack_cooldown_bits: u32,
};

pub const BonusActiveEntry = struct {
    bonus_id: i32,
    amount: i32,
};

pub const ProjectileTypeCountEntry = struct {
    type_id: i32,
    count: usize,
};

pub const ReplayTickTiming = struct {
    elapsed_ms: i64,
};

pub const ReplayTickRng = struct {
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

pub const ReplayTickSummary = struct {
    elapsed_ms: i64 = 0,
    score_xp: i32,
    kills: i32,
    shots_fired_p0: i32,
    creature_count: usize,
    perk_pending: i32,
};

pub const ReplayTickSummaryJson = struct {
    score_xp: i32,
    kills: i32,
    shots_fired_p0: i32,
    creature_count: usize,
    perk_pending: i32,
};

pub const ReplayTickPlayer = struct {
    player_weapon_id: i32,
    player_ammo_bits: u32,
    player_health_bits: u32,
    player_pos_x_bits: u32,
    player_pos_y_bits: u32,
    player_aim_x_bits: u32,
    player_aim_y_bits: u32,
    player_heading_bits: u32,
    player_aim_heading_bits: u32,
    player_move_speed_bits: u32,
    player_turn_speed_bits: u32,
    player_level: i32,
    player_experience: i32,
    player_reload_active: bool,
    player_reload_timer_bits: u32,
    player_shot_cooldown_bits: u32,
    player_shot_seq: i32,
    player_perk_counts: [perk_count_size]i32,
    player_hot_tempered_timer_bits: u32,
    player_shield_timer_bits: u32,
    player_man_bomb_timer_bits: u32,
    player_fire_cough_timer_bits: u32,
    player_living_fortress_timer_bits: u32,
    perk_interval_hot_tempered_bits: u32,
    perk_interval_man_bomb_bits: u32,
    perk_interval_fire_cough_bits: u32,
};

pub const ReplayTickBonuses = struct {
    bonus_timer_ms_by_id: [bonus_id_count]i32,
    bonus_active_count: usize,
    active_entries_len: usize,
    active_entries: [bonus_runtime.bonus_pool_size]BonusActiveEntry,
};

pub const ReplayTickProjectiles = struct {
    projectile_count: usize,
    projectile_hit_count: i32,
    projectile_first_hit_creature_index: i32,
    projectile_first_hit_projectile_index: i32,
    projectile_first_hit_type_id: i32,
    projectile_first_hit_origin_x_bits: u32,
    projectile_first_hit_origin_y_bits: u32,
    projectile_first_hit_pos_x_bits: u32,
    projectile_first_hit_pos_y_bits: u32,
    projectile_first_hit_target_size_bits: u32,
    projectile_first_hit_target_x_bits: u32,
    projectile_first_hit_target_y_bits: u32,
    projectile_type_counts_len: usize,
    projectile_type_counts: [projectiles_mod.main_projectile_pool_size]ProjectileTypeCountEntry,
    entries_len: usize,
    entries: [projectiles_mod.main_projectile_pool_size]ProjectileTraceEntry,
};

pub const ReplayTickCreatures = struct {
    entries_len: usize,
    entries: [creatures_mod.max_creatures]CreatureTraceEntry,
};

pub const ReplayTickDebug = struct {
    debug_pending_nuke: i32,
    debug_nuke_kills_last: i32,
    debug_nuke_tick_last: i32,
    debug_nuke_kill_index_sum: i32,
    debug_last_picked_bonus_id: i32,
    debug_last_picked_bonus_amount: i32,
};

pub const ReplayTickTrace = struct {
    tick: usize = 0,
    tick_index: usize,
    timing: ReplayTickTiming,
    rng: ReplayTickRng,
    summary: ReplayTickSummary,
    player: ReplayTickPlayer,
    bonuses: ReplayTickBonuses,
    projectiles: ReplayTickProjectiles,
    creatures: ReplayTickCreatures,
    debug: ReplayTickDebug,
};

pub const ReplayTickBonusesJson = struct {
    bonus_timer_ms_by_id: [bonus_id_count]i32,
    bonus_active_count: usize,
    active_entries: []const BonusActiveEntry,
};

pub const ReplayTickProjectilesJson = struct {
    projectile_count: usize,
    projectile_hit_count: i32,
    projectile_first_hit_creature_index: i32,
    projectile_first_hit_projectile_index: i32,
    projectile_first_hit_type_id: i32,
    projectile_first_hit_origin_x_bits: u32,
    projectile_first_hit_origin_y_bits: u32,
    projectile_first_hit_pos_x_bits: u32,
    projectile_first_hit_pos_y_bits: u32,
    projectile_first_hit_target_size_bits: u32,
    projectile_first_hit_target_x_bits: u32,
    projectile_first_hit_target_y_bits: u32,
    projectile_type_counts: []const ProjectileTypeCountEntry,
    entries: []const ProjectileTraceEntry,
};

pub const ReplayTickCreaturesJson = struct {
    entries: []const CreatureTraceEntry,
};

pub const ReplayTickTraceJsonRow = struct {
    schema_version: i32,
    tick_index: usize,
    timing: ReplayTickTiming,
    rng: ReplayTickRng,
    summary: ReplayTickSummaryJson,
    player: ReplayTickPlayer,
    bonuses: ReplayTickBonusesJson,
    projectiles: ReplayTickProjectilesJson,
    creatures: ReplayTickCreaturesJson,
    debug: ReplayTickDebug,
};

pub fn toJsonRow(trace: anytype) ReplayTickTraceJsonRow {
    const bonus_active_entries = trace.bonuses.active_entries[0..trace.bonuses.active_entries_len];
    const projectile_type_counts = trace.projectiles.projectile_type_counts[0..trace.projectiles.projectile_type_counts_len];
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
            .perk_pending = trace.summary.perk_pending,
        },
        .player = trace.player,
        .bonuses = .{
            .bonus_timer_ms_by_id = trace.bonuses.bonus_timer_ms_by_id,
            .bonus_active_count = trace.bonuses.bonus_active_count,
            .active_entries = @ptrCast(bonus_active_entries),
        },
        .projectiles = .{
            .projectile_count = trace.projectiles.projectile_count,
            .projectile_hit_count = trace.projectiles.projectile_hit_count,
            .projectile_first_hit_creature_index = trace.projectiles.projectile_first_hit_creature_index,
            .projectile_first_hit_projectile_index = trace.projectiles.projectile_first_hit_projectile_index,
            .projectile_first_hit_type_id = trace.projectiles.projectile_first_hit_type_id,
            .projectile_first_hit_origin_x_bits = trace.projectiles.projectile_first_hit_origin_x_bits,
            .projectile_first_hit_origin_y_bits = trace.projectiles.projectile_first_hit_origin_y_bits,
            .projectile_first_hit_pos_x_bits = trace.projectiles.projectile_first_hit_pos_x_bits,
            .projectile_first_hit_pos_y_bits = trace.projectiles.projectile_first_hit_pos_y_bits,
            .projectile_first_hit_target_size_bits = trace.projectiles.projectile_first_hit_target_size_bits,
            .projectile_first_hit_target_x_bits = trace.projectiles.projectile_first_hit_target_x_bits,
            .projectile_first_hit_target_y_bits = trace.projectiles.projectile_first_hit_target_y_bits,
            .projectile_type_counts = @ptrCast(projectile_type_counts),
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
    @compileError("toJsonRow expects a trace with tick_index or tick");
}

fn traceElapsedMs(trace: anytype) i64 {
    const trace_type = @TypeOf(trace.*);
    if (@hasField(trace_type, "timing") and @hasField(@TypeOf(trace.summary), "elapsed_ms")) {
        return if (trace.timing.elapsed_ms != 0) trace.timing.elapsed_ms else trace.summary.elapsed_ms;
    }
    if (@hasField(trace_type, "timing")) return trace.timing.elapsed_ms;
    if (@hasField(trace_type, "summary")) return trace.summary.elapsed_ms;
    @compileError("toJsonRow expects a trace with timing.elapsed_ms or summary.elapsed_ms");
}

pub fn buildReplayTickTrace(
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
) ReplayTickTrace {
    var projectile_count: usize = 0;
    var projectile_type_counts: [projectiles_mod.main_projectile_pool_size]ProjectileTypeCountEntry = undefined;
    var projectile_type_counts_len: usize = 0;
    var projectile_entries: [projectiles_mod.main_projectile_pool_size]ProjectileTraceEntry = undefined;
    var projectile_entries_len: usize = 0;
    for (projectiles.entries, 0..) |entry, idx| {
        if (!entry.active) continue;

        projectile_count += 1;

        addProjectileTypeCount(&projectile_type_counts, &projectile_type_counts_len, entry.type_id);

        projectile_entries[projectile_entries_len] = .{
            .index = idx,
            .type_id = entry.type_id,
            .pos_x_bits = f32Bits(entry.pos.x),
            .pos_y_bits = f32Bits(entry.pos.y),
            .origin_x_bits = f32Bits(entry.origin.x),
            .origin_y_bits = f32Bits(entry.origin.y),
            .life_timer_bits = f32Bits(entry.life_timer),
            .damage_pool_bits = f32Bits(entry.damage_pool),
            .angle_bits = f32Bits(entry.angle),
            .speed_scale_bits = f32Bits(entry.speed_scale),
            .owner_legacy = entry.owner.toLegacy(),
            .hits_players = entry.hits_players,
        };
        projectile_entries_len += 1;
    }

    var creature_entries: [creatures_mod.max_creatures]CreatureTraceEntry = undefined;
    var creature_entries_len: usize = 0;
    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;

        creature_entries[creature_entries_len] = .{
            .index = idx,
            .type_id = creature.type_id,
            .flags = @bitCast(creature.flags),
            .ai_mode = @intFromEnum(creature.ai_mode),
            .link_index = creature.link_index,
            .pos_x_bits = f32Bits(creature.pos.x),
            .pos_y_bits = f32Bits(creature.pos.y),
            .target_x_bits = f32Bits(creature.target.x),
            .target_y_bits = f32Bits(creature.target.y),
            .heading_bits = f32Bits(creature.heading),
            .target_heading_bits = f32Bits(creature.target_heading),
            .hp_bits = f32Bits(creature.hp),
            .lifecycle_stage_bits = f32Bits(creature.lifecycle_stage),
            .size_bits = f32Bits(creature.size),
            .attack_cooldown_bits = f32Bits(creature.attack_cooldown),
        };
        creature_entries_len += 1;
    }

    var bonus_active_count: usize = 0;
    var bonus_active_entries: [bonus_runtime.bonus_pool_size]BonusActiveEntry = undefined;
    var bonus_active_entries_len: usize = 0;
    for (bonuses.entries) |entry| {
        if (entry.bonus_id == .unused) continue;
        bonus_active_count += 1;
        addBonusActiveEntry(
            &bonus_active_entries,
            &bonus_active_entries_len,
            .{
                .bonus_id = @intFromEnum(entry.bonus_id),
                .amount = entry.amount,
            },
        );
    }

    var player_perk_counts: [perk_count_size]i32 = undefined;
    for (0..perk_count_size) |idx| {
        const perk_id: PerkId = @enumFromInt(@as(i32, @intCast(idx)));
        player_perk_counts[idx] = player.perk_counts.get(perk_id);
    }

    var bonus_timer_ms_by_id = [_]i32{0} ** bonus_id_count;
    bonus_timer_ms_by_id[@intFromEnum(game_ids.BonusId.weapon_power_up)] = bonusTimerMs(state.bonuses.weapon_power_up);
    bonus_timer_ms_by_id[@intFromEnum(game_ids.BonusId.reflex_boost)] = bonusTimerMs(state.bonuses.reflex_boost);
    bonus_timer_ms_by_id[@intFromEnum(game_ids.BonusId.energizer)] = bonusTimerMs(state.bonuses.energizer);
    bonus_timer_ms_by_id[@intFromEnum(game_ids.BonusId.double_experience)] = bonusTimerMs(state.bonuses.double_experience);
    bonus_timer_ms_by_id[@intFromEnum(game_ids.BonusId.freeze)] = bonusTimerMs(state.bonuses.freeze);

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
            .perk_pending = state.perk_selection.pending_count,
        },
        .player = .{
            .player_weapon_id = @intFromEnum(player.weapon.weapon_id),
            .player_ammo_bits = f32Bits(player.weapon.ammo),
            .player_health_bits = f32Bits(player.health),
            .player_pos_x_bits = f32Bits(player.pos.x),
            .player_pos_y_bits = f32Bits(player.pos.y),
            .player_aim_x_bits = f32Bits(player.aim.x),
            .player_aim_y_bits = f32Bits(player.aim.y),
            .player_heading_bits = f32Bits(player.heading),
            .player_aim_heading_bits = f32Bits(player.aim_heading),
            .player_move_speed_bits = f32Bits(player.move_speed),
            .player_turn_speed_bits = f32Bits(player.turn_speed),
            .player_level = player.level,
            .player_experience = player.experience,
            .player_reload_active = player.weapon.reload_active,
            .player_reload_timer_bits = f32Bits(player.weapon.reload_timer),
            .player_shot_cooldown_bits = f32Bits(player.weapon.shot_cooldown),
            .player_shot_seq = player.shot_seq,
            .player_perk_counts = player_perk_counts,
            .player_hot_tempered_timer_bits = f32Bits(player.hot_tempered_timer),
            .player_shield_timer_bits = f32Bits(player.shield_timer),
            .player_man_bomb_timer_bits = f32Bits(player.man_bomb_timer),
            .player_fire_cough_timer_bits = f32Bits(player.fire_cough_timer),
            .player_living_fortress_timer_bits = f32Bits(player.living_fortress_timer),
            .perk_interval_hot_tempered_bits = f32Bits(state.perk_interval_hot_tempered),
            .perk_interval_man_bomb_bits = f32Bits(state.perk_interval_man_bomb),
            .perk_interval_fire_cough_bits = f32Bits(state.perk_interval_fire_cough),
        },
        .bonuses = .{
            .bonus_timer_ms_by_id = bonus_timer_ms_by_id,
            .bonus_active_count = bonus_active_count,
            .active_entries_len = bonus_active_entries_len,
            .active_entries = bonus_active_entries,
        },
        .projectiles = .{
            .projectile_count = projectile_count,
            .projectile_hit_count = projectile_tick_stats.hit_count,
            .projectile_first_hit_creature_index = projectile_tick_stats.first_hit_creature_index,
            .projectile_first_hit_projectile_index = projectile_tick_stats.first_hit_projectile_index,
            .projectile_first_hit_type_id = projectile_tick_stats.first_hit_type_id,
            .projectile_first_hit_origin_x_bits = f32Bits(projectile_tick_stats.first_hit_origin.x),
            .projectile_first_hit_origin_y_bits = f32Bits(projectile_tick_stats.first_hit_origin.y),
            .projectile_first_hit_pos_x_bits = f32Bits(projectile_tick_stats.first_hit_pos.x),
            .projectile_first_hit_pos_y_bits = f32Bits(projectile_tick_stats.first_hit_pos.y),
            .projectile_first_hit_target_size_bits = f32Bits(narrowF32(projectile_tick_stats.first_hit_target_size)),
            .projectile_first_hit_target_x_bits = f32Bits(narrowF32(projectile_tick_stats.first_hit_target_x)),
            .projectile_first_hit_target_y_bits = f32Bits(narrowF32(projectile_tick_stats.first_hit_target_y)),
            .projectile_type_counts_len = projectile_type_counts_len,
            .projectile_type_counts = projectile_type_counts,
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

fn addProjectileTypeCount(
    entries: *[projectiles_mod.main_projectile_pool_size]ProjectileTypeCountEntry,
    len: *usize,
    type_id: i32,
) void {
    var idx: usize = 0;
    while (idx < len.* and entries[idx].type_id < type_id) : (idx += 1) {}
    if (idx < len.* and entries[idx].type_id == type_id) {
        entries[idx].count += 1;
        return;
    }

    var move_idx = len.*;
    while (move_idx > idx) : (move_idx -= 1) {
        entries[move_idx] = entries[move_idx - 1];
    }
    entries[idx] = .{
        .type_id = type_id,
        .count = 1,
    };
    len.* += 1;
}

fn addBonusActiveEntry(
    entries: *[bonus_runtime.bonus_pool_size]BonusActiveEntry,
    len: *usize,
    entry: BonusActiveEntry,
) void {
    var idx: usize = 0;
    while (idx < len.* and entries[idx].bonus_id < entry.bonus_id) : (idx += 1) {}

    var move_idx = len.*;
    while (move_idx > idx) : (move_idx -= 1) {
        entries[move_idx] = entries[move_idx - 1];
    }
    entries[idx] = entry;
    len.* += 1;
}

fn f32Bits(value: f32) u32 {
    return @bitCast(value);
}

fn bonusTimerMs(seconds: f32) i32 {
    if (!(seconds > 0.0)) return 0;
    const ms = @round(seconds * 1000.0);
    if (ms <= 0.0) return 0;
    if (ms >= @as(f32, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(ms);
}
