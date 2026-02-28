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

pub const replay_tick_trace_schema_version: i32 = 6;
pub const perk_count_size: usize = state_mod.perk_count_size;
pub const bonus_id_count: usize = @typeInfo(game_ids.BonusId).@"enum".fields.len;
pub const replay_tick_trace_msgpack_magic = "crimson_replay_tick_trace_msgpack_v3\n";

pub const ProjectileTraceEntry = struct {
    index: usize,
    type_id: i32,
    pos_x: f64,
    pos_y: f64,
    origin_x: f64,
    origin_y: f64,
    life_timer: f64,
    damage_pool: f64,
    angle: f64,
    speed_scale: f64,
    owner_legacy: i32,
    hits_players: bool,
};

pub const CreatureTraceEntry = struct {
    index: usize,
    type_id: i32,
    flags: i32,
    ai_mode: i32,
    link_index: i32,
    pos_x: f64,
    pos_y: f64,
    target_x: f64,
    target_y: f64,
    heading: f64,
    target_heading: f64,
    hp: f64,
    lifecycle_stage: f64,
    size: f64,
    attack_cooldown: f64,
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

pub const ReplayTickPlayer = struct {
    player_weapon_id: i32,
    player_ammo: f64,
    player_health: f64,
    player_pos_x: f64,
    player_pos_y: f64,
    player_aim_x: f64,
    player_aim_y: f64,
    player_heading: f64,
    player_aim_heading: f64,
    player_move_speed: f64,
    player_turn_speed: f64,
    player_level: i32,
    player_experience: i32,
    player_reload_active: bool,
    player_reload_timer: f64,
    player_shot_cooldown: f64,
    player_shot_seq: i32,
    player_perk_counts: [perk_count_size]i32,
    player_hot_tempered_timer: f64,
    player_shield_timer: f64,
    player_man_bomb_timer: f64,
    player_fire_cough_timer: f64,
    player_living_fortress_timer: f64,
    perk_interval_hot_tempered: f64,
    perk_interval_man_bomb: f64,
    perk_interval_fire_cough: f64,
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
    projectile_first_hit_origin_x: f64,
    projectile_first_hit_origin_y: f64,
    projectile_first_hit_pos_x: f64,
    projectile_first_hit_pos_y: f64,
    projectile_first_hit_target_size: f64,
    projectile_first_hit_target_x: f64,
    projectile_first_hit_target_y: f64,
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
    schema_version: i32 = replay_tick_trace_schema_version,
    tick: usize = 0,
    tick_index: usize,
    timing: ReplayTickTiming,
    rng: ReplayTickRng,
    summary: ReplayTickSummary,
    gameplay_state: state_mod.GameplayState,
    player_state: state_mod.PlayerState,
    weapon_state: state_mod.WeaponSlotState,
    player: ReplayTickPlayer,
    bonuses: ReplayTickBonuses,
    projectiles: ReplayTickProjectiles,
    creatures: ReplayTickCreatures,
    debug: ReplayTickDebug,
};
const empty_projectile_type_count_entry = ProjectileTypeCountEntry{
    .type_id = 0,
    .count = 0,
};

const empty_projectile_trace_entry = ProjectileTraceEntry{
    .index = 0,
    .type_id = 0,
    .pos_x = 0.0,
    .pos_y = 0.0,
    .origin_x = 0.0,
    .origin_y = 0.0,
    .life_timer = 0.0,
    .damage_pool = 0.0,
    .angle = 0.0,
    .speed_scale = 0.0,
    .owner_legacy = 0,
    .hits_players = false,
};

const empty_creature_trace_entry = CreatureTraceEntry{
    .index = 0,
    .type_id = 0,
    .flags = 0,
    .ai_mode = 0,
    .link_index = -1,
    .pos_x = 0.0,
    .pos_y = 0.0,
    .target_x = 0.0,
    .target_y = 0.0,
    .heading = 0.0,
    .target_heading = 0.0,
    .hp = 0.0,
    .lifecycle_stage = 0.0,
    .size = 0.0,
    .attack_cooldown = 0.0,
};

const empty_bonus_active_entry = BonusActiveEntry{
    .bonus_id = 0,
    .amount = 0,
};

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
    var projectile_type_counts: [projectiles_mod.main_projectile_pool_size]ProjectileTypeCountEntry =
        [_]ProjectileTypeCountEntry{empty_projectile_type_count_entry} ** projectiles_mod.main_projectile_pool_size;
    var projectile_type_counts_len: usize = 0;
    var projectile_entries: [projectiles_mod.main_projectile_pool_size]ProjectileTraceEntry =
        [_]ProjectileTraceEntry{empty_projectile_trace_entry} ** projectiles_mod.main_projectile_pool_size;
    var projectile_entries_len: usize = 0;
    for (projectiles.entries, 0..) |entry, idx| {
        if (!entry.active) continue;

        projectile_count += 1;

        addProjectileTypeCount(&projectile_type_counts, &projectile_type_counts_len, entry.type_id);

        projectile_entries[projectile_entries_len] = .{
            .index = idx,
            .type_id = entry.type_id,
            .pos_x = wireF64(entry.pos.x),
            .pos_y = wireF64(entry.pos.y),
            .origin_x = wireF64(entry.origin.x),
            .origin_y = wireF64(entry.origin.y),
            .life_timer = wireF64(entry.life_timer),
            .damage_pool = wireF64(entry.damage_pool),
            .angle = wireF64(entry.angle),
            .speed_scale = wireF64(entry.speed_scale),
            .owner_legacy = entry.owner.toLegacy(),
            .hits_players = entry.hits_players,
        };
        projectile_entries_len += 1;
    }

    var creature_entries: [creatures_mod.max_creatures]CreatureTraceEntry =
        [_]CreatureTraceEntry{empty_creature_trace_entry} ** creatures_mod.max_creatures;
    var creature_entries_len: usize = 0;
    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;

        creature_entries[creature_entries_len] = .{
            .index = idx,
            .type_id = creature.type_id,
            .flags = @bitCast(creature.flags),
            .ai_mode = @intFromEnum(creature.ai_mode),
            .link_index = creature.link_index,
            .pos_x = wireF64(creature.pos.x),
            .pos_y = wireF64(creature.pos.y),
            .target_x = wireF64(creature.target.x),
            .target_y = wireF64(creature.target.y),
            .heading = wireF64(creature.heading),
            .target_heading = wireF64(creature.target_heading),
            .hp = wireF64(creature.hp),
            .lifecycle_stage = wireF64(creature.lifecycle_stage),
            .size = wireF64(creature.size),
            .attack_cooldown = wireF64(creature.attack_cooldown),
        };
        creature_entries_len += 1;
    }

    var bonus_active_count: usize = 0;
    var bonus_active_entries: [bonus_runtime.bonus_pool_size]BonusActiveEntry =
        [_]BonusActiveEntry{empty_bonus_active_entry} ** bonus_runtime.bonus_pool_size;
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
        .schema_version = replay_tick_trace_schema_version,
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
        .gameplay_state = state.*,
        .player_state = player,
        .weapon_state = player.weapon,
        .player = .{
            .player_weapon_id = @intFromEnum(player.weapon.weapon_id),
            .player_ammo = wireF64(player.weapon.ammo),
            .player_health = wireF64(player.health),
            .player_pos_x = wireF64(player.pos.x),
            .player_pos_y = wireF64(player.pos.y),
            .player_aim_x = wireF64(player.aim.x),
            .player_aim_y = wireF64(player.aim.y),
            .player_heading = wireF64(player.heading),
            .player_aim_heading = wireF64(player.aim_heading),
            .player_move_speed = wireF64(player.move_speed),
            .player_turn_speed = wireF64(player.turn_speed),
            .player_level = player.level,
            .player_experience = player.experience,
            .player_reload_active = player.weapon.reload_active,
            .player_reload_timer = wireF64(player.weapon.reload_timer),
            .player_shot_cooldown = wireF64(player.weapon.shot_cooldown),
            .player_shot_seq = player.shot_seq,
            .player_perk_counts = player_perk_counts,
            .player_hot_tempered_timer = wireF64(player.hot_tempered_timer),
            .player_shield_timer = wireF64(player.shield_timer),
            .player_man_bomb_timer = wireF64(player.man_bomb_timer),
            .player_fire_cough_timer = wireF64(player.fire_cough_timer),
            .player_living_fortress_timer = wireF64(player.living_fortress_timer),
            .perk_interval_hot_tempered = wireF64(state.perk_interval_hot_tempered),
            .perk_interval_man_bomb = wireF64(state.perk_interval_man_bomb),
            .perk_interval_fire_cough = wireF64(state.perk_interval_fire_cough),
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
            .projectile_first_hit_origin_x = wireF64(projectile_tick_stats.first_hit_origin.x),
            .projectile_first_hit_origin_y = wireF64(projectile_tick_stats.first_hit_origin.y),
            .projectile_first_hit_pos_x = wireF64(projectile_tick_stats.first_hit_pos.x),
            .projectile_first_hit_pos_y = wireF64(projectile_tick_stats.first_hit_pos.y),
            .projectile_first_hit_target_size = wireF64(narrowF32(projectile_tick_stats.first_hit_target_size)),
            .projectile_first_hit_target_x = wireF64(narrowF32(projectile_tick_stats.first_hit_target_x)),
            .projectile_first_hit_target_y = wireF64(narrowF32(projectile_tick_stats.first_hit_target_y)),
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

fn wireF64(value: f32) f64 {
    return @as(f64, @floatCast(value));
}

fn bonusTimerMs(seconds: f32) i32 {
    if (!(seconds > 0.0)) return 0;
    const ms = @round(seconds * 1000.0);
    if (ms <= 0.0) return 0;
    if (ms >= @as(f32, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(ms);
}
