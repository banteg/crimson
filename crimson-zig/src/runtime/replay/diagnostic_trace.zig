const std = @import("std");

const bonuses_mod = @import("../bonuses.zig");
const creatures_mod = @import("../creatures.zig");
const owner_ref = @import("../owner_ref.zig");
const projectiles_mod = @import("../projectiles.zig");
const secondary_projectiles_mod = @import("../secondary_projectiles.zig");
const state_mod = @import("../state.zig");

pub const ReplayTickTiming = struct {
    elapsed_ms: i64,
};

pub const ReplayTickRngDraw = struct {
    tick_call_index: i32,
    value_15: i32,
    state_before_u32: u32,
    state_after_u32: u32,
    caller: ?u32 = null,
};

pub const ReplayTickTimingSample = struct {
    tick_index: i32,
    gameplay_frame: ?i32 = null,
    phase: []const u8,
    write_kind: []const u8 = "snapshot",
    frame_dt_f32: ?f32 = null,
    frame_dt_ms_i32: ?i32 = null,
    frame_dt_ms_f32: ?f32 = null,
    time_scale_active_entry: ?bool = null,
    time_scale_active_current: ?bool = null,
    time_scale_factor: ?f32 = null,
    bonus_reflex_boost_timer: ?f32 = null,
    mode_fn: ?[]const u8 = null,
    player_index: ?i32 = null,
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
    score_xp: i32,
    kills: i32,
    shots_fired_p0: i32,
    creature_count: usize,
    perk_pending: i32,
};

pub const ReplayTickCreatureSample = struct {
    index: usize,
    type_id: i32,
    hp: f32,
    pos: state_mod.Vec2,
    flags: u32,
    ai_mode: i32,
    link_index: i32,
    heading: f32,
    target_heading: f32,
    orbit_angle: f32,
    orbit_radius: f32,
    lifecycle_stage: f32,
};

pub const ReplayTickProjectileSample = struct {
    index: usize,
    type_id: i32,
    angle: f32,
    pos: state_mod.Vec2,
    vel: state_mod.Vec2,
    life_timer: f32,
    speed_scale: f32,
    damage_pool: f32,
    hit_radius: f32,
    travel_budget: f32,
    owner_id: i32,
};

pub const ReplayTickSecondaryProjectileSample = struct {
    index: usize,
    type_id: i32,
    angle: f32,
    pos: state_mod.Vec2,
    vel: state_mod.Vec2,
    speed: f32,
    trail_timer: f32,
    owner_id: i32,
    target_id: i32,
};

pub const ReplayTickBonusSample = struct {
    index: usize,
    bonus_id: i32,
    picked: bool,
    time_left: f32,
    time_max: f32,
    pos: state_mod.Vec2,
    amount: i32,
};

pub const ReplayTickEntitySamples = struct {
    creatures: []const ReplayTickCreatureSample = &.{},
    projectiles: []const ReplayTickProjectileSample = &.{},
    secondary_projectiles: []const ReplayTickSecondaryProjectileSample = &.{},
    bonuses: []const ReplayTickBonusSample = &.{},
};

pub const ReplayTickTrace = struct {
    tick_index: usize,
    timing: ReplayTickTiming,
    rng: ReplayTickRng,
    summary: ReplayTickSummary,
    gameplay_state: state_mod.GameplayState,
    player_state: state_mod.PlayerState,
    rng_rows: []const ReplayTickRngDraw = &.{},
    timing_samples: []const ReplayTickTimingSample = &.{},
    entities: ReplayTickEntitySamples = .{},
};

pub fn buildReplayTickTrace(
    tick_index: usize,
    elapsed_ms_sim: f32,
    state: *const state_mod.GameplayState,
    player: state_mod.PlayerState,
    creatures: *const creatures_mod.CreaturePool,
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
    rng_rows: []const ReplayTickRngDraw,
    timing_samples: []const ReplayTickTimingSample,
) ReplayTickTrace {
    return .{
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
            .score_xp = player.experience,
            .kills = creatures.kill_count,
            .shots_fired_p0 = if (state.shots_fired.len > 0) state.shots_fired[0] else 0,
            .creature_count = creatures.activeCount(),
            .perk_pending = state.perk_selection.pending_count,
        },
        .gameplay_state = state.*,
        .player_state = player,
        .rng_rows = rng_rows,
        .timing_samples = timing_samples,
    };
}

pub fn buildReplayTickTraceWithEntities(
    allocator: std.mem.Allocator,
    tick_index: usize,
    elapsed_ms_sim: f32,
    state: *const state_mod.GameplayState,
    player: state_mod.PlayerState,
    creatures: *const creatures_mod.CreaturePool,
    projectiles: *const projectiles_mod.ProjectilePool,
    secondary_projectiles: *const secondary_projectiles_mod.SecondaryProjectilePool,
    bonuses: *const bonuses_mod.BonusPool,
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
    rng_rows: []const ReplayTickRngDraw,
    timing_samples: []const ReplayTickTimingSample,
) !ReplayTickTrace {
    const entities: ReplayTickEntitySamples = .{
        .creatures = try collectCreatureSamples(allocator, creatures),
        .projectiles = try collectProjectileSamples(allocator, projectiles),
        .secondary_projectiles = try collectSecondaryProjectileSamples(allocator, secondary_projectiles),
        .bonuses = try collectBonusSamples(allocator, bonuses),
    };
    errdefer {
        if (entities.creatures.len > 0) allocator.free(entities.creatures);
        if (entities.projectiles.len > 0) allocator.free(entities.projectiles);
        if (entities.secondary_projectiles.len > 0) allocator.free(entities.secondary_projectiles);
        if (entities.bonuses.len > 0) allocator.free(entities.bonuses);
    }

    var row = buildReplayTickTrace(
        tick_index,
        elapsed_ms_sim,
        state,
        player,
        creatures,
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
        rng_rows,
        timing_samples,
    );
    row.entities = entities;
    return row;
}

pub fn deinitReplayTickTrace(allocator: std.mem.Allocator, trace: *ReplayTickTrace) void {
    if (trace.rng_rows.len > 0) allocator.free(trace.rng_rows);
    if (trace.timing_samples.len > 0) allocator.free(trace.timing_samples);
    if (trace.entities.creatures.len > 0) allocator.free(trace.entities.creatures);
    if (trace.entities.projectiles.len > 0) allocator.free(trace.entities.projectiles);
    if (trace.entities.secondary_projectiles.len > 0) allocator.free(trace.entities.secondary_projectiles);
    if (trace.entities.bonuses.len > 0) allocator.free(trace.entities.bonuses);
    trace.rng_rows = &.{};
    trace.timing_samples = &.{};
    trace.entities = .{};
}

pub fn deinitReplayTickTraceSlice(allocator: std.mem.Allocator, trace: []ReplayTickTrace) void {
    for (trace) |*row| {
        deinitReplayTickTrace(allocator, row);
    }
}

fn collectCreatureSamples(
    allocator: std.mem.Allocator,
    creatures: *const creatures_mod.CreaturePool,
) ![]const ReplayTickCreatureSample {
    var rows: std.ArrayList(ReplayTickCreatureSample) = .empty;
    defer rows.deinit(allocator);
    for (creatures.entries, 0..) |creature, index| {
        if (!creature.active) continue;
        try rows.append(allocator, .{
            .index = index,
            .type_id = creature.type_id,
            .hp = creature.hp,
            .pos = creature.pos,
            .flags = creature.flags,
            .ai_mode = @intFromEnum(creature.ai_mode),
            .link_index = creature.link_index,
            .heading = creature.heading,
            .target_heading = creature.target_heading,
            .orbit_angle = creature.orbit_angle,
            .orbit_radius = creature.orbit_radius,
            .lifecycle_stage = creature.lifecycle_stage,
        });
    }
    return rows.toOwnedSlice(allocator);
}

fn collectProjectileSamples(
    allocator: std.mem.Allocator,
    projectiles: *const projectiles_mod.ProjectilePool,
) ![]const ReplayTickProjectileSample {
    var rows: std.ArrayList(ReplayTickProjectileSample) = .empty;
    defer rows.deinit(allocator);
    for (projectiles.entries, 0..) |projectile, index| {
        if (!projectile.active) continue;
        try rows.append(allocator, .{
            .index = index,
            .type_id = projectile.type_id,
            .angle = projectile.angle,
            .pos = projectile.pos,
            .vel = projectile.vel,
            .life_timer = projectile.life_timer,
            .speed_scale = projectile.speed_scale,
            .damage_pool = projectile.damage_pool,
            .hit_radius = projectile.hit_radius,
            .travel_budget = projectile.travel_budget,
            .owner_id = owner_ref.OwnerRef.toLegacy(projectile.owner),
        });
    }
    return rows.toOwnedSlice(allocator);
}

fn collectSecondaryProjectileSamples(
    allocator: std.mem.Allocator,
    secondary_projectiles: *const secondary_projectiles_mod.SecondaryProjectilePool,
) ![]const ReplayTickSecondaryProjectileSample {
    var rows: std.ArrayList(ReplayTickSecondaryProjectileSample) = .empty;
    defer rows.deinit(allocator);
    for (secondary_projectiles.entries, 0..) |projectile, index| {
        if (!projectile.active) continue;
        try rows.append(allocator, .{
            .index = index,
            .type_id = @intFromEnum(projectile.type_id),
            .angle = projectile.angle,
            .pos = projectile.pos,
            .vel = projectile.vel,
            .speed = projectile.speed,
            .trail_timer = projectile.trail_timer,
            .owner_id = owner_ref.OwnerRef.toLegacy(projectile.owner),
            .target_id = projectile.target_id,
        });
    }
    return rows.toOwnedSlice(allocator);
}

fn collectBonusSamples(
    allocator: std.mem.Allocator,
    bonuses: *const bonuses_mod.BonusPool,
) ![]const ReplayTickBonusSample {
    var rows: std.ArrayList(ReplayTickBonusSample) = .empty;
    defer rows.deinit(allocator);
    for (bonuses.entries, 0..) |bonus, index| {
        if (bonus.bonus_id == .unused) continue;
        try rows.append(allocator, .{
            .index = index,
            .bonus_id = @intFromEnum(bonus.bonus_id),
            .picked = bonus.picked,
            .time_left = bonus.time_left,
            .time_max = bonus.time_max,
            .pos = bonus.pos,
            .amount = bonus.amount,
        });
    }
    return rows.toOwnedSlice(allocator);
}
