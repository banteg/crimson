const std = @import("std");
const game_ids = @import("../../game_ids.zig");
const native_math = @import("../native_math.zig");

const bonus_runtime = @import("../bonuses.zig");
const creature_lifecycle = @import("../lifecycle.zig").CreatureLifecycle;
const creatures_mod = @import("../creatures.zig");
const owner_ref = @import("../owner_ref.zig");
const perks = @import("../perks.zig");
const particles_mod = @import("../particles.zig");
const projectiles_mod = @import("../projectiles.zig");
const spawn_mod = @import("../spawn.zig");
const state_mod = @import("../state.zig");
const weapon_data = @import("../weapon_data.zig");

const narrowF32 = native_math.roundF32;
const native_half_pi: f32 = native_math.native_half_pi;
const PerkId = perks.PerkId;

pub fn applyPendingBonusEffects(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    bonuses: *bonus_runtime.BonusPool,
    dt: f32,
    world_size: f32,
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

pub fn applyPendingCreatureProjectiles(
    state: *state_mod.GameplayState,
    projectiles: *projectiles_mod.ProjectilePool,
) void {
    if (state.pending_creature_projectile_count <= 0) {
        state.pending_creature_projectile_count = 0;
        return;
    }

    const pending_count_i32 = @min(
        state.pending_creature_projectile_count,
        @as(i32, @intCast(state.pending_creature_projectiles.len)),
    );

    var idx_i32: i32 = 0;
    while (idx_i32 < pending_count_i32) : (idx_i32 += 1) {
        const idx: usize = @intCast(idx_i32);
        const pending = state.pending_creature_projectiles[idx];
        const type_id = pending.type_id;
        if (type_id <= 0) continue;
        const angle = pending.angle;
        const pos = pending.pos;
        const owner = pending.owner;
        const meta = projectileTravelBudgetFromRawId(type_id);
        _ = projectiles.spawn(pos, narrowF32(angle), type_id, owner, meta, true);
    }
    state.pending_creature_projectile_count = 0;
}

pub fn applyFireblastBonus(
    state: *state_mod.GameplayState,
    projectiles: *projectiles_mod.ProjectilePool,
    origin: state_mod.Vec2,
) void {
    const projectile_owner = owner_ref.OwnerRef.fromLocalPlayer(0);
    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    const count: usize = 16;
    const step = std.math.tau / @as(f32, @floatFromInt(count));
    for (0..count) |idx| {
        const angle = @as(f32, @floatFromInt(idx)) * step;
        const type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle);
        const meta = projectileTravelBudgetFromRawId(type_id);
        _ = projectiles.spawn(origin, narrowF32(angle), type_id, projectile_owner, meta, false);
    }
}

pub fn applyShockChainBonus(
    state: *state_mod.GameplayState,
    projectiles: *projectiles_mod.ProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    origin: state_mod.Vec2,
) void {
    if (creatures.entries.len == 0) return;

    var best_idx: ?usize = null;
    var best_dist_sq: f32 = 1e12;
    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        if (!creature_lifecycle.isAlive(creature.lifecycle_stage)) continue;
        const d_sq = distanceSq(origin, creature.pos);
        if (d_sq < best_dist_sq) {
            best_dist_sq = d_sq;
            best_idx = idx;
        }
    }
    const target_idx = best_idx orelse return;

    const target = creatures.entries[target_idx];
    const angle = state_mod.Vec2.sub(target.pos, origin).toHeading();
    const projectile_owner = owner_ref.OwnerRef.fromLocalPlayer(0);
    const type_id = @intFromEnum(game_ids.ProjectileTypeId.ion_rifle);
    const meta = projectileTravelBudgetFromRawId(type_id);

    const prev_spawn_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_spawn_guard;

    state.shock_chain_links_left = 0x20;
    const proj_idx = projectiles.spawn(origin, narrowF32(angle), type_id, projectile_owner, meta, false);
    state.shock_chain_projectile_id = @intCast(proj_idx);
}

fn distanceSq(a: state_mod.Vec2, b: state_mod.Vec2) f32 {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    return dx * dx + dy * dy;
}

fn projectileTravelBudgetFromRawId(raw_id: i32) f32 {
    const weapon_id = weapon_data.weaponIdFromInt(raw_id);
    return weapon_data.weapon_stats.get(weapon_id).travel_budget;
}

pub fn updateEvilEyesTargets(
    _: *const state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: []const creatures_mod.CreatureState,
) void {
    if (players.len == 0) return;
    for (players) |*player| {
        if (player.health <= 0.0 or !perks.perkActive(player, PerkId.evil_eyes)) {
            player.evil_eyes_target_creature = -1;
            continue;
        }
        player.evil_eyes_target_creature = perks.creatureFindInRadius(creatures, player.aim, 12.0, 0);
    }
}

pub fn applyNukeBonus(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    projectiles: *projectiles_mod.ProjectilePool,
    creatures: *creatures_mod.CreaturePool,
    bonuses: *bonus_runtime.BonusPool,
    origin: state_mod.Vec2,
    dt: f32,
    world_size: f32,
    tick_index: usize,
) void {
    if (players.len == 0) return;
    const player = &players[0];
    const projectile_owner = owner_ref.OwnerRef.fromLocalPlayer(0);
    const damage_owner = owner_ref.OwnerRef.fromPlayer(@intCast(player.index));
    var nuke_kill_count: i32 = 0;
    state.camera_shake_pulses = 0x14;
    state.camera_shake_timer = 0.2;

    var bullet_count: i32 = @intCast(state.rng.rand() & 3);
    bullet_count += 4;
    var bullet_idx: i32 = 0;
    while (bullet_idx < bullet_count) : (bullet_idx += 1) {
        const angle = @as(f32, @floatFromInt(state.rng.rand() % 0x274)) * 0.01;
        var type_id = @intFromEnum(game_ids.ProjectileTypeId.pistol);
        applyPlayerProjectileSpawnRules(state, players, projectile_owner, &type_id);
        const meta = projectileTravelBudgetFromRawId(type_id);
        const proj_idx = projectiles.spawn(origin, narrowF32(angle), type_id, projectile_owner, meta, false);
        const speed_scale = @as(f32, @floatFromInt(state.rng.rand() % 0x32)) * 0.01 + 0.5;
        projectiles.entries[proj_idx].speed_scale *= narrowF32(speed_scale);
    }

    for (0..2) |_| {
        const angle = @as(f32, @floatFromInt(state.rng.rand() % 0x274)) * 0.01;
        var type_id = @intFromEnum(game_ids.ProjectileTypeId.gauss_gun);
        applyPlayerProjectileSpawnRules(state, players, projectile_owner, &type_id);
        const meta = projectileTravelBudgetFromRawId(type_id);
        _ = projectiles.spawn(origin, narrowF32(angle), type_id, projectile_owner, meta, false);
    }

    perks.consumeExplosionBurstRng(state, 5);

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
            damage_owner,
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

fn applyPlayerProjectileSpawnRules(
    state: *state_mod.GameplayState,
    players: []const state_mod.PlayerState,
    owner: owner_ref.OwnerRef,
    type_id: *i32,
) void {
    if (state.bonus_spawn_guard) return;
    const player_ref = switch (owner) {
        .player => |ref| ref,
        else => return,
    };
    const player_index: ?usize = if (player_ref.local_host and player_ref.index == 0)
        if (players.len == 1) @as(?usize, 0) else null
    else if (player_ref.index < players.len)
        player_ref.index
    else
        null;

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

pub fn consumeSpawnBurstRng(
    state: *state_mod.GameplayState,
    count: usize,
) void {
    for (0..count) |_| {
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
    }
}

pub fn applyFreezePickupCorpseCleanupRng(
    state: *state_mod.GameplayState,
    creatures: *creatures_mod.CreaturePool,
    freeze_corpse_at_tick_start: []const bool,
) void {
    for (&creatures.entries, 0..) |*creature, idx| {
        if (!creature.active) continue;
        if (creature.hp > 0.0) continue;

        if (creature_lifecycle.isDespawned(creature.lifecycle_stage)) {
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

test "shock chain bonus no-ops when no alive target exists" {
    var state = state_mod.GameplayState.init(0x1234);
    var projectiles = projectiles_mod.ProjectilePool{};
    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[0].active = true;
    creatures.entries[0].lifecycle_stage = 0.0;

    applyShockChainBonus(
        &state,
        &projectiles,
        &creatures,
        .{ .x = 512.0, .y = 512.0 },
    );

    try std.testing.expectEqual(@as(i32, 0), state.shock_chain_links_left);
    try std.testing.expectEqual(@as(i32, -1), state.shock_chain_projectile_id);
    try std.testing.expect(!projectiles.entries[0].active);
}

test "evil eyes targeting defaults to alive player slot" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 0.0 },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[1].perk_counts.set(PerkId.evil_eyes, 1);

    var creatures = [_]creatures_mod.CreatureState{
        .{
            .active = true,
            .pos = .{ .x = 100.0, .y = 200.0 },
            .lifecycle_stage = creature_lifecycle.alive,
            .size = 50.0,
            .hp = 100.0,
        },
    };

    updateEvilEyesTargets(&state, players[0..], creatures[0..]);
    try std.testing.expectEqual(@as(i32, -1), players[0].evil_eyes_target_creature);
    try std.testing.expectEqual(@as(i32, 0), players[1].evil_eyes_target_creature);
}

test "evil eyes targeting assigns each alive owner" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
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
    players[0].perk_counts.set(PerkId.evil_eyes, 1);
    players[1].perk_counts.set(PerkId.evil_eyes, 1);

    var creatures = [_]creatures_mod.CreatureState{
        .{
            .active = true,
            .pos = .{ .x = 100.0, .y = 200.0 },
            .lifecycle_stage = creature_lifecycle.alive,
            .size = 50.0,
            .hp = 100.0,
        },
        .{
            .active = true,
            .pos = .{ .x = 140.0, .y = 200.0 },
            .lifecycle_stage = creature_lifecycle.alive,
            .size = 50.0,
            .hp = 100.0,
        },
    };

    updateEvilEyesTargets(&state, players[0..], creatures[0..]);
    try std.testing.expectEqual(@as(i32, 0), players[0].evil_eyes_target_creature);
    try std.testing.expectEqual(@as(i32, 1), players[1].evil_eyes_target_creature);
}

fn activeParticleCount(particles: *const particles_mod.ParticlePool) usize {
    var count: usize = 0;
    for (particles.entries) |entry| {
        if (entry.active) count += 1;
    }
    return count;
}

test "pyrokinetic spawns particle burst when collision timer wraps" {
    var state = state_mod.GameplayState.init(0);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[0].perk_counts.set(PerkId.pyrokinetic, 1);

    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = creature_lifecycle.alive,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };

    var particles = particles_mod.ParticlePool{};

    perks.applyPyrokineticEffects(&state, players[0..], &creatures, &particles, 0.2);
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 5), activeParticleCount(&particles));

    const expected_intensities = [_]f32{ 0.8, 0.6, 0.4, 0.3, 0.2 };
    for (expected_intensities, 0..) |expected, idx| {
        try std.testing.expectApproxEqAbs(expected, particles.entries[idx].intensity, 1e-6);
    }
}

test "pyrokinetic uses f32 timer threshold before wrapping" {
    var state = state_mod.GameplayState.init(0);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[0].perk_counts.set(PerkId.pyrokinetic, 1);

    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = creature_lifecycle.alive,
        .collision_timer = 0.034000009298324585,
        .size = 50.0,
        .hp = 100.0,
    };

    var particles = particles_mod.ParticlePool{};

    perks.applyPyrokineticEffects(
        &state,
        players[0..],
        &creatures,
        &particles,
        0.03400000184774399,
    );
    try std.testing.expect(creatures.entries[0].collision_timer > 0.0);
    try std.testing.expect(creatures.entries[0].collision_timer < 1e-6);
    try std.testing.expectEqual(@as(usize, 0), activeParticleCount(&particles));

    perks.applyPyrokineticEffects(
        &state,
        players[0..],
        &creatures,
        &particles,
        0.03200000151991844,
    );
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 5), activeParticleCount(&particles));
}

test "pyrokinetic defaults to first alive player slot" {
    var state = state_mod.GameplayState.init(0);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 0.0 },
        .{
            .index = 1,
            .pos = .{},
            .health = 100.0,
            .aim = .{ .x = 100.0, .y = 200.0 },
        },
    };
    players[1].perk_counts.set(PerkId.pyrokinetic, 1);

    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = creature_lifecycle.alive,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };
    var particles = particles_mod.ParticlePool{};

    perks.applyPyrokineticEffects(&state, players[0..], &creatures, &particles, 0.2);
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 5), activeParticleCount(&particles));
}

test "pyrokinetic targets all alive owners in default mode" {
    var state = state_mod.GameplayState.init(0);
    var players = [_]state_mod.PlayerState{
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
    players[0].perk_counts.set(PerkId.pyrokinetic, 1);
    players[1].perk_counts.set(PerkId.pyrokinetic, 1);

    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[0] = .{
        .active = true,
        .pos = .{ .x = 100.0, .y = 200.0 },
        .lifecycle_stage = creature_lifecycle.alive,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };
    creatures.entries[1] = .{
        .active = true,
        .pos = .{ .x = 140.0, .y = 200.0 },
        .lifecycle_stage = creature_lifecycle.alive,
        .collision_timer = 0.1,
        .size = 50.0,
        .hp = 100.0,
    };
    var particles = particles_mod.ParticlePool{};

    perks.applyPyrokineticEffects(&state, players[0..], &creatures, &particles, 0.2);
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), creatures.entries[0].collision_timer, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), creatures.entries[1].collision_timer, 1e-6);
    try std.testing.expectEqual(@as(usize, 10), activeParticleCount(&particles));
}

test "pending fireblast spawns sixteen plasma rifle projectiles" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var projectiles = projectiles_mod.ProjectilePool{};
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

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
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 512.0, .y = 512.0 },
            .fire_bullets_timer = 1.0,
        },
    };
    var projectiles = projectiles_mod.ProjectilePool{};
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

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
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var projectiles = projectiles_mod.ProjectilePool{};
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

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
    try std.testing.expectApproxEqAbs(@as(f32, 10.0), creatures.entries[1].hp, 1e-6);
    try std.testing.expectEqual(@as(i32, 0), state.pending_nuke_count);
}

test "poison bullets does not trigger on pending nuke radius damage" {
    var state = state_mod.GameplayState.init(1);
    state.rng.state = 1; // Mirrors poison-hit seed but nuke path must not set poison flags.
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    players[0].perk_counts.set(PerkId.poison_bullets, 1);
    var projectiles = projectiles_mod.ProjectilePool{};
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 612.0, .y = 512.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = spawn_mod.CreatureFlags.anim_ping_pong,
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

    try std.testing.expect((creatures.entries[0].flags & spawn_mod.CreatureFlags.self_damage_tick) == 0);
}

test "pending nuke spawns pistol and gauss projectiles with native meta ranges" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{ .x = 512.0, .y = 512.0 } },
    };
    var projectiles = projectiles_mod.ProjectilePool{};
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

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
            try std.testing.expectApproxEqAbs(@as(f32, 55.0), entry.travel_budget, 1e-6);
            try std.testing.expect(entry.speed_scale >= 0.5);
            try std.testing.expect(entry.speed_scale < 1.0);
        } else if (entry.type_id == @intFromEnum(game_ids.ProjectileTypeId.gauss_gun)) {
            gauss_count += 1;
            try std.testing.expectApproxEqAbs(@as(f32, 215.0), entry.travel_budget, 1e-6);
            try std.testing.expectApproxEqAbs(@as(f32, 1.0), entry.speed_scale, 1e-6);
        }
    }

    try std.testing.expect(pistol_count >= 4);
    try std.testing.expect(pistol_count <= 7);
    try std.testing.expectEqual(@as(i32, 2), gauss_count);
}

test "pending creature projectile queue materializes hostile shots before projectile step" {
    var state = state_mod.GameplayState.init(1);
    var projectiles = projectiles_mod.ProjectilePool{};

    state.pending_creature_projectile_count = 1;
    state.pending_creature_projectiles[0] = .{
        .type_id = @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle),
        .owner = owner_ref.OwnerRef.fromCreature(17),
        .angle = native_half_pi,
        .pos = .{ .x = 100.0, .y = 200.0 },
    };

    applyPendingCreatureProjectiles(&state, &projectiles);

    try std.testing.expectEqual(@as(i32, 0), state.pending_creature_projectile_count);
    try std.testing.expect(projectiles.entries[0].active);
    try std.testing.expect(projectiles.entries[0].hits_players);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.plasma_rifle), projectiles.entries[0].type_id);
    try std.testing.expectEqual(@as(i32, 17), projectiles.entries[0].owner.toLegacy());
    try std.testing.expectApproxEqAbs(@as(f32, 100.0), projectiles.entries[0].pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 200.0), projectiles.entries[0].pos.y, 1e-6);
}

fn findSeedForRandModSequence(
    moduli: []const u32,
    targets: []const u32,
    max_seed: u32,
) ?u32 {
    if (moduli.len == 0 or moduli.len != targets.len) return null;

    var seed: u32 = 0;
    while (seed < max_seed) : (seed += 1) {
        var rng = spawn_mod.Crand.init(seed);
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

    var state = state_mod.GameplayState.init(seed);
    state.jinxed_timer = 0.0;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 50.0,
            .experience = 100,
        },
    };
    players[0].perk_counts.set(PerkId.jinxed, 1);
    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[2].active = true;
    creatures.entries[2].hp = 100.0;
    creatures.entries[2].lifecycle_stage = creature_lifecycle.alive;
    creatures.entries[2].reward_value = 12.7;

    perks.applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f32, 1.8), state.jinxed_timer, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, -1.0), creatures.entries[2].hp, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 12.0), creatures.entries[2].lifecycle_stage, 1e-6);
    try std.testing.expectEqual(@as(i32, 112), players[0].experience);
}

test "jinxed reward uses float32 sum before truncation" {
    const seed = findSeedForRandModSequence(
        &.{ 10, 0x14, 0x180 },
        &.{ 0, 0, 2 },
        500_000,
    ) orelse unreachable;
    const dt = 0.2;

    var state = state_mod.GameplayState.init(seed);
    state.jinxed_timer = 0.0;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 50.0,
            .experience = 139_451,
        },
    };
    players[0].perk_counts.set(PerkId.jinxed, 1);
    var creatures = creatures_mod.CreaturePool{};
    creatures.entries[2].active = true;
    creatures.entries[2].hp = 100.0;
    creatures.entries[2].lifecycle_stage = creature_lifecycle.alive;
    creatures.entries[2].reward_value = 97.99636190476191;

    perks.applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectEqual(@as(i32, 139_549), players[0].experience);
}

test "jinxed accident can target another alive player" {
    const seed = findSeedForRandModSequence(
        &.{ 10, 2, 0x14 },
        &.{ 3, 1, 0 },
        500_000,
    ) orelse unreachable;
    const dt = 0.2;

    var state = state_mod.GameplayState.init(seed);
    state.jinxed_timer = 0.0;
    state.bonuses.freeze = 1.0;
    var players = [_]state_mod.PlayerState{
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
    players[0].perk_counts.set(PerkId.jinxed, 1);
    var creatures = creatures_mod.CreaturePool{};

    perks.applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f32, 1.8), state.jinxed_timer, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 50.0), players[0].health, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 65.0), players[1].health, 1e-6);
}

test "jinxed timer uses f32 underflow threshold before proc" {
    const dt = 0.03400000184774399;
    var state = state_mod.GameplayState.init(7);
    state.jinxed_timer = 0.034000836312770844;
    const rng_before = state.rng.state;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 10.0, .y = 20.0 },
            .health = 50.0,
        },
    };
    players[0].perk_counts.set(PerkId.jinxed, 1);
    var creatures = creatures_mod.CreaturePool{};

    perks.applyJinxedEffects(&state, players[0..], &creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f32, 8.344650268554688e-07), state.jinxed_timer, 1e-12);
    try std.testing.expectApproxEqAbs(@as(f32, 50.0), players[0].health, 1e-6);
    try std.testing.expectEqual(rng_before, state.rng.state);
}

test "jinxed pool uses full 384-slot upper bound" {
    const seed = findSeedForRandModSequence(
        &.{ 10, 0x14, 0x180 },
        &.{ 0, 0, 0x17F },
        1_000_000,
    ) orelse unreachable;
    const dt = 0.2;

    var default_state = state_mod.GameplayState.init(seed);
    default_state.jinxed_timer = 0.0;
    var default_players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{},
            .health = 50.0,
            .experience = 100,
        },
    };
    default_players[0].perk_counts.set(PerkId.jinxed, 1);
    var default_creatures = creatures_mod.CreaturePool{};
    default_creatures.entries[0x17F].active = true;
    default_creatures.entries[0x17F].hp = 100.0;
    default_creatures.entries[0x17F].lifecycle_stage = creature_lifecycle.alive;
    default_creatures.entries[0x17F].reward_value = 12.7;

    perks.applyJinxedEffects(&default_state, default_players[0..], &default_creatures, dt);

    try std.testing.expectApproxEqAbs(@as(f32, -1.0), default_creatures.entries[0x17F].hp, 1e-6);
    try std.testing.expectEqual(@as(i32, 112), default_players[0].experience);
}

test "final revenge explosion applies radial damage on death transition" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = -0.5,
        },
    };
    players[0].perk_counts.set(PerkId.final_revenge, 1);
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

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

    perks.applyFinalRevengeOnDeathTransition(
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

    try std.testing.expectApproxEqAbs(@as(f32, 7440.0), creatures.entries[0].hp, 1e-6);
}

test "final revenge aoe includes active non-positive hp entries" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
            .health = -1.0,
        },
    };
    players[0].perk_counts.set(PerkId.final_revenge, 1);
    var creatures = creatures_mod.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

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
    creatures.entries[0].lifecycle_stage = creature_lifecycle.alive;

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

    perks.applyFinalRevengeOnDeathTransition(
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

    try std.testing.expectApproxEqAbs(@as(f32, 14.5), creatures.entries[0].lifecycle_stage, 1e-6);
    try std.testing.expect(creatures.entries[1].hp < 10.0);
    try std.testing.expectApproxEqAbs(@as(f32, 10.0), creatures.entries[2].hp, 1e-6);
}
