const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");

const bonus_runtime = @import("bonuses.zig");
const survival_creatures = @import("creatures.zig");
const perks = @import("perks.zig");
const runtime_helpers = @import("helpers.zig");
const survival_spawn = @import("spawn.zig");
const state_mod = @import("state.zig");
const survival_math = @import("math.zig");

const narrowF32 = native_math.roundF32;
const PerkId = perks.PerkId;
const WeaponId = state_mod.WeaponId;

pub const main_projectile_pool_size: usize = 0x60;
const native_half_pi: f64 = native_math.roundTripF32(native_math.native_half_pi);
const creature_lifecycle_stage_alive: f64 = 16.0;

pub const Projectile = struct {
    active: bool = false,
    angle: f32 = 0.0,
    pos: state_mod.Vec2 = .{},
    origin: state_mod.Vec2 = .{},
    vel: state_mod.Vec2 = .{},
    type_id: i32 = 0,
    life_timer: f32 = 0.0,
    reserved: f32 = 0.0,
    speed_scale: f32 = 1.0,
    damage_pool: f32 = 1.0,
    hit_radius: f32 = 1.0,
    base_damage: f32 = 0.0,
    owner_id: i32 = 0,
    hits_players: bool = false,
};

pub const ProjectileTickStats = struct {
    hit_count: i32 = 0,
    first_hit_creature_index: i32 = -1,
    first_hit_projectile_index: i32 = -1,
    first_hit_type_id: i32 = 0,
    first_hit_origin: state_mod.Vec2 = .{},
    first_hit_pos: state_mod.Vec2 = .{},
    first_hit_target_size: f64 = 0.0,
    first_hit_target_x: f64 = 0.0,
    first_hit_target_y: f64 = 0.0,
};

pub const ProjectilePool = struct {
    entries: [main_projectile_pool_size]Projectile = [_]Projectile{.{}} ** main_projectile_pool_size,

    pub fn reset(self: *ProjectilePool) void {
        self.entries = [_]Projectile{.{}} ** main_projectile_pool_size;
    }

    pub fn spawn(
        self: *ProjectilePool,
        pos: state_mod.Vec2,
        angle: f64,
        type_id: i32,
        owner_id: i32,
        base_damage: f64,
        hits_players: bool,
    ) usize {
        var index: usize = self.entries.len - 1;
        for (self.entries, 0..) |entry, idx| {
            if (!entry.active) {
                index = idx;
                break;
            }
        }

        const meta = if (base_damage > 0.0) base_damage else projectileMetaFromRawId(type_id);
        var entry = &self.entries[index];
        entry.* = .{
            .active = true,
            .angle = narrowF32(angle),
            .pos = .{ .x = pos.x, .y = pos.y },
            .origin = .{ .x = pos.x, .y = pos.y },
            .vel = runtime_helpers.directionFromHeading(narrowF32(angle)).mul(1.5),
            .type_id = type_id,
            .life_timer = 0.4,
            .reserved = 0.0,
            .speed_scale = 1.0,
            .damage_pool = 1.0,
            .hit_radius = 1.0,
            .base_damage = narrowF32(meta),
            .owner_id = owner_id,
            .hits_players = hits_players,
        };

        if (type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_minigun)) {
            entry.hit_radius = 3.0;
            return index;
        }
        if (type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_rifle)) {
            entry.hit_radius = 5.0;
            return index;
        }
        if (type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_cannon) or
            type_id == @intFromEnum(game_ids.ProjectileTypeId.plasma_cannon))
        {
            entry.hit_radius = 10.0;
        } else {
            entry.hit_radius = 1.0;
            if (type_id == @intFromEnum(game_ids.ProjectileTypeId.gauss_gun)) {
                entry.damage_pool = 300.0;
                return index;
            }
            if (type_id == @intFromEnum(game_ids.ProjectileTypeId.fire_bullets)) {
                entry.damage_pool = 240.0;
                return index;
            }
            if (type_id == @intFromEnum(game_ids.ProjectileTypeId.blade_gun)) {
                entry.damage_pool = 50.0;
                return index;
            }
        }
        return index;
    }

    pub fn update(
        self: *ProjectilePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        creatures: *survival_creatures.CreaturePool,
        bonuses: *bonus_runtime.BonusPool,
        dt: f64,
        world_size: f64,
    ) ProjectileTickStats {
        if (!(dt > 0.0)) return .{};
        const margin = 64.0;
        var barrel_greaser_active = false;
        var ion_gun_master_active = false;
        var ion_scale: f64 = 1.0;
        for (players) |player| {
            if (player.perk_counts.get(PerkId.barrel_greaser) > 0) {
                barrel_greaser_active = true;
            }
            if (player.perk_counts.get(PerkId.ion_gun_master) > 0) {
                ion_gun_master_active = true;
            }
            if (barrel_greaser_active and ion_gun_master_active) {
                break;
            }
        }
        if (ion_scale == 1.0 and ion_gun_master_active) {
            ion_scale = 1.2;
        }
        var hit_audio_game_tune_started = state.game_tune_started;
        var tick_stats = ProjectileTickStats{};
        // Mirror Python/native spatial-hash behavior for one projectile update pass:
        // candidate slots are seeded from collidable-at-pass-start state and only
        // synced for indices touched by damage resolution.
        var collidable_snapshot = [_]bool{false} ** survival_creatures.max_creatures;
        var candidate_cell_x = [_]i32{0} ** survival_creatures.max_creatures;
        var candidate_cell_y = [_]i32{0} ** survival_creatures.max_creatures;
        var candidate_has_cell = [_]bool{false} ** survival_creatures.max_creatures;
        var max_find_margin: f64 = 0.0;
        const bucket_size: f64 = 64.0;
        for (creatures.entries, 0..) |creature, idx| {
            collidable_snapshot[idx] = creature.active and
                creature.lifecycle_stage > 5.0;
            if (!collidable_snapshot[idx]) continue;
            candidate_has_cell[idx] = true;
            candidate_cell_x[idx] = @intFromFloat(@floor(creature.pos.x / bucket_size));
            candidate_cell_y[idx] = @intFromFloat(@floor(creature.pos.y / bucket_size));
            const find_margin = narrowF32(creature.size * 0.14285715 + 3.0);
            if (find_margin > max_find_margin) {
                max_find_margin = find_margin;
            }
        }

        for (&self.entries, 0..) |*proj, proj_idx| {
            if (!proj.active) continue;

            if (proj.life_timer <= 0.0) {
                proj.active = false;
            }

            if (proj.life_timer < 0.4) {
                if (proj.type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_rifle) or
                    proj.type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_minigun))
                {
                    resetShockChainIfOwner(state, proj_idx);
                }
                const linger_decay: f64 = switch (proj.type_id) {
                    @intFromEnum(game_ids.ProjectileTypeId.gauss_gun) => dt * 0.1,
                    @intFromEnum(game_ids.ProjectileTypeId.ion_cannon) => dt * 0.7,
                    else => dt,
                };
                proj.life_timer = narrowF32(proj.life_timer - linger_decay);
                applyIonLingerDamage(
                    state,
                    players,
                    creatures,
                    bonuses,
                    proj,
                    dt,
                    ion_scale,
                    world_size,
                );
                continue;
            }

            if (proj.pos.x < -margin or proj.pos.y < -margin or
                proj.pos.x > world_size + margin or proj.pos.y > world_size + margin)
            {
                proj.life_timer = narrowF32(proj.life_timer - dt);
                continue;
            }

            var steps: i32 = @intFromFloat(proj.base_damage);
            if (steps <= 0) steps = 1;
            if (barrel_greaser_active and proj.owner_id < 0) {
                steps *= 2;
            }
            const direction = runtime_helpers.directionFromHeading(proj.angle);
            var acc = state_mod.Vec2{};

            var step: i32 = 0;
            while (step < steps) : (step += 3) {
                const step_scale = narrowF32(dt * 20.0 * proj.speed_scale * 3.0);
                acc = .{
                    .x = narrowF32(acc.x + direction.x * step_scale),
                    .y = narrowF32(acc.y + direction.y * step_scale),
                };

                if (!(acc.length() >= 4.0 or steps <= step + 3)) continue;

                const move = acc;
                proj.pos = .{
                    .x = narrowF32(proj.pos.x + move.x),
                    .y = narrowF32(proj.pos.y + move.y),
                };
                acc = .{};

                var hit_idx: ?usize = null;
                const proj_cell_x: i32 = @intFromFloat(@floor(proj.pos.x / bucket_size));
                const proj_cell_y: i32 = @intFromFloat(@floor(proj.pos.y / bucket_size));
                const max_axis_delta = narrowF32(proj.hit_radius + max_find_margin + 0.001);
                const cell_span: i32 = @intFromFloat(@ceil(max_axis_delta / bucket_size));
                for (creatures.entries, 0..) |creature, idx| {
                    if (!collidable_snapshot[idx]) continue;
                    if (!candidate_has_cell[idx]) continue;
                    if (!(creature.active and creature.lifecycle_stage > 5.0)) continue;
                    const in_span =
                        @abs(candidate_cell_x[idx] - proj_cell_x) <= cell_span and
                        @abs(candidate_cell_y[idx] - proj_cell_y) <= cell_span;
                    if (!in_span) continue;
                    if (runtime_helpers.withinNativeFindRadius(
                        proj.pos,
                        creature.pos,
                        proj.hit_radius,
                        creature.size,
                    )) {
                        hit_idx = idx;
                        break;
                    }
                }

                if (hit_idx) |idx| {
                    if (proj.owner_id >= 0 and idx == @as(usize, @intCast(proj.owner_id))) {
                        hit_idx = null;
                    }
                }
                if (hit_idx == null) {
                    var can_hit_players = true;
                    if (state.shock_chain_projectile_id == @as(i32, @intCast(proj_idx))) {
                        can_hit_players = false;
                    }

                    if (proj.hits_players and can_hit_players) {
                        var hit_player_idx: ?usize = null;
                        const owner_player_idx: ?usize = if (proj.owner_id < 0 and proj.owner_id != -100)
                            ownerIdToPlayerIndex(proj.owner_id, players.len)
                        else
                            null;

                        for (players, 0..) |player, idx| {
                            if (owner_player_idx) |owner_idx| {
                                if (owner_idx == idx) continue;
                            }
                            if (!(player.health > 0.0)) continue;
                            if (runtime_helpers.withinNativeFindRadius(
                                proj.pos,
                                player.pos,
                                proj.hit_radius,
                                player.size,
                            )) {
                                hit_player_idx = idx;
                                break;
                            }
                        }

                        if (hit_player_idx) |player_idx| {
                            proj.life_timer = 0.25;
                            if (players[player_idx].shield_timer <= 0.0) {
                                players[player_idx].health = narrowF32(players[player_idx].health - 10.0);
                            }
                        }
                    }
                    continue;
                }
                tick_stats.hit_count += 1;
                if (tick_stats.first_hit_creature_index < 0) {
                    tick_stats.first_hit_creature_index = @intCast(hit_idx.?);
                    tick_stats.first_hit_projectile_index = @intCast(proj_idx);
                    tick_stats.first_hit_type_id = proj.type_id;
                    tick_stats.first_hit_origin = .{
                        .x = narrowF32(proj.origin.x),
                        .y = narrowF32(proj.origin.y),
                    };
                    tick_stats.first_hit_pos = .{
                        .x = narrowF32(proj.pos.x),
                        .y = narrowF32(proj.pos.y),
                    };
                    tick_stats.first_hit_target_size = narrowF32(creatures.entries[hit_idx.?].size);
                    tick_stats.first_hit_target_x = narrowF32(creatures.entries[hit_idx.?].pos.x);
                    tick_stats.first_hit_target_y = narrowF32(creatures.entries[hit_idx.?].pos.y);
                }

                const owner_player_idx = ownerIdToPlayerIndex(proj.owner_id, players.len);
                const owner_player = if (owner_player_idx) |idx| &players[idx] else null;
                const presentation_player = if (owner_player_idx) |idx| &players[idx] else if (players.len > 0) &players[0] else null;

                if (owner_player) |player| {
                    if (perkActive(player, PerkId.poison_bullets)) {
                        const poison_roll = state.rng.rand();
                        if ((poison_roll & 7) == 1) {
                            creatures.entries[hit_idx.?].flags |= survival_spawn.CreatureFlags.self_damage_tick;
                        }
                    }
                }
                if (presentation_player) |player| {
                    survival_creatures.consumeProjectileHitPresentationPreRng(
                        state,
                        player,
                        proj.type_id,
                    );
                }

                if (owner_player_idx) |idx| {
                    if (idx < state.shots_hit.len and creatures.entries[hit_idx.?].lifecycle_stage == creature_lifecycle_stage_alive) {
                        state.shots_hit[idx] += 1;
                    }
                }

                if (proj.life_timer != 0.25 and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.fire_bullets) and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.gauss_gun) and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.blade_gun))
                {
                    proj.life_timer = 0.25;
                    const jitter = @as(f64, @floatFromInt(state.rng.rand() & 3));
                    proj.pos = .{
                        .x = narrowF32(proj.pos.x + direction.x * jitter),
                        .y = narrowF32(proj.pos.y + direction.y * jitter),
                    };
                }

                if (proj.type_id == @intFromEnum(game_ids.ProjectileTypeId.ion_rifle)) {
                    postHitIonRifleShockChain(
                        state,
                        self,
                        creatures,
                        proj_idx,
                        proj,
                        hit_idx.?,
                    );
                }
                if (proj.type_id == @intFromEnum(game_ids.ProjectileTypeId.pulse_gun)) {
                    // Native pulse-gun post-hit behavior pushes the target using the
                    // current projectile move delta before damage resolution.
                    creatures.entries[hit_idx.?].pos = .{
                        .x = narrowF32(creatures.entries[hit_idx.?].pos.x + move.x * 3.0),
                        .y = narrowF32(creatures.entries[hit_idx.?].pos.y + move.y * 3.0),
                    };
                }
                consumeIonHitEffectsRng(state, proj.type_id);

                var dist = state_mod.Vec2.sub(proj.origin, proj.pos).length();
                if (dist < 50.0) dist = 50.0;
                const damage_scale = damageScaleFromRawId(proj.type_id);
                const damage_amount = ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95;
                const impulse_axis = narrowF32(survival_math.cos(proj.angle - native_half_pi) * proj.speed_scale);
                const impulse = state_mod.Vec2{
                    .x = impulse_axis,
                    .y = impulse_axis,
                };

                if (damage_amount > 0.0 and creatures.entries[hit_idx.?].hp > 0.0) {
                    const remaining = proj.damage_pool - 1.0;
                    proj.damage_pool = remaining;
                    if (remaining <= 0.0) {
                        _ = creatures.applyProjectileDamage(
                            state,
                            players,
                            bonuses,
                            hit_idx.?,
                            damage_amount,
                            impulse,
                            proj.owner_id,
                            dt,
                            world_size,
                        );
                        if (proj.life_timer != 0.25) {
                            proj.life_timer = 0.25;
                        }
                    } else {
                        _ = creatures.applyProjectileDamage(
                            state,
                            players,
                            bonuses,
                            hit_idx.?,
                            remaining,
                            impulse,
                            proj.owner_id,
                            dt,
                            world_size,
                        );
                        proj.damage_pool -= narrowF32(creatures.entries[hit_idx.?].hp);
                    }
                    const idx = hit_idx.?;
                    collidable_snapshot[idx] = creatures.entries[idx].active and
                        creatures.entries[idx].lifecycle_stage > 5.0;
                    if (!collidable_snapshot[idx]) {
                        candidate_has_cell[idx] = false;
                    } else {
                        candidate_has_cell[idx] = true;
                        candidate_cell_x[idx] = @intFromFloat(@floor(creatures.entries[idx].pos.x / bucket_size));
                        candidate_cell_y[idx] = @intFromFloat(@floor(creatures.entries[idx].pos.y / bucket_size));
                        const find_margin = narrowF32(creatures.entries[idx].size * 0.14285715 + 3.0);
                        if (find_margin > max_find_margin) {
                            max_find_margin = find_margin;
                        }
                    }
                }

                // Native `projectile_update` spawns one freeze shard for non-gauss/non-fire
                // projectile hits while Freeze bonus is active.
                if (state.bonuses.freeze > 0.0 and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.gauss_gun) and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.fire_bullets))
                {
                    consumeFreezeHitShardRng(state);
                }

                if (proj.damage_pool == 1.0) {
                    const life_before = proj.life_timer;
                    proj.damage_pool = 0.0;
                    if (life_before != 0.25) {
                        proj.life_timer = 0.25;
                    }
                }

                if (proj.life_timer == 0.25 and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.fire_bullets) and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.gauss_gun) and
                    proj.type_id != @intFromEnum(game_ids.ProjectileTypeId.blade_gun))
                {
                    if (presentation_player != null) {
                        survival_creatures.consumeProjectileHitPresentationPostRng(
                            state,
                            proj.type_id,
                        );
                        survival_creatures.consumeHitSfxRng(
                            state,
                            &hit_audio_game_tune_started,
                            proj.type_id,
                        );
                    }
                    break;
                }
                if (presentation_player != null) {
                    survival_creatures.consumeProjectileHitPresentationPostRng(
                        state,
                        proj.type_id,
                    );
                    survival_creatures.consumeHitSfxRng(
                        state,
                        &hit_audio_game_tune_started,
                        proj.type_id,
                    );
                }
                if (proj.damage_pool <= 0.0) break;
            }
        }
        state.game_tune_started = hit_audio_game_tune_started;
        return tick_stats;
    }
};

fn resetShockChainIfOwner(
    state: *state_mod.GameplayState,
    proj_index: usize,
) void {
    if (state.shock_chain_projectile_id != @as(i32, @intCast(proj_index))) return;
    state.shock_chain_projectile_id = -1;
    state.shock_chain_links_left = 0;
}

fn applyIonLingerDamage(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: *survival_creatures.CreaturePool,
    bonus_pool: *bonus_runtime.BonusPool,
    proj: *Projectile,
    dt: f64,
    ion_scale: f64,
    world_size: f64,
) void {
    var damage: f64 = 0.0;
    var radius: f64 = 0.0;
    switch (proj.type_id) {
        @intFromEnum(game_ids.ProjectileTypeId.ion_minigun) => {
            damage = dt * 40.0;
            radius = ion_scale * 60.0;
        },
        @intFromEnum(game_ids.ProjectileTypeId.ion_rifle) => {
            damage = dt * 100.0;
            radius = ion_scale * 88.0;
        },
        @intFromEnum(game_ids.ProjectileTypeId.ion_cannon) => {
            damage = dt * 300.0;
            radius = ion_scale * 128.0;
        },
        else => return,
    }

    for (creatures.entries, 0..) |creature, idx| {
        if (!creature.active) continue;
        if (!(creature.lifecycle_stage > 5.0)) continue;
        const creature_radius = creatureHitRadius(creature.size);
        const hit_radius = radius + creature_radius;
        if (runtime_helpers.distanceSq(proj.pos, creature.pos) <= hit_radius * hit_radius) {
            _ = creatures.applyIonDamage(
                state,
                players,
                bonus_pool,
                idx,
                damage,
                .{},
                proj.owner_id,
                dt,
                world_size,
            );
        }
    }
}

fn consumeFreezeHitShardRng(state: *state_mod.GameplayState) void {
    // `shard_angle` draw + `effect_spawn_freeze_shard` internal draws.
    _ = state.rng.rand() % 0x264;
    _ = state.rng.rand() & 0xF;
    _ = state.rng.rand() % 100;
    _ = state.rng.rand() % 5;
    _ = state.rng.rand() % 0x14;
    _ = state.rng.rand() & 0xF;
    _ = state.rng.rand() % 3;
}

fn creatureHitRadius(size: f64) f64 {
    const radius = narrowF32(size * 0.14285715 + 3.0);
    if (radius < 0.0) return 0.0;
    return radius;
}

fn postHitIonRifleShockChain(
    state: *state_mod.GameplayState,
    pool: *ProjectilePool,
    creatures: *survival_creatures.CreaturePool,
    proj_index: usize,
    proj: *const Projectile,
    hit_idx: usize,
) void {
    if (state.shock_chain_projectile_id != @as(i32, @intCast(proj_index))) return;
    if (hit_idx >= creatures.entries.len) return;

    const links_left = state.shock_chain_links_left;
    if (links_left <= 0) return;
    state.shock_chain_links_left = links_left - 1;

    const origin_pos = proj.pos;
    const min_dist_sq = 100.0 * 100.0;
    var best_idx: usize = 0;
    var best_dist_sq: f64 = 1e12;
    for (creatures.entries, 0..) |creature, idx| {
        if (idx == hit_idx) continue;
        if (!creature.active) continue;
        const d_sq = runtime_helpers.distanceSq(origin_pos, creature.pos);
        if (d_sq <= min_dist_sq) continue;
        if (d_sq < best_dist_sq) {
            best_dist_sq = d_sq;
            best_idx = idx;
        }
    }

    const origin_creature = creatures.entries[hit_idx];
    const target = creatures.entries[best_idx];
    const angle = state_mod.Vec2.sub(target.pos, origin_creature.pos).toHeading();

    const prev_guard = state.bonus_spawn_guard;
    state.bonus_spawn_guard = true;
    defer state.bonus_spawn_guard = prev_guard;

    const spawned_idx = pool.spawn(
        origin_pos,
        angle,
        proj.type_id,
        @intCast(hit_idx),
        proj.base_damage,
        false,
    );
    state.shock_chain_projectile_id = @intCast(spawned_idx);
}

fn consumeIonHitEffectsRng(
    state: *state_mod.GameplayState,
    projectile_type_id: i32,
) void {
    var burst_scale: f64 = 0.0;
    switch (projectile_type_id) {
        @intFromEnum(game_ids.ProjectileTypeId.ion_minigun) => burst_scale = 0.8,
        @intFromEnum(game_ids.ProjectileTypeId.ion_rifle) => burst_scale = 1.2,
        @intFromEnum(game_ids.ProjectileTypeId.ion_cannon) => burst_scale = 2.2,
        else => return,
    }

    const burst = burst_scale * 0.8;
    var count: i32 = @intFromFloat(burst * 5.0);
    if (count < 0) count = 0;
    var idx: i32 = 0;
    while (idx < count) : (idx += 1) {
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
        _ = state.rng.rand();
    }
}

fn ownerIdToPlayerIndex(owner_id: i32, player_len: usize) ?usize {
    if (owner_id == -100) {
        if (player_len > 0) return 0;
        return null;
    }
    if (owner_id < 0) {
        const idx: i32 = -1 - owner_id;
        if (idx < 0) return null;
        const as_usize: usize = @intCast(idx);
        if (as_usize < player_len) return as_usize;
    }
    return null;
}

fn projectileMetaFromRawId(raw_id: i32) f32 {
    const weapon_id = state_mod.weaponIdFromInt(raw_id) orelse return 45.0;
    return state_mod.weapon_stats.get(weapon_id).projectile_meta;
}

fn damageScaleFromRawId(raw_id: i32) f32 {
    const weapon_id = state_mod.weaponIdFromInt(raw_id) orelse return 1.0;
    return state_mod.weapon_stats.get(weapon_id).damage_scale;
}

fn perkActive(player: *const state_mod.PlayerState, perk_id: PerkId) bool {
    return player.perk_counts.get(perk_id) > 0;
}

fn expectFloatClose(expected: f64, actual: f64) !void {
    try std.testing.expectApproxEqAbs(expected, actual, 1e-6);
}

test "projectile hit consumes hit-presentation rng" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 102.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    var pool = ProjectilePool{};
    _ = pool.spawn(
        players[0].pos,
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        -1,
        55.0,
        false,
    );
    const rng_before = state.rng.state;
    _ = pool.update(&state, players[0..], &creatures, &bonuses, 1.0 / 60.0, 1024.0);
    try std.testing.expect(rng_before != state.rng.state);
}

test "pulse gun hit applies post-hit target push" {
    var state = state_mod.GameplayState.init(1);
    const initial_creature_x = 102.0;
    const initial_creature_y = 100.0;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = initial_creature_x, .y = initial_creature_y },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 44.0,
        .move_speed = 1.0,
        .health = 1000.0,
        .max_health = 1000.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    var base_pool = ProjectilePool{};
    _ = base_pool.spawn(
        players[0].pos,
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        -100,
        45.0,
        false,
    );
    _ = base_pool.update(&state, players[0..], &creatures, &bonuses, 1.0 / 60.0, 1024.0);
    const base_dx = creatures.entries[0].pos.x - initial_creature_x;
    const base_dy = creatures.entries[0].pos.y - initial_creature_y;
    const base_displacement = std.math.sqrt(base_dx * base_dx + base_dy * base_dy);

    creatures.entries[0].pos = .{ .x = initial_creature_x, .y = initial_creature_y };
    creatures.entries[0].hp = 1000.0;
    creatures.entries[0].lifecycle_stage = creature_lifecycle_stage_alive;
    creatures.entries[0].active = true;

    var pulse_pool = ProjectilePool{};
    _ = pulse_pool.spawn(
        players[0].pos,
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.pulse_gun),
        -100,
        45.0,
        false,
    );
    const pulse_tick = pulse_pool.update(&state, players[0..], &creatures, &bonuses, 1.0 / 60.0, 1024.0);
    const pulse_dx = creatures.entries[0].pos.x - initial_creature_x;
    const pulse_dy = creatures.entries[0].pos.y - initial_creature_y;
    const pulse_displacement = std.math.sqrt(pulse_dx * pulse_dx + pulse_dy * pulse_dy);
    try std.testing.expect(pulse_tick.hit_count > 0);
    try std.testing.expect(pulse_displacement > base_displacement + 1.5);
}

test "projectile hit pass does not retarget newly spawned split children in new slots" {
    var state = state_mod.GameplayState.init(1);
    state.bonus_spawn_guard = true;
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = survival_spawn.CreatureFlags.anim_ping_pong | survival_spawn.CreatureFlags.split_on_death,
        .size = 40.0,
        .move_speed = 1.0,
        .health = 18.0,
        .max_health = 400.0,
        .reward_value = 131.68724279835388,
        .contact_damage = 4.0,
    });
    creatures.entries[39] = creatures.entries[0];
    creatures.entries[0] = .{};

    var pool = ProjectilePool{};
    const proj_idx = pool.spawn(
        .{ .x = 100.0, .y = 100.0 },
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.fire_bullets),
        -100,
        300.0,
        false,
    );
    pool.entries[proj_idx].hit_radius = 8.0;

    const tick = pool.update(&state, players[0..], &creatures, &bonuses, 1.0 / 60.0, 1024.0);
    try std.testing.expect(tick.hit_count > 2);
    try std.testing.expect(creatures.entries[39].active);
    try std.testing.expect(creatures.entries[39].hp < 0.0);
    // Child spawned into previously inactive index 0 should not be retargeted until next update pass.
    try std.testing.expect(creatures.entries[0].active);
    try expectFloatClose(100.0, creatures.entries[0].hp);
}

test "poison bullets sets weak self-damage flag when rng roll hits" {
    var state = state_mod.GameplayState.init(1);
    state.rng.state = 1; // First rand() == 41 => (41 & 7) == 1.
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    players[0].perk_counts.set(PerkId.poison_bullets, 1);

    var creatures = survival_creatures.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 102.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = survival_spawn.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 1000.0,
        .max_health = 1000.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    var pool = ProjectilePool{};
    _ = pool.spawn(
        players[0].pos,
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        -100,
        45.0,
        false,
    );

    const tick = pool.update(&state, players[0..], &creatures, &bonuses, 0.016, 1024.0);
    try std.testing.expect(tick.hit_count > 0);
    try std.testing.expect((creatures.entries[0].flags & survival_spawn.CreatureFlags.self_damage_tick) != 0);
}

test "poison bullets does not set self-damage flag when rng roll misses" {
    var state = state_mod.GameplayState.init(1);
    state.rng.state = 0; // First rand() == 38 => (38 & 7) != 1.
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    players[0].perk_counts.set(PerkId.poison_bullets, 1);

    var creatures = survival_creatures.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 102.0, .y = 100.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = survival_spawn.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 1000.0,
        .max_health = 1000.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    var pool = ProjectilePool{};
    _ = pool.spawn(
        players[0].pos,
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        -100,
        45.0,
        false,
    );

    const tick = pool.update(&state, players[0..], &creatures, &bonuses, 0.016, 1024.0);
    try std.testing.expect(tick.hit_count > 0);
    try std.testing.expect((creatures.entries[0].flags & survival_spawn.CreatureFlags.self_damage_tick) == 0);
}

test "poison bullets with toxic avenger still applies weak bullet poison only" {
    var state = state_mod.GameplayState.init(1);
    state.rng.state = 1; // First rand() == 41 => (41 & 7) == 1.
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    players[0].perk_counts.set(PerkId.poison_bullets, 1);
    players[0].perk_counts.set(PerkId.toxic_avenger, 1);

    var creatures = survival_creatures.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 300.0, .y = 300.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .flags = survival_spawn.CreatureFlags.anim_ping_pong,
        .size = 44.0,
        .move_speed = 0.0,
        .health = 1000.0,
        .max_health = 1000.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });

    var pool = ProjectilePool{};
    _ = pool.spawn(
        creatures.entries[0].pos,
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        -100,
        45.0,
        false,
    );

    _ = pool.update(&state, players[0..], &creatures, &bonuses, 0.016, 1024.0);
    try std.testing.expect((creatures.entries[0].flags & survival_spawn.CreatureFlags.self_damage_tick) != 0);
    try std.testing.expect((creatures.entries[0].flags & survival_spawn.CreatureFlags.self_damage_tick_strong) == 0);
}

test "barrel greaser doubles pistol projectile movement steps" {
    var base_state = state_mod.GameplayState.init(1);
    var base_players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};
    var base_pool = ProjectilePool{};
    _ = base_pool.spawn(
        .{},
        std.math.pi / 2.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        -100,
        state_mod.weapon_stats.get(WeaponId.pistol).projectile_meta,
        false,
    );
    _ = base_pool.update(
        &base_state,
        base_players[0..],
        &creatures,
        &bonuses,
        0.016,
        10_000.0,
    );
    const base_x = base_pool.entries[0].pos.x;

    var greased_state = state_mod.GameplayState.init(1);
    var greased_players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    greased_players[0].perk_counts.set(PerkId.barrel_greaser, 1);
    var greased_pool = ProjectilePool{};
    _ = greased_pool.spawn(
        .{},
        std.math.pi / 2.0,
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        -100,
        state_mod.weapon_stats.get(WeaponId.pistol).projectile_meta,
        false,
    );
    _ = greased_pool.update(
        &greased_state,
        greased_players[0..],
        &creatures,
        &bonuses,
        0.016,
        10_000.0,
    );
    const greased_x = greased_pool.entries[0].pos.x;

    try expectFloatClose(18.239999771118164, base_x);
    try expectFloatClose(35.519996643066406, greased_x);
    try std.testing.expect(greased_x > base_x);
}

test "ion gun master increases ion rifle linger radius" {
    var state_without = state_mod.GameplayState.init(1);
    var players_without = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    var creatures_without = survival_creatures.CreaturePool{};
    var bonuses_without = bonus_runtime.BonusPool{};
    _ = creatures_without.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 105.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });
    var pool_without = ProjectilePool{};
    const idx_without = pool_without.spawn(
        .{},
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.ion_rifle),
        -100,
        45.0,
        false,
    );
    pool_without.entries[idx_without].life_timer = 0.39;
    _ = pool_without.update(
        &state_without,
        players_without[0..],
        &creatures_without,
        &bonuses_without,
        0.016,
        10_000.0,
    );
    try expectFloatClose(10.0, creatures_without.entries[0].hp);

    var state_with = state_mod.GameplayState.init(1);
    var players_with = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{} },
    };
    players_with[0].perk_counts.set(PerkId.ion_gun_master, 1);
    var creatures_with = survival_creatures.CreaturePool{};
    var bonuses_with = bonus_runtime.BonusPool{};
    _ = creatures_with.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 105.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 50.0,
        .contact_damage = 4.0,
    });
    var pool_with = ProjectilePool{};
    const idx_with = pool_with.spawn(
        .{},
        0.0,
        @intFromEnum(game_ids.ProjectileTypeId.ion_rifle),
        -100,
        45.0,
        false,
    );
    pool_with.entries[idx_with].life_timer = 0.39;
    _ = pool_with.update(
        &state_with,
        players_with[0..],
        &creatures_with,
        &bonuses_with,
        0.016,
        10_000.0,
    );
    try std.testing.expect(creatures_with.entries[0].hp < 10.0);
}

test "ranged projectile can damage player when no creature is hit" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 4.0, .y = 0.0 },
            .health = 100.0,
        },
    };
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};
    var pool = ProjectilePool{};

    _ = pool.spawn(
        .{},
        native_half_pi,
        @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle),
        0,
        45.0,
        true,
    );

    _ = pool.update(
        &state,
        players[0..],
        &creatures,
        &bonuses,
        0.001,
        1024.0,
    );

    try std.testing.expect(players[0].health < 100.0);
}

test "ranged projectile can damage creature before player collision" {
    var state = state_mod.GameplayState.init(1);
    var players = [_]state_mod.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 4.0, .y = 0.0 },
            .health = 100.0,
        },
    };
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = bonus_runtime.BonusPool{};
    var pool = ProjectilePool{};

    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = -200.0, .y = -200.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 10.0,
        .max_health = 10.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });
    _ = creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 4.0, .y = 0.0 },
        .heading = 0.0,
        .phase_seed = 0.0,
        .type_id = .alien,
        .size = 50.0,
        .move_speed = 0.0,
        .health = 100.0,
        .max_health = 100.0,
        .reward_value = 10.0,
        .contact_damage = 0.0,
    });

    _ = pool.spawn(
        .{},
        native_half_pi,
        @intFromEnum(game_ids.ProjectileTypeId.plasma_rifle),
        0,
        45.0,
        true,
    );

    _ = pool.update(
        &state,
        players[0..],
        &creatures,
        &bonuses,
        0.1,
        1024.0,
    );

    try std.testing.expect(creatures.entries[1].hp < 100.0);
    try expectFloatClose(100.0, players[0].health);
}
