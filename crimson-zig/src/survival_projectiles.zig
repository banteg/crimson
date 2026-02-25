const std = @import("std");

const survival_bonuses = @import("survival_bonuses.zig");
const survival_creatures = @import("survival_creatures.zig");
const survival_perks = @import("survival_perks.zig");
const survival_spawn = @import("survival_spawn.zig");
const survival_state = @import("survival_state.zig");
const survival_math = @import("survival_math.zig");

pub const main_projectile_pool_size: usize = 0x60;
const native_half_pi: f64 = 1.5707963705062866;
const creature_lifecycle_stage_alive: f64 = 16.0;
const perk_id_poison_bullets: i32 = 25;
const perk_id_barrel_greaser: i32 = 34;
const perk_id_ion_gun_master: i32 = survival_perks.PerkId.ion_gun_master;

pub const Projectile = struct {
    active: bool = false,
    angle: f64 = 0.0,
    pos: survival_state.Vec2 = .{},
    origin: survival_state.Vec2 = .{},
    vel: survival_state.Vec2 = .{},
    type_id: i32 = 0,
    life_timer: f64 = 0.0,
    reserved: f64 = 0.0,
    speed_scale: f64 = 1.0,
    damage_pool: f64 = 1.0,
    hit_radius: f64 = 1.0,
    base_damage: f64 = 0.0,
    owner_id: i32 = 0,
    hits_players: bool = false,
};

pub const ProjectileTickStats = struct {
    hit_count: i32 = 0,
    first_hit_creature_index: i32 = -1,
    first_hit_projectile_index: i32 = -1,
    first_hit_type_id: i32 = 0,
    first_hit_origin: survival_state.Vec2 = .{},
    first_hit_pos: survival_state.Vec2 = .{},
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
        pos: survival_state.Vec2,
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

        const meta = if (base_damage > 0.0) base_damage else survival_state.weaponProjectileMeta(type_id);
        var entry = &self.entries[index];
        entry.* = .{
            .active = true,
            .angle = angle,
            .pos = .{ .x = pos.x, .y = pos.y },
            .origin = .{ .x = pos.x, .y = pos.y },
            .vel = directionFromHeading(angle).mul(1.5),
            .type_id = type_id,
            .life_timer = 0.4,
            .reserved = 0.0,
            .speed_scale = 1.0,
            .damage_pool = 1.0,
            .hit_radius = 1.0,
            .base_damage = asF32F64(meta),
            .owner_id = owner_id,
            .hits_players = hits_players,
        };

        if (type_id == 0x16) {
            entry.hit_radius = 3.0;
            return index;
        }
        if (type_id == 0x15) {
            entry.hit_radius = 5.0;
            return index;
        }
        if (type_id == 0x17 or type_id == 0x1C) {
            entry.hit_radius = 10.0;
        } else {
            entry.hit_radius = 1.0;
            if (type_id == 0x06) {
                entry.damage_pool = 300.0;
                return index;
            }
            if (type_id == 0x2D) {
                entry.damage_pool = 240.0;
                return index;
            }
            if (type_id == 0x19) {
                entry.damage_pool = 50.0;
                return index;
            }
        }
        return index;
    }

    pub fn update(
        self: *ProjectilePool,
        state: *survival_state.GameplayState,
        players: []survival_state.PlayerState,
        creatures: *survival_creatures.CreaturePool,
        bonuses: *survival_bonuses.BonusPool,
        dt: f64,
        world_size: f64,
    ) ProjectileTickStats {
        if (!(dt > 0.0)) return .{};
        const margin = 64.0;
        var barrel_greaser_active = false;
        var ion_gun_master_active = false;
        var ion_scale: f64 = 1.0;
        for (players) |player| {
            if (perk_id_barrel_greaser >= 0 and perk_id_barrel_greaser < player.perk_counts.len and
                player.perk_counts[@intCast(perk_id_barrel_greaser)] > 0)
            {
                barrel_greaser_active = true;
            }
            if (perk_id_ion_gun_master >= 0 and perk_id_ion_gun_master < player.perk_counts.len and
                player.perk_counts[@intCast(perk_id_ion_gun_master)] > 0)
            {
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

        for (&self.entries, 0..) |*proj, proj_idx| {
            if (!proj.active) continue;

            if (proj.life_timer <= 0.0) {
                proj.active = false;
            }

            if (proj.life_timer < 0.4) {
                if (proj.type_id == survival_state.ProjectileTypeId.ion_rifle or
                    proj.type_id == survival_state.ProjectileTypeId.ion_minigun)
                {
                    resetShockChainIfOwner(state, proj_idx);
                }
                const linger_decay: f64 = switch (proj.type_id) {
                    survival_state.ProjectileTypeId.gauss_gun => dt * 0.1,
                    survival_state.ProjectileTypeId.ion_cannon => dt * 0.7,
                    else => dt,
                };
                proj.life_timer = asF32F64(proj.life_timer - linger_decay);
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
                proj.life_timer = asF32F64(proj.life_timer - dt);
                continue;
            }

            var steps: i32 = @intFromFloat(proj.base_damage);
            if (steps <= 0) steps = 1;
            if (barrel_greaser_active and proj.owner_id < 0) {
                steps *= 2;
            }
            const direction = directionFromHeading(proj.angle);
            var acc = survival_state.Vec2{};

            var step: i32 = 0;
            while (step < steps) : (step += 3) {
                const step_scale = asF32F64(dt * 20.0 * proj.speed_scale * 3.0);
                acc = .{
                    .x = asF32F64(acc.x + direction.x * step_scale),
                    .y = asF32F64(acc.y + direction.y * step_scale),
                };

                if (!(acc.length() >= 4.0 or steps <= step + 3)) continue;

                const move = acc;
                proj.pos = .{
                    .x = asF32F64(proj.pos.x + move.x),
                    .y = asF32F64(proj.pos.y + move.y),
                };
                acc = .{};

                var hit_idx: ?usize = null;
                for (creatures.entries, 0..) |creature, idx| {
                    if (!creature.active) continue;
                    if (!(creature.lifecycle_stage > 5.0)) continue;
                    if (withinNativeFindRadius(
                        proj.pos,
                        creature.pos,
                        proj.hit_radius,
                        creature.size,
                    )) {
                        hit_idx = idx;
                        break;
                    }
                }

                if (hit_idx == null) continue;
                if (proj.owner_id >= 0 and hit_idx.? == @as(usize, @intCast(proj.owner_id))) continue;
                tick_stats.hit_count += 1;
                if (tick_stats.first_hit_creature_index < 0) {
                    tick_stats.first_hit_creature_index = @intCast(hit_idx.?);
                    tick_stats.first_hit_projectile_index = @intCast(proj_idx);
                    tick_stats.first_hit_type_id = proj.type_id;
                    tick_stats.first_hit_origin = .{
                        .x = asF32F64(proj.origin.x),
                        .y = asF32F64(proj.origin.y),
                    };
                    tick_stats.first_hit_pos = .{
                        .x = asF32F64(proj.pos.x),
                        .y = asF32F64(proj.pos.y),
                    };
                    tick_stats.first_hit_target_size = asF32F64(creatures.entries[hit_idx.?].size);
                    tick_stats.first_hit_target_x = asF32F64(creatures.entries[hit_idx.?].pos.x);
                    tick_stats.first_hit_target_y = asF32F64(creatures.entries[hit_idx.?].pos.y);
                }

                const owner_player_idx = ownerIdToPlayerIndex(proj.owner_id, players.len);
                const owner_player = if (owner_player_idx) |idx| &players[idx] else null;
                const presentation_player = if (owner_player_idx) |idx| &players[idx] else if (players.len > 0) &players[0] else null;

                if (owner_player) |player| {
                    if (perkActive(player, perk_id_poison_bullets)) {
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
                    proj.type_id != survival_state.ProjectileTypeId.fire_bullets and
                    proj.type_id != survival_state.ProjectileTypeId.gauss_gun and
                    proj.type_id != survival_state.ProjectileTypeId.blade_gun)
                {
                    proj.life_timer = 0.25;
                    const jitter = @as(f64, @floatFromInt(state.rng.rand() & 3));
                    proj.pos = .{
                        .x = asF32F64(proj.pos.x + direction.x * jitter),
                        .y = asF32F64(proj.pos.y + direction.y * jitter),
                    };
                }

                if (proj.type_id == survival_state.ProjectileTypeId.ion_rifle) {
                    postHitIonRifleShockChain(
                        state,
                        self,
                        creatures,
                        proj_idx,
                        proj,
                        hit_idx.?,
                    );
                }
                consumeIonHitEffectsRng(state, proj.type_id);

                var dist = survival_state.Vec2.sub(proj.origin, proj.pos).length();
                if (dist < 50.0) dist = 50.0;
                const damage_scale = survival_state.weaponDamageScale(proj.type_id);
                const damage_amount = ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95;
                const impulse_axis = asF32F64(survival_math.cos(proj.angle - native_half_pi) * proj.speed_scale);
                const impulse = survival_state.Vec2{
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
                        proj.damage_pool -= creatures.entries[hit_idx.?].hp;
                    }
                }

                // Native `projectile_update` spawns one freeze shard for non-gauss/non-fire
                // projectile hits while Freeze bonus is active.
                if (state.bonuses.freeze > 0.0 and
                    proj.type_id != survival_state.ProjectileTypeId.gauss_gun and
                    proj.type_id != survival_state.ProjectileTypeId.fire_bullets)
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
                    proj.type_id != survival_state.ProjectileTypeId.fire_bullets and
                    proj.type_id != survival_state.ProjectileTypeId.gauss_gun and
                    proj.type_id != survival_state.ProjectileTypeId.blade_gun)
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

fn withinNativeFindRadius(
    origin: survival_state.Vec2,
    target: survival_state.Vec2,
    radius: f64,
    target_size: f64,
) bool {
    const dx = target.x - origin.x;
    const dy = target.y - origin.y;
    const size_margin = target_size * 0.14285715 + 3.0;
    const max_axis_delta = radius + size_margin;
    if (@abs(dx) > max_axis_delta or @abs(dy) > max_axis_delta) return false;
    const margin = std.math.sqrt(dx * dx + dy * dy) - radius - size_margin;
    return margin < 0.0;
}

fn resetShockChainIfOwner(
    state: *survival_state.GameplayState,
    proj_index: usize,
) void {
    if (state.shock_chain_projectile_id != @as(i32, @intCast(proj_index))) return;
    state.shock_chain_projectile_id = -1;
    state.shock_chain_links_left = 0;
}

fn applyIonLingerDamage(
    state: *survival_state.GameplayState,
    players: []survival_state.PlayerState,
    creatures: *survival_creatures.CreaturePool,
    bonus_pool: *survival_bonuses.BonusPool,
    proj: *Projectile,
    dt: f64,
    ion_scale: f64,
    world_size: f64,
) void {
    var damage: f64 = 0.0;
    var radius: f64 = 0.0;
    switch (proj.type_id) {
        survival_state.ProjectileTypeId.ion_minigun => {
            damage = dt * 40.0;
            radius = ion_scale * 60.0;
        },
        survival_state.ProjectileTypeId.ion_rifle => {
            damage = dt * 100.0;
            radius = ion_scale * 88.0;
        },
        survival_state.ProjectileTypeId.ion_cannon => {
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
        if (distanceSq(proj.pos, creature.pos) <= hit_radius * hit_radius) {
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

fn consumeFreezeHitShardRng(state: *survival_state.GameplayState) void {
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
    const radius = asF32F64(size * 0.14285715 + 3.0);
    if (radius < 0.0) return 0.0;
    return radius;
}

fn directionFromHeading(heading: f64) survival_state.Vec2 {
    const radians = heading - std.math.pi / 2.0;
    return .{
        .x = survival_math.cos(radians),
        .y = survival_math.sin(radians),
    };
}

fn postHitIonRifleShockChain(
    state: *survival_state.GameplayState,
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
        const d_sq = distanceSq(origin_pos, creature.pos);
        if (d_sq <= min_dist_sq) continue;
        if (d_sq < best_dist_sq) {
            best_dist_sq = d_sq;
            best_idx = idx;
        }
    }

    const origin_creature = creatures.entries[hit_idx];
    const target = creatures.entries[best_idx];
    const angle = survival_state.Vec2.sub(target.pos, origin_creature.pos).toHeading();

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

fn distanceSq(a: survival_state.Vec2, b: survival_state.Vec2) f64 {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    return dx * dx + dy * dy;
}

fn consumeIonHitEffectsRng(
    state: *survival_state.GameplayState,
    projectile_type_id: i32,
) void {
    var burst_scale: f64 = 0.0;
    switch (projectile_type_id) {
        survival_state.ProjectileTypeId.ion_minigun => burst_scale = 0.8,
        survival_state.ProjectileTypeId.ion_rifle => burst_scale = 1.2,
        survival_state.ProjectileTypeId.ion_cannon => burst_scale = 2.2,
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

fn perkActive(player: *const survival_state.PlayerState, perk_id: i32) bool {
    if (perk_id < 0 or perk_id >= player.perk_counts.len) return false;
    return player.perk_counts[@intCast(perk_id)] > 0;
}

fn asF32F64(value: f64) f64 {
    const rounded: f32 = @floatCast(value);
    return @floatCast(rounded);
}

test "projectile hit consumes hit-presentation rng" {
    var state = survival_state.GameplayState.init(1);
    var players = [_]survival_state.PlayerState{
        .{
            .index = 0,
            .pos = .{ .x = 100.0, .y = 100.0 },
        },
    };
    var creatures = survival_creatures.CreaturePool{};
    var bonuses = survival_bonuses.BonusPool{};
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
        survival_state.ProjectileTypeId.pistol,
        -1,
        55.0,
        false,
    );
    const rng_before = state.rng.state;
    _ = pool.update(&state, players[0..], &creatures, &bonuses, 1.0 / 60.0, 1024.0);
    try std.testing.expect(rng_before != state.rng.state);
}
