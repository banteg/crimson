const std = @import("std");

const survival_bonuses = @import("survival_bonuses.zig");
const survival_creatures = @import("survival_creatures.zig");
const survival_state = @import("survival_state.zig");

pub const main_projectile_pool_size: usize = 0x60;
const creature_hitbox_alive: f64 = 16.0;
const perk_id_poison_bullets: i32 = 25;

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
            .vel = survival_state.Vec2.fromAngle(angle).mul(1.5),
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
        var hit_audio_game_tune_started = state.game_tune_started;
        var tick_stats = ProjectileTickStats{};

        for (&self.entries, 0..) |*proj, proj_idx| {
            if (!proj.active) continue;

            if (proj.life_timer <= 0.0) {
                proj.active = false;
            }

            if (proj.life_timer < 0.4) {
                proj.life_timer = asF32F64(proj.life_timer - dt);
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
            const direction = survival_state.Vec2.fromAngle(proj.angle);
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
                    if (!(creature.hitbox_size > 5.0)) continue;
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
                const owner_player = if (owner_player_idx) |idx| &players[idx] else if (players.len > 0) &players[0] else null;

                if (owner_player) |player| {
                    if (perkActive(player, perk_id_poison_bullets)) {
                        _ = state.rng.rand();
                    }
                    survival_creatures.consumeProjectileHitPresentationPreRng(
                        state,
                        player,
                        proj.type_id,
                    );
                }

                if (owner_player_idx) |idx| {
                    if (idx < state.shots_hit.len and creatures.entries[hit_idx.?].hitbox_size == creature_hitbox_alive) {
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

                var dist = survival_state.Vec2.sub(proj.origin, proj.pos).length();
                if (dist < 50.0) dist = 50.0;
                const damage_scale = survival_state.weaponDamageScale(proj.type_id);
                const damage_amount = asF32F64(((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95);

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
                            proj.owner_id,
                            dt,
                            world_size,
                        );
                        proj.damage_pool -= creatures.entries[hit_idx.?].hp;
                    }
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
                    if (owner_player != null) {
                        survival_creatures.consumeProjectileHitPresentationPostRng(
                            state,
                            proj.type_id,
                        );
                        survival_creatures.consumeHitSfxRng(
                            state,
                            &hit_audio_game_tune_started,
                        );
                    }
                    break;
                }
                if (owner_player != null) {
                    survival_creatures.consumeProjectileHitPresentationPostRng(
                        state,
                        proj.type_id,
                    );
                    survival_creatures.consumeHitSfxRng(
                        state,
                        &hit_audio_game_tune_started,
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
    creatures.spawnInit(.{
        .origin_template_id = -1,
        .pos = .{ .x = 180.0, .y = 100.0 },
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
    pool.update(&state, players[0..], &creatures, &bonuses, 1.0 / 60.0, 1024.0);
    try std.testing.expect(rng_before != state.rng.state);
}
