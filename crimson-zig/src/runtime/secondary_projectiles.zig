const std = @import("std");
const native_math = @import("native_math.zig");

const survival_bonuses = @import("bonuses.zig");
const survival_creatures = @import("creatures.zig");
const survival_state = @import("state.zig");
const survival_math = @import("math.zig");

const asF32F64 = native_math.roundF32;

pub const secondary_projectile_pool_size: usize = 0x40;
const creature_lifecycle_stage_alive: f64 = 16.0;

pub const SecondaryProjectileTypeId = struct {
    pub const none: i32 = 0;
    pub const rocket: i32 = 1;
    pub const homing_rocket: i32 = 2;
    pub const detonation: i32 = 3;
    pub const rocket_minigun: i32 = 4;
};

pub const SecondaryProjectile = struct {
    active: bool = false,
    angle: f32 = 0.0,
    speed: f32 = 0.0,
    pos: survival_state.Vec2 = .{},
    vel: survival_state.Vec2 = .{},
    detonation_t: f32 = 0.0,
    detonation_scale: f32 = 1.0,
    type_id: i32 = 0,
    owner_id: i32 = -100,
    trail_timer: f32 = 0.0,
    target_id: i32 = -1,
    target_hint_active: bool = false,
    target_hint: survival_state.Vec2 = .{},
};

pub const SecondaryProjectilePool = struct {
    entries: [secondary_projectile_pool_size]SecondaryProjectile = [_]SecondaryProjectile{.{}} ** secondary_projectile_pool_size,

    pub fn reset(self: *SecondaryProjectilePool) void {
        self.entries = [_]SecondaryProjectile{.{}} ** secondary_projectile_pool_size;
    }

    pub fn spawn(
        self: *SecondaryProjectilePool,
        pos: survival_state.Vec2,
        angle: f64,
        type_id: i32,
        owner_id: i32,
        time_to_live: f64,
        target_hint: ?survival_state.Vec2,
        creatures: ?*const survival_creatures.CreaturePool,
    ) usize {
        var index: usize = self.entries.len - 1;
        for (self.entries, 0..) |entry, idx| {
            if (!entry.active) {
                index = idx;
                break;
            }
        }

        var entry = &self.entries[index];
        entry.* = .{
            .active = true,
            .angle = asF32F64(angle),
            .speed = asF32F64(time_to_live),
            .pos = .{
                .x = asF32F64(pos.x),
                .y = asF32F64(pos.y),
            },
            .vel = .{},
            .detonation_t = 0.0,
            .detonation_scale = 1.0,
            .type_id = type_id,
            .owner_id = owner_id,
            .trail_timer = 0.0,
            .target_id = -1,
            .target_hint_active = false,
            .target_hint = .{},
        };

        if (type_id == SecondaryProjectileTypeId.detonation) {
            entry.detonation_t = 0.0;
            entry.detonation_scale = asF32F64(time_to_live);
            entry.speed = asF32F64(time_to_live);
            return index;
        }

        var base_speed: f32 = 90.0;
        if (type_id == SecondaryProjectileTypeId.homing_rocket) {
            base_speed = 190.0;
        }
        entry.vel = directionFromHeading(entry.angle).mul(base_speed);
        entry.speed = asF32F64(time_to_live);

        if (type_id == SecondaryProjectileTypeId.homing_rocket) {
            if (creatures) |pool| {
                const origin = target_hint orelse pos;
                entry.target_id = @intCast(creatureFindNearestAlive(pool, origin));
            } else if (target_hint) |hint| {
                entry.target_hint_active = true;
                entry.target_hint = .{
                    .x = asF32F64(hint.x),
                    .y = asF32F64(hint.y),
                };
            }
        }

        return index;
    }

    pub fn updatePulseGun(
        self: *SecondaryProjectilePool,
        state: *survival_state.GameplayState,
        players: []survival_state.PlayerState,
        creatures: *survival_creatures.CreaturePool,
        bonuses: *survival_bonuses.BonusPool,
        dt: f64,
        world_size: f64,
        detail_preset: i32,
    ) void {
        if (!(dt > 0.0)) return;
        const dt_f32 = asF32F64(dt);
        const freeze_active = state.bonuses.freeze > 0.0;

        for (&self.entries, 0..) |*entry, secondary_idx| {
            _ = secondary_idx;
            if (!entry.active) continue;

            if (entry.type_id == SecondaryProjectileTypeId.detonation) {
                state.camera_shake_pulses = 4;
                entry.detonation_t = asF32F64(entry.detonation_t + dt_f32 * 3.0);
                const t = entry.detonation_t;
                const scale = entry.detonation_scale;
                if (t > 1.0) {
                    entry.active = false;
                }

                const radius = asF32F64(scale * t * 80.0);
                const radius_sq = asF32F64(radius * radius);
                const damage = asF32F64(dt_f32 * scale * 700.0);
                var collidable_snapshot = [_]bool{false} ** survival_creatures.max_creatures;
                var candidate_snapshot = [_]bool{false} ** survival_creatures.max_creatures;
                var max_find_margin: f64 = 0.0;
                for (creatures.entries, 0..) |creature, idx| {
                    collidable_snapshot[idx] = creature.active and
                        creature.lifecycle_stage > 5.0;
                    if (!collidable_snapshot[idx]) continue;
                    const find_margin = asF32F64(creature.size * 0.14285715 + 3.0);
                    if (find_margin > max_find_margin) {
                        max_find_margin = find_margin;
                    }
                }
                const bucket_size: f64 = 64.0;
                const proj_cell_x: i32 = @intFromFloat(@floor(entry.pos.x / bucket_size));
                const proj_cell_y: i32 = @intFromFloat(@floor(entry.pos.y / bucket_size));
                const max_axis_delta = asF32F64(radius + max_find_margin + 0.001);
                const cell_span: i32 = @intFromFloat(@ceil(max_axis_delta / bucket_size));
                for (creatures.entries, 0..) |creature, idx| {
                    if (!collidable_snapshot[idx]) continue;
                    const cell_x: i32 = @intFromFloat(@floor(creature.pos.x / bucket_size));
                    const cell_y: i32 = @intFromFloat(@floor(creature.pos.y / bucket_size));
                    candidate_snapshot[idx] =
                        @abs(cell_x - proj_cell_x) <= cell_span and
                        @abs(cell_y - proj_cell_y) <= cell_span;
                }

                for (creatures.entries, 0..) |_, idx| {
                    if (!candidate_snapshot[idx]) continue;
                    const target = creatures.entries[idx];
                    if (!target.active) continue;
                    if (!(target.lifecycle_stage > 5.0)) continue;
                    if (!(target.hp > 0.0)) continue;
                    const d_sq = distanceSq(entry.pos, target.pos);
                    if (!(d_sq < radius_sq)) continue;
                    const hp_before = target.hp;
                    const impulse = directionTo(entry.pos, target.pos).mul(0.1);
                    var killed_now = false;
                    _ = creatures.applyExplosionDamage(
                        state,
                        players,
                        bonuses,
                        idx,
                        damage,
                        impulse,
                        entry.owner_id,
                        dt_f32,
                        world_size,
                        &killed_now,
                    );
                    if (hp_before > 0.0 and killed_now) {
                        if (!freeze_active) {
                            consumeAddRandomRng(state);
                            consumeAddRandomRng(state);
                        }
                        _ = creatures.handleSecondaryDetonationDeathFollowup(
                            state,
                            players,
                            bonuses,
                            idx,
                            entry.owner_id,
                            dt_f32,
                            world_size,
                        );
                    }
                }
                continue;
            }

            if (entry.type_id != SecondaryProjectileTypeId.rocket and
                entry.type_id != SecondaryProjectileTypeId.homing_rocket and
                entry.type_id != SecondaryProjectileTypeId.rocket_minigun)
            {
                continue;
            }

            entry.pos = .{
                .x = asF32F64(entry.pos.x + entry.vel.x * dt_f32),
                .y = asF32F64(entry.pos.y + entry.vel.y * dt_f32),
            };

            const speed_mag = entry.vel.length();
            if (entry.type_id == SecondaryProjectileTypeId.rocket) {
                if (speed_mag < 500.0) {
                    const factor = asF32F64(1.0 + dt_f32 * 3.0);
                    entry.vel = entry.vel.mul(factor);
                }
                entry.speed = asF32F64(entry.speed - dt_f32);
            } else if (entry.type_id == SecondaryProjectileTypeId.rocket_minigun) {
                if (speed_mag < 600.0) {
                    const factor = asF32F64(1.0 + dt_f32 * 4.0);
                    entry.vel = entry.vel.mul(factor);
                }
                entry.speed = asF32F64(entry.speed - dt_f32);
            } else {
                var target_id = entry.target_id;
                if (!(target_id >= 0 and target_id < creatures.entries.len) or
                    !creatures.entries[@intCast(target_id)].active)
                {
                    var search_pos = entry.pos;
                    if (entry.target_hint_active) {
                        entry.target_hint_active = false;
                        search_pos = entry.target_hint;
                    }
                    const nearest = creatureFindNearestAlive(creatures, search_pos);
                    entry.target_id = @intCast(nearest);
                    target_id = entry.target_id;
                }

                if (target_id >= 0 and target_id < creatures.entries.len) {
                    const target = creatures.entries[@intCast(target_id)];
                    const to_target = survival_state.Vec2.sub(target.pos, entry.pos);
                    const dist = to_target.length();
                    if (dist > 1e-6) {
                        entry.angle = asF32F64(to_target.toHeading());
                        const inv_dist = asF32F64(1.0 / dist);
                        const target_dir = to_target.mul(inv_dist);
                        const accel = target_dir.mul(asF32F64(dt_f32 * 800.0));
                        const next_velocity = survival_state.Vec2.add(entry.vel, accel);
                        if (next_velocity.length() <= 350.0) {
                            entry.vel = .{
                                .x = asF32F64(next_velocity.x),
                                .y = asF32F64(next_velocity.y),
                            };
                        }
                    }
                }
                entry.speed = asF32F64(entry.speed - dt_f32 * 0.5);
            }

            const trail_decay = asF32F64((@abs(entry.vel.x) + @abs(entry.vel.y)) * dt_f32 * 0.01);
            entry.trail_timer = asF32F64(entry.trail_timer - trail_decay);
            if (entry.trail_timer < 0.0) {
                // `sprite_effects.spawn` consumes one rotation RNG draw.
                _ = state.rng.rand() % 0x274;
                entry.trail_timer = asF32F64(0.06);
            }

            var hit_idx: ?usize = null;
            for (creatures.entries, 0..) |creature, idx| {
                if (!creature.active) continue;
                if (!(creature.lifecycle_stage > 5.0)) continue;
                if (withinNativeFindRadius(entry.pos, creature.pos, 8.0, creature.size)) {
                    hit_idx = idx;
                    break;
                }
            }
            if (hit_idx) |idx| {
                if (entry.owner_id < 0 and creatures.entries[idx].lifecycle_stage == creature_lifecycle_stage_alive) {
                    const player_idx = if (entry.owner_id == -100) @as(i32, 0) else -1 - entry.owner_id;
                    if (player_idx >= 0 and player_idx < state.shots_hit.len) {
                        state.shots_hit[@intCast(player_idx)] += 1;
                    }
                }

                const hit_type = entry.type_id;
                const det_scale: f64 = switch (entry.type_id) {
                    SecondaryProjectileTypeId.rocket => 1.0,
                    SecondaryProjectileTypeId.homing_rocket => 0.35,
                    SecondaryProjectileTypeId.rocket_minigun => 0.25,
                    else => 0.5,
                };

                if (freeze_active) {
                    for (0..4) |_| {
                        _ = state.rng.rand() % 0x264;
                        consumeFreezeShardRng(state);
                    }
                } else {
                    for (0..3) |_| {
                        _ = state.rng.rand() % 0x14;
                        _ = state.rng.rand() % 0x14;
                        consumeAddRandomRng(state);
                    }
                }

                if (entry.type_id == SecondaryProjectileTypeId.rocket and detail_preset > 2) {
                    consumeExplosionBurstRng(state, detail_preset);
                }

                const damage: f64 = switch (entry.type_id) {
                    SecondaryProjectileTypeId.rocket => asF32F64(entry.speed * 50.0 + 500.0),
                    SecondaryProjectileTypeId.homing_rocket => asF32F64(entry.speed * 20.0 + 80.0),
                    SecondaryProjectileTypeId.rocket_minigun => asF32F64(entry.speed * 20.0 + 40.0),
                    else => 150.0,
                };
                _ = creatures.applyExplosionDamage(
                    state,
                    players,
                    bonuses,
                    idx,
                    damage,
                    .{
                        .x = asF32F64(entry.vel.x / dt_f32),
                        .y = asF32F64(entry.vel.y / dt_f32),
                    },
                    entry.owner_id,
                    dt_f32,
                    world_size,
                    null,
                );

                entry.type_id = SecondaryProjectileTypeId.detonation;
                entry.vel = .{};
                entry.detonation_t = 0.0;
                entry.detonation_scale = asF32F64(det_scale);
                entry.trail_timer = 0.0;

                if (freeze_active) {
                    for (0..8) |_| {
                        _ = state.rng.rand() % 0x264;
                        consumeFreezeShardRng(state);
                    }
                } else {
                    const extra_decals: i32 = if (det_scale == 1.0)
                        0x14
                    else if (det_scale == 0.35)
                        10
                    else if (det_scale == 0.25)
                        3
                    else
                        0;
                    const extra_radius: i32 = if (det_scale == 1.0)
                        90
                    else if (det_scale == 0.35)
                        64
                    else if (det_scale == 0.25)
                        44
                    else
                        0;
                    var i: i32 = 0;
                    while (i < extra_decals) : (i += 1) {
                        _ = state.rng.rand() % 0x274;
                        if (det_scale == 0.35) {
                            _ = state.rng.rand() & 0x3f;
                        } else {
                            const radius_mod = @max(extra_radius, 1);
                            _ = state.rng.rand() % @as(u32, @intCast(radius_mod));
                        }
                        consumeAddRandomRng(state);
                    }
                }

                for (0..10) |_| {
                    _ = state.rng.rand() % 800;
                    // Each sprite spawn consumes one rotation RNG draw.
                    _ = state.rng.rand() % 0x274;
                }

                _ = hit_type;
                continue;
            }

            if (entry.speed < 0.0) {
                entry.type_id = SecondaryProjectileTypeId.detonation;
                entry.vel = .{};
                entry.detonation_t = 0.0;
                entry.detonation_scale = 0.5;
                entry.trail_timer = 0.0;
            }
        }

    }
};

fn directionFromHeading(heading: f32) survival_state.Vec2 {
    const radians = asF32F64(heading - std.math.pi / 2.0);
    return .{
        .x = asF32F64(survival_math.cos(radians)),
        .y = asF32F64(survival_math.sin(radians)),
    };
}

fn directionTo(origin: survival_state.Vec2, target: survival_state.Vec2) survival_state.Vec2 {
    const delta = survival_state.Vec2.sub(target, origin);
    const len = delta.length();
    if (!(len > 1e-6)) return .{};
    return .{
        .x = asF32F64(delta.x / len),
        .y = asF32F64(delta.y / len),
    };
}

fn creatureFindNearestAlive(
    creatures: *const survival_creatures.CreaturePool,
    origin: survival_state.Vec2,
) usize {
    var best_idx: usize = 0;
    var best_dist_sq: f64 = 1_000_000.0;
    const limit: usize = @min(creatures.entries.len, 0x180);
    for (creatures.entries[0..limit], 0..) |creature, idx| {
        if (!creature.active) continue;
        if (!(creature.lifecycle_stage == creature_lifecycle_stage_alive)) continue;
        const dist_sq = distanceSq(origin, creature.pos);
        if (dist_sq < best_dist_sq) {
            best_dist_sq = dist_sq;
            best_idx = idx;
        }
    }
    return best_idx;
}

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

fn distanceSq(a: survival_state.Vec2, b: survival_state.Vec2) f64 {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    return asF32F64(dx * dx + dy * dy);
}

fn consumeAddRandomRng(state: *survival_state.GameplayState) void {
    _ = state.rng.rand();
    _ = state.rng.rand();
    _ = state.rng.rand();
    _ = state.rng.rand();
}

fn consumeFreezeShardRng(state: *survival_state.GameplayState) void {
    _ = state.rng.rand();
    _ = state.rng.rand();
    _ = state.rng.rand();
    _ = state.rng.rand();
    _ = state.rng.rand();
    _ = state.rng.rand();
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
