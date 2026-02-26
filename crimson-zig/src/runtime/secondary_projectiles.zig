const native_math = @import("native_math.zig");

const bonus_runtime = @import("bonuses.zig");
const creature_lifecycle = @import("lifecycle.zig").CreatureLifecycle;
const creatures_mod = @import("creatures.zig");
const owner_ref = @import("owner_ref.zig");
const runtime_helpers = @import("helpers.zig");
const state_mod = @import("state.zig");

const narrowF32 = native_math.roundF32;

pub const secondary_projectile_pool_size: usize = 0x40;

pub const SecondaryProjectileTypeId = enum(i32) {
    none = 0,
    rocket = 1,
    homing_rocket = 2,
    detonation = 3,
    rocket_minigun = 4,
};

pub const SecondaryProjectile = struct {
    active: bool = false,
    angle: f32 = 0.0,
    speed: f32 = 0.0,
    pos: state_mod.Vec2 = .{},
    vel: state_mod.Vec2 = .{},
    detonation_t: f32 = 0.0,
    detonation_scale: f32 = 1.0,
    type_id: SecondaryProjectileTypeId = .none,
    owner: owner_ref.OwnerRef = .{ .none = {} },
    trail_timer: f32 = 0.0,
    target_id: i32 = -1,
    target_hint_active: bool = false,
    target_hint: state_mod.Vec2 = .{},
};

pub const SecondaryProjectilePool = struct {
    entries: [secondary_projectile_pool_size]SecondaryProjectile = [_]SecondaryProjectile{.{}} ** secondary_projectile_pool_size,

    pub fn reset(self: *SecondaryProjectilePool) void {
        self.entries = [_]SecondaryProjectile{.{}} ** secondary_projectile_pool_size;
    }

    pub fn spawn(
        self: *SecondaryProjectilePool,
        pos: state_mod.Vec2,
        angle: f64,
        type_id: SecondaryProjectileTypeId,
        owner: owner_ref.OwnerRef,
        time_to_live: f64,
        target_hint: ?state_mod.Vec2,
        creatures: ?*const creatures_mod.CreaturePool,
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
            .angle = narrowF32(angle),
            .speed = narrowF32(time_to_live),
            .pos = .{
                .x = narrowF32(pos.x),
                .y = narrowF32(pos.y),
            },
            .vel = .{},
            .detonation_t = 0.0,
            .detonation_scale = 1.0,
            .type_id = type_id,
            .owner = owner,
            .trail_timer = 0.0,
            .target_id = -1,
            .target_hint_active = false,
            .target_hint = .{},
        };

        if (type_id == SecondaryProjectileTypeId.detonation) {
            entry.detonation_t = 0.0;
            entry.detonation_scale = narrowF32(time_to_live);
            entry.speed = narrowF32(time_to_live);
            return index;
        }

        var base_speed: f32 = 90.0;
        if (type_id == SecondaryProjectileTypeId.homing_rocket) {
            base_speed = 190.0;
        }
        entry.vel = runtime_helpers.directionFromHeading(entry.angle).mul(base_speed);
        entry.speed = narrowF32(time_to_live);

        if (type_id == SecondaryProjectileTypeId.homing_rocket) {
            if (creatures) |pool| {
                const origin = target_hint orelse pos;
                entry.target_id = @intCast(creatureFindNearestAlive(pool, origin));
            } else if (target_hint) |hint| {
                entry.target_hint_active = true;
                entry.target_hint = .{
                    .x = narrowF32(hint.x),
                    .y = narrowF32(hint.y),
                };
            }
        }

        return index;
    }

    pub fn updatePulseGun(
        self: *SecondaryProjectilePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        creatures: *creatures_mod.CreaturePool,
        bonuses: *bonus_runtime.BonusPool,
        dt: f64,
        world_size: f64,
        detail_preset: i32,
    ) void {
        if (!(dt > 0.0)) return;
        const dt_f32 = narrowF32(dt);
        const freeze_active = state.bonuses.freeze > 0.0;

        for (&self.entries) |*entry| {
            if (!entry.active) continue;

            if (entry.type_id == SecondaryProjectileTypeId.detonation) {
                state.camera_shake_pulses = 4;
                entry.detonation_t = narrowF32(entry.detonation_t + dt_f32 * 3.0);
                const t = entry.detonation_t;
                const scale = entry.detonation_scale;
                if (t > 1.0) {
                    entry.active = false;
                }

                const radius = narrowF32(scale * t * 80.0);
                const radius_sq = narrowF32(radius * radius);
                const damage = narrowF32(dt_f32 * scale * 700.0);
                var collidable_snapshot = [_]bool{false} ** creatures_mod.max_creatures;
                var candidate_snapshot = [_]bool{false} ** creatures_mod.max_creatures;
                var max_find_margin: f64 = 0.0;
                for (creatures.entries, 0..) |creature, idx| {
                    collidable_snapshot[idx] = creature.active and
                        creature_lifecycle.isCollidable(creature.lifecycle_stage);
                    if (!collidable_snapshot[idx]) continue;
                    const find_margin = narrowF32(creature.size * 0.14285715 + 3.0);
                    if (find_margin > max_find_margin) {
                        max_find_margin = find_margin;
                    }
                }
                const bucket_size: f64 = 64.0;
                const proj_cell_x: i32 = @intFromFloat(@floor(entry.pos.x / bucket_size));
                const proj_cell_y: i32 = @intFromFloat(@floor(entry.pos.y / bucket_size));
                const max_axis_delta = narrowF32(radius + max_find_margin + 0.001);
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
                    if (!creature_lifecycle.isCollidable(target.lifecycle_stage)) continue;
                    if (!(target.hp > 0.0)) continue;
                    const d_sq = runtime_helpers.distanceSqRoundedF32(entry.pos, target.pos);
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
                        entry.owner,
                        dt_f32,
                        world_size,
                        &killed_now,
                    );
                    if (hp_before > 0.0 and killed_now) {
                        if (!freeze_active) {
                            runtime_helpers.consumeAddRandomRng(state);
                            runtime_helpers.consumeAddRandomRng(state);
                        }
                        _ = creatures.handleSecondaryDetonationDeathFollowup(
                            state,
                            players,
                            bonuses,
                            idx,
                            entry.owner,
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
                .x = narrowF32(entry.pos.x + entry.vel.x * dt_f32),
                .y = narrowF32(entry.pos.y + entry.vel.y * dt_f32),
            };

            const speed_mag = entry.vel.length();
            if (entry.type_id == SecondaryProjectileTypeId.rocket) {
                if (speed_mag < 500.0) {
                    const factor = narrowF32(1.0 + dt_f32 * 3.0);
                    entry.vel = entry.vel.mul(factor);
                }
                entry.speed = narrowF32(entry.speed - dt_f32);
            } else if (entry.type_id == SecondaryProjectileTypeId.rocket_minigun) {
                if (speed_mag < 600.0) {
                    const factor = narrowF32(1.0 + dt_f32 * 4.0);
                    entry.vel = entry.vel.mul(factor);
                }
                entry.speed = narrowF32(entry.speed - dt_f32);
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
                    const to_target = state_mod.Vec2.sub(target.pos, entry.pos);
                    const dist = to_target.length();
                    if (dist > 1e-6) {
                        entry.angle = narrowF32(to_target.toHeading());
                        const inv_dist = narrowF32(1.0 / dist);
                        const target_dir = to_target.mul(inv_dist);
                        const accel = target_dir.mul(narrowF32(dt_f32 * 800.0));
                        const next_velocity = state_mod.Vec2.add(entry.vel, accel);
                        if (next_velocity.length() <= 350.0) {
                            entry.vel = .{
                                .x = narrowF32(next_velocity.x),
                                .y = narrowF32(next_velocity.y),
                            };
                        }
                    }
                }
                entry.speed = narrowF32(entry.speed - dt_f32 * 0.5);
            }

            const trail_decay = narrowF32((@abs(entry.vel.x) + @abs(entry.vel.y)) * dt_f32 * 0.01);
            entry.trail_timer = narrowF32(entry.trail_timer - trail_decay);
            if (entry.trail_timer < 0.0) {
                // `sprite_effects.spawn` consumes one rotation RNG draw.
                _ = state.rng.rand() % 0x274;
                entry.trail_timer = narrowF32(0.06);
            }

            var hit_idx: ?usize = null;
            for (creatures.entries, 0..) |creature, idx| {
                if (!creature.active) continue;
                if (!creature_lifecycle.isCollidable(creature.lifecycle_stage)) continue;
                if (runtime_helpers.withinNativeFindRadius(entry.pos, creature.pos, 8.0, creature.size)) {
                    hit_idx = idx;
                    break;
                }
            }
            if (hit_idx) |idx| {
                if (creature_lifecycle.isAlive(creatures.entries[idx].lifecycle_stage)) {
                    if (entry.owner.playerIndexInBounds(state.shots_hit.len)) |player_idx| {
                        state.shots_hit[player_idx] += 1;
                    }
                }

                const hit_type = @intFromEnum(entry.type_id);
                const det_scale: f64 = switch (entry.type_id) {
                    SecondaryProjectileTypeId.rocket => 1.0,
                    SecondaryProjectileTypeId.homing_rocket => 0.35,
                    SecondaryProjectileTypeId.rocket_minigun => 0.25,
                    else => 0.5,
                };

                if (freeze_active) {
                    for (0..4) |_| {
                        _ = state.rng.rand() % 0x264;
                        runtime_helpers.consumeFreezeShardRng(state);
                    }
                } else {
                    for (0..3) |_| {
                        _ = state.rng.rand() % 0x14;
                        _ = state.rng.rand() % 0x14;
                        runtime_helpers.consumeAddRandomRng(state);
                    }
                }

                if (entry.type_id == SecondaryProjectileTypeId.rocket and detail_preset > 2) {
                    consumeExplosionBurstRng(state, detail_preset);
                }

                const damage: f64 = switch (entry.type_id) {
                    SecondaryProjectileTypeId.rocket => narrowF32(entry.speed * 50.0 + 500.0),
                    SecondaryProjectileTypeId.homing_rocket => narrowF32(entry.speed * 20.0 + 80.0),
                    SecondaryProjectileTypeId.rocket_minigun => narrowF32(entry.speed * 20.0 + 40.0),
                    else => 150.0,
                };
                _ = creatures.applyExplosionDamage(
                    state,
                    players,
                    bonuses,
                    idx,
                    damage,
                    .{
                        .x = narrowF32(entry.vel.x / dt_f32),
                        .y = narrowF32(entry.vel.y / dt_f32),
                    },
                    entry.owner,
                    dt_f32,
                    world_size,
                    null,
                );

                entry.type_id = SecondaryProjectileTypeId.detonation;
                entry.vel = .{};
                entry.detonation_t = 0.0;
                entry.detonation_scale = narrowF32(det_scale);
                entry.trail_timer = 0.0;

                if (freeze_active) {
                    for (0..8) |_| {
                        _ = state.rng.rand() % 0x264;
                        runtime_helpers.consumeFreezeShardRng(state);
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
                        runtime_helpers.consumeAddRandomRng(state);
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

fn directionTo(origin: state_mod.Vec2, target: state_mod.Vec2) state_mod.Vec2 {
    const delta = state_mod.Vec2.sub(target, origin);
    const len = delta.length();
    if (!(len > 1e-6)) return .{};
    return .{
        .x = narrowF32(delta.x / len),
        .y = narrowF32(delta.y / len),
    };
}

fn creatureFindNearestAlive(
    creatures: *const creatures_mod.CreaturePool,
    origin: state_mod.Vec2,
) usize {
    var best_idx: usize = 0;
    var best_dist_sq: f64 = 1_000_000.0;
    const limit: usize = @min(creatures.entries.len, 0x180);
    for (creatures.entries[0..limit], 0..) |creature, idx| {
        if (!creature.active) continue;
        if (!creature_lifecycle.isAlive(creature.lifecycle_stage)) continue;
        const dist_sq = runtime_helpers.distanceSqRoundedF32(origin, creature.pos);
        if (dist_sq < best_dist_sq) {
            best_dist_sq = dist_sq;
            best_idx = idx;
        }
    }
    return best_idx;
}

fn consumeExplosionBurstRng(
    state: *state_mod.GameplayState,
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
