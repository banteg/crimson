const native_math = @import("native_math.zig");

const bonus_runtime = @import("bonuses.zig");
const creature_lifecycle = @import("lifecycle.zig").CreatureLifecycle;
const creatures_mod = @import("creatures.zig");
const effects_mod = @import("effects.zig");
const owner_ref = @import("owner_ref.zig");
const rng_callers = @import("../rng_caller_static.zig");
const runtime_helpers = @import("helpers.zig");
const state_mod = @import("state.zig");
const terrain_fx_mod = @import("terrain_fx.zig");

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
        angle: f32,
        type_id: SecondaryProjectileTypeId,
        owner: owner_ref.OwnerRef,
        time_to_live: f32,
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
            .angle = angle,
            .speed = time_to_live,
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
            entry.detonation_scale = time_to_live;
            entry.speed = time_to_live;
            return index;
        }

        var base_speed: f32 = 90.0;
        if (type_id == SecondaryProjectileTypeId.homing_rocket) {
            base_speed = 190.0;
        }
        entry.vel = runtime_helpers.directionFromHeading(entry.angle).mul(base_speed);
        entry.speed = time_to_live;

        if (type_id == SecondaryProjectileTypeId.homing_rocket) {
            if (creatures) |pool| {
                const origin = target_hint orelse pos;
                entry.target_id = @intCast(creatureFindNearestAlive(pool, origin));
            } else if (target_hint) |hint| {
                entry.target_hint_active = true;
                entry.target_hint = .{
                    .x = hint.x,
                    .y = hint.y,
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
        dt: f32,
        world_size: f32,
        detail_preset: i32,
    ) void {
        var effects: effects_mod.EffectPool = .{};
        var sprite_effects: effects_mod.SpriteEffectPool = .{};
        var terrain_fx: terrain_fx_mod.TerrainFxScratch = .{};
        self.updatePulseGunWithEffects(
            state,
            players,
            creatures,
            bonuses,
            &effects,
            &sprite_effects,
            &terrain_fx,
            dt,
            world_size,
            detail_preset,
        );
    }

    pub fn updatePulseGunWithEffects(
        self: *SecondaryProjectilePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        creatures: *creatures_mod.CreaturePool,
        bonuses: *bonus_runtime.BonusPool,
        effects: *effects_mod.EffectPool,
        sprite_effects: *effects_mod.SpriteEffectPool,
        terrain_fx: *terrain_fx_mod.TerrainFxScratch,
        dt: f32,
        world_size: f32,
        detail_preset: i32,
    ) void {
        if (!(dt > 0.0)) return;
        const dt_f32 = dt;
        const freeze_active = state.bonuses.freeze > 0.0;

        for (&self.entries) |*entry| {
            if (!entry.active) continue;

            if (entry.type_id == SecondaryProjectileTypeId.detonation) {
                state.camera_shake_pulses = 4;
                entry.detonation_t = narrowF32(entry.detonation_t + dt_f32 * 3.0);
                const t = entry.detonation_t;
                const scale = entry.detonation_scale;
                if (t > 1.0) {
                    _ = terrain_fx.decals.add(
                        @intFromEnum(effects_mod.EffectId.aura),
                        entry.pos,
                        scale * 256.0,
                        scale * 256.0,
                        0.0,
                        .{ .r = 0.0, .g = 0.0, .b = 0.0, .a = 0.25 },
                    );
                    entry.active = false;
                }

                const radius = narrowF32(scale * t * 80.0);
                const radius_sq = narrowF32(radius * radius);
                const damage = narrowF32(dt_f32 * scale * 700.0);
                var collidable_snapshot = [_]bool{false} ** creatures_mod.max_creatures;
                var candidate_snapshot = [_]bool{false} ** creatures_mod.max_creatures;
                var max_find_margin: f32 = 0.0;
                for (creatures.entries, 0..) |creature, idx| {
                    collidable_snapshot[idx] = creature.active and
                        creature_lifecycle.isCollidable(creature.lifecycle_stage);
                    if (!collidable_snapshot[idx]) continue;
                    const find_margin = narrowF32(creature.size * 0.14285715 + 3.0);
                    if (find_margin > max_find_margin) {
                        max_find_margin = find_margin;
                    }
                }
                const bucket_size: f32 = 64.0;
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
                        terrain_fx,
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
                            _ = terrain_fx.decals.addRandom(state, target.pos);
                            _ = terrain_fx.decals.addRandom(state, target.pos);
                        }
                        _ = creatures.handleSecondaryDetonationDeathFollowup(
                            state,
                            players,
                            bonuses,
                            terrain_fx,
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
                const direction = runtime_helpers.directionFromHeading(entry.angle);
                const spawn_pos = state_mod.Vec2.sub(entry.pos, direction.mul(9.0));
                // Native bug: both trail velocity components come from cosine
                // (fcos with no fsin), so the smoke drifts diagonally.
                const trail_cos = @cos(entry.angle + narrowF32(native_math.native_half_pi));
                const trail_velocity: state_mod.Vec2 = .{
                    .x = narrowF32(trail_cos) * 90.0,
                    .y = narrowF32(trail_cos * 90.0),
                };
                _ = sprite_effects.spawn(
                    state,
                    spawn_pos,
                    trail_velocity,
                    14.0,
                    .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 0.25 },
                );
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
                const det_scale: f32 = switch (entry.type_id) {
                    SecondaryProjectileTypeId.rocket => 1.0,
                    SecondaryProjectileTypeId.homing_rocket => 0.35,
                    SecondaryProjectileTypeId.rocket_minigun => 0.25,
                    else => 0.5,
                };

                if (freeze_active) {
                    const freeze_angle_caller: rng_callers.Caller = switch (entry.type_id) {
                        .rocket => rng_callers.secondary_projectile_update_rocket_freeze_shard_angle,
                        .homing_rocket => rng_callers.secondary_projectile_update_seeker_rocket_freeze_shard_angle,
                        .rocket_minigun => rng_callers.secondary_projectile_update_rocket_minigun_freeze_shard_angle,
                        else => rng_callers.secondary_projectile_update_pre_hit_freeze_shard_angle,
                    };
                    for (0..4) |_| {
                        const shard_angle = @as(f32, @floatFromInt(state.rng.randTagged(freeze_angle_caller) % 612)) * 0.01;
                        effects.spawnFreezeShard(state, entry.pos, shard_angle, detail_preset);
                    }
                } else {
                    const offset_1: state_mod.Vec2 = .{
                        .x = @as(f32, @floatFromInt(@as(i32, @intCast(state.rng.randTagged(rng_callers.secondary_projectile_update_pre_hit_decal_dx_1) % 20)) - 10)),
                        .y = @as(f32, @floatFromInt(@as(i32, @intCast(state.rng.randTagged(rng_callers.secondary_projectile_update_pre_hit_decal_dy_1) % 20)) - 10)),
                    };
                    _ = terrain_fx.decals.addRandom(state, state_mod.Vec2.add(creatures.entries[idx].pos, offset_1));
                    const offset_2: state_mod.Vec2 = .{
                        .x = @as(f32, @floatFromInt(@as(i32, @intCast(state.rng.randTagged(rng_callers.secondary_projectile_update_pre_hit_decal_dx_2) % 20)) - 10)),
                        .y = @as(f32, @floatFromInt(@as(i32, @intCast(state.rng.randTagged(rng_callers.secondary_projectile_update_pre_hit_decal_dy_2) % 20)) - 10)),
                    };
                    _ = terrain_fx.decals.addRandom(state, state_mod.Vec2.add(creatures.entries[idx].pos, offset_2));
                    const offset_3: state_mod.Vec2 = .{
                        .x = @as(f32, @floatFromInt(@as(i32, @intCast(state.rng.randTagged(rng_callers.secondary_projectile_update_pre_hit_decal_dx_3) % 20)) - 10)),
                        .y = @as(f32, @floatFromInt(@as(i32, @intCast(state.rng.randTagged(rng_callers.secondary_projectile_update_pre_hit_decal_dy_3) % 20)) - 10)),
                    };
                    _ = terrain_fx.decals.addRandom(state, state_mod.Vec2.add(creatures.entries[idx].pos, offset_3));
                }

                if (entry.type_id == SecondaryProjectileTypeId.rocket and detail_preset > 2) {
                    effects.spawnExplosionBurst(state, entry.pos, 1.0, detail_preset);
                }

                const damage: f32 = switch (entry.type_id) {
                    SecondaryProjectileTypeId.rocket => narrowF32(entry.speed * 50.0 + 500.0),
                    SecondaryProjectileTypeId.homing_rocket => narrowF32(entry.speed * 20.0 + 80.0),
                    SecondaryProjectileTypeId.rocket_minigun => narrowF32(entry.speed * 20.0 + 40.0),
                    else => 150.0,
                };
                _ = creatures.applyExplosionDamage(
                    state,
                    players,
                    bonuses,
                    terrain_fx,
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
                // Native secondary-rocket hits run the same first-hit game-tune
                // branch as bullet hits (one playlist rand) outside demo/rush.
                if (!state.demo_mode_active and state.game_mode != .rush and !state.game_tune_started) {
                    state.game_tune_started = true;
                    _ = state.rng.randTagged(rng_callers.sfx_play_exclusive_playlist_pick);
                } else {
                    state.sfx_queue.append(.explosion_medium);
                }

                if (freeze_active) {
                    const freeze_angle_caller: rng_callers.Caller = switch (entry.type_id) {
                        .rocket => rng_callers.secondary_projectile_update_rocket_freeze_shard_angle,
                        .homing_rocket => rng_callers.secondary_projectile_update_seeker_rocket_freeze_shard_angle,
                        .rocket_minigun => rng_callers.secondary_projectile_update_rocket_minigun_freeze_shard_angle,
                        else => rng_callers.secondary_projectile_update_pre_hit_freeze_shard_angle,
                    };
                    for (0..8) |_| {
                        const shard_angle = @as(f32, @floatFromInt(state.rng.randTagged(freeze_angle_caller) % 612)) * 0.01;
                        effects.spawnFreezeShard(state, entry.pos, shard_angle, detail_preset);
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
                    const angle_caller: rng_callers.Caller = switch (entry.type_id) {
                        .rocket => rng_callers.secondary_projectile_update_rocket_decal_angle,
                        .homing_rocket => rng_callers.secondary_projectile_update_seeker_rocket_decal_angle,
                        .rocket_minigun => rng_callers.secondary_projectile_update_rocket_minigun_decal_angle,
                        else => rng_callers.secondary_projectile_update_rocket_decal_angle,
                    };
                    const radius_caller: rng_callers.Caller = switch (entry.type_id) {
                        .rocket => rng_callers.secondary_projectile_update_rocket_decal_radius,
                        .homing_rocket => rng_callers.secondary_projectile_update_seeker_rocket_decal_radius,
                        .rocket_minigun => rng_callers.secondary_projectile_update_rocket_minigun_decal_radius,
                        else => rng_callers.secondary_projectile_update_rocket_decal_radius,
                    };
                    var i: i32 = 0;
                    while (i < extra_decals) : (i += 1) {
                        const angle = @as(f32, @floatFromInt(state.rng.randTagged(angle_caller) % 0x274)) * 0.01;
                        if (det_scale == 0.35) {
                            const radius = @as(f32, @floatFromInt(state.rng.randTagged(radius_caller) & 0x3F));
                            const pos = state_mod.Vec2.add(creatures.entries[idx].pos, state_mod.Vec2.fromAngle(angle).mul(radius));
                            _ = terrain_fx.decals.addRandom(state, pos);
                        } else {
                            const radius_mod = @max(extra_radius, 1);
                            const radius = state.rng.randTagged(radius_caller) % @as(u32, @intCast(radius_mod));
                            const pos = state_mod.Vec2.add(creatures.entries[idx].pos, state_mod.Vec2.fromAngle(angle).mul(@floatFromInt(radius)));
                            _ = terrain_fx.decals.addRandom(state, pos);
                        }
                    }
                }

                for (0..10) |sprite_idx| {
                    const mag = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.secondary_projectile_update_detonation_sprite_mag) % 800)) * 0.1;
                    const ang = @as(f32, @floatFromInt(sprite_idx)) * (native_math.native_tau / 10.0);
                    _ = sprite_effects.spawn(
                        state,
                        entry.pos,
                        state_mod.Vec2.fromAngle(ang).mul(mag),
                        16.0,
                        .{ .r = 1.0, .g = 0.5, .b = 0.2, .a = 0.35 },
                    );
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
                state.sfx_queue.append(.explosion_medium);
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
    // Native seeds best with 1e6 and compares plain distances, so the search
    // is effectively unbounded on a 1024 map; square it for the squared compare.
    var best_dist_sq: f32 = 1e12;
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
