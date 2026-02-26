const std = @import("std");
const native_math = @import("native_math.zig");

const bonus_runtime = @import("bonuses.zig");
const creature_lifecycle = @import("lifecycle.zig").CreatureLifecycle;
const creatures_mod = @import("creatures.zig");
const owner_ref = @import("owner_ref.zig");
const runtime_helpers = @import("helpers.zig");
const state_mod = @import("state.zig");

const narrowF32 = native_math.roundF32;

pub const particle_pool_size: usize = 0x80;

pub const ParticleStyleId = enum(i32) {
    flamethrower = 0,
    blow_torch = 1,
    hr_flamer = 2,
    bubblegun = 8,
};

pub const Particle = struct {
    active: bool = false,
    render_flag: bool = false,
    pos: state_mod.Vec2 = .{},
    vel: state_mod.Vec2 = .{},
    scale_x: f32 = 1.0,
    scale_y: f32 = 1.0,
    scale_z: f32 = 1.0,
    age: f32 = 0.0,
    intensity: f32 = 0.0,
    angle: f32 = 0.0,
    spin: f32 = 0.0,
    style_id: ParticleStyleId = .flamethrower,
    target_id: i32 = -1,
    owner: owner_ref.OwnerRef = .{ .none = {} },
};

pub const ParticlePool = struct {
    entries: [particle_pool_size]Particle = [_]Particle{.{}} ** particle_pool_size,

    pub fn reset(self: *ParticlePool) void {
        self.entries = [_]Particle{.{}} ** particle_pool_size;
    }

    pub fn spawnParticle(
        self: *ParticlePool,
        state: *state_mod.GameplayState,
        pos: state_mod.Vec2,
        angle: f64,
        intensity: f64,
        owner: owner_ref.OwnerRef,
    ) usize {
        const index = self.allocSlot(state);
        const entry = &self.entries[index];
        entry.* = .{
            .active = true,
            .render_flag = true,
            .pos = .{
                .x = narrowF32(pos.x),
                .y = narrowF32(pos.y),
            },
            .vel = runtime_helpers.directionFromAngle(narrowF32(angle)).mul(90.0),
            .scale_x = 1.0,
            .scale_y = 1.0,
            .scale_z = 1.0,
            .age = 0.0,
            .intensity = narrowF32(intensity),
            .angle = narrowF32(angle),
            .spin = narrowF32(@as(f64, @floatFromInt(state.rng.rand() % 0x274)) * 0.01),
            .style_id = ParticleStyleId.flamethrower,
            .target_id = -1,
            .owner = owner,
        };
        return index;
    }

    pub fn spawnParticleSlow(
        self: *ParticlePool,
        state: *state_mod.GameplayState,
        pos: state_mod.Vec2,
        angle: f64,
        owner: owner_ref.OwnerRef,
    ) usize {
        const index = self.allocSlot(state);
        const entry = &self.entries[index];
        entry.* = .{
            .active = true,
            .render_flag = true,
            .pos = .{
                .x = narrowF32(pos.x),
                .y = narrowF32(pos.y),
            },
            .vel = runtime_helpers.directionFromAngle(narrowF32(angle)).mul(30.0),
            .scale_x = 1.0,
            .scale_y = 1.0,
            .scale_z = 1.0,
            .age = 0.0,
            .intensity = 1.0,
            .angle = narrowF32(angle),
            .spin = narrowF32(@as(f64, @floatFromInt(state.rng.rand() % 0x274)) * 0.01),
            .style_id = ParticleStyleId.bubblegun,
            .target_id = -1,
            .owner = owner,
        };
        return index;
    }

    pub fn update(
        self: *ParticlePool,
        state: *state_mod.GameplayState,
        players: []state_mod.PlayerState,
        creatures: *creatures_mod.CreaturePool,
        bonuses: *bonus_runtime.BonusPool,
        dt: f64,
        world_size: f64,
    ) void {
        if (!(dt > 0.0)) return;
        const dt_f32 = narrowF32(dt);

        for (&self.entries, 0..) |*entry, particle_idx| {
            if (!entry.active) continue;
            const style = entry.style_id;

            if (style == ParticleStyleId.bubblegun) {
                entry.intensity = narrowF32(entry.intensity - dt_f32 * 0.11);
                entry.spin = narrowF32(entry.spin + dt_f32 * 5.0);
                var move_scale = entry.intensity;
                if (move_scale <= 0.15) {
                    move_scale = narrowF32(move_scale * 0.55);
                }
                const move = entry.vel.mul(narrowF32(dt_f32 * move_scale));
                entry.pos = .{
                    .x = narrowF32(entry.pos.x + move.x),
                    .y = narrowF32(entry.pos.y + move.y),
                };
            } else {
                entry.intensity = narrowF32(entry.intensity - dt_f32 * 0.9);
                entry.spin = narrowF32(entry.spin + dt_f32);
                const move_scale = narrowF32(@max(entry.intensity, 0.15) * 2.5);
                const move = entry.vel.mul(narrowF32(dt_f32 * move_scale));
                entry.pos = .{
                    .x = narrowF32(entry.pos.x + move.x),
                    .y = narrowF32(entry.pos.y + move.y),
                };
            }

            const alive_cutoff: f32 = if (style == ParticleStyleId.flamethrower) 0.0 else 0.8;
            if (!(entry.intensity > alive_cutoff)) {
                entry.active = false;
                if (style == ParticleStyleId.bubblegun and entry.target_id != -1) {
                    const target_idx_i32 = entry.target_id;
                    entry.target_id = -1;
                    if (target_idx_i32 >= 0 and target_idx_i32 < creatures.entries.len) {
                        _ = creatures.killNoCorpse(
                            state,
                            players,
                            bonuses,
                            @intCast(target_idx_i32),
                            entry.owner,
                            dt_f32,
                            narrowF32(world_size),
                        );
                    }
                }
                continue;
            }

            if (entry.render_flag) {
                const jitter_base = narrowF32(@as(f64, @floatFromInt(@as(i32, @intCast(state.rng.rand() % 100)) - 50)) * 0.06);
                var jitter = narrowF32(jitter_base * @max(entry.intensity, 0.0) * dt_f32);
                var speed: f32 = 82.0;
                if (style == ParticleStyleId.flamethrower) {
                    jitter = narrowF32(jitter * 1.96);
                    speed = 82.0;
                } else if (style == ParticleStyleId.bubblegun) {
                    jitter = narrowF32(jitter * 1.1);
                    speed = 62.0;
                } else {
                    jitter = narrowF32(jitter * 1.1);
                    speed = 82.0;
                }
                entry.angle = narrowF32(entry.angle - jitter);
                entry.vel = runtime_helpers.directionFromAngle(entry.angle).mul(speed);
            }

            const alpha = std.math.clamp(entry.intensity, 0.0, 1.0);
            const shade = 1.0 - @max(entry.intensity, 0.0) * 0.95;
            entry.age = narrowF32(alpha);
            entry.scale_x = narrowF32(shade);
            entry.scale_y = narrowF32(shade);

            if (style == ParticleStyleId.bubblegun and
                !entry.render_flag and
                entry.target_id != -1)
            {
                const target_idx_i32 = entry.target_id;
                if (target_idx_i32 >= 0 and target_idx_i32 < creatures.entries.len) {
                    const target = creatures.entries[@intCast(target_idx_i32)];
                    if (target.active) {
                        entry.pos = .{
                            .x = narrowF32(target.pos.x),
                            .y = narrowF32(target.pos.y),
                        };
                    }
                }
            }

            if (entry.render_flag) {
                const radius = narrowF32(@max(entry.intensity, 0.0) * 8.0);
                const hit_idx = creatureFindInRadius(creatures, entry.pos, radius);
                if (hit_idx) |target_idx| {
                    entry.render_flag = false;
                    const creature = &creatures.entries[target_idx];
                    if (style == ParticleStyleId.bubblegun) {
                        entry.target_id = @intCast(target_idx);
                        entry.pos = .{
                            .x = narrowF32(creature.pos.x),
                            .y = narrowF32(creature.pos.y),
                        };
                        entry.vel = .{};
                    } else {
                        entry.angle = wrapAngle(entry.angle);
                        const hit_delta = state_mod.Vec2{
                            .x = narrowF32((entry.pos.x - entry.vel.x * dt_f32) - creature.pos.x),
                            .y = narrowF32((entry.pos.y - entry.vel.y * dt_f32) - creature.pos.y),
                        };
                        const hit_angle = wrapAngle(hit_delta.toAngle());
                        const deflect_step = std.math.tau * 0.2;
                        if (entry.angle <= hit_angle) {
                            entry.angle = narrowF32(entry.angle + deflect_step);
                        } else {
                            entry.angle = narrowF32(entry.angle - deflect_step);
                        }

                        const bounce = runtime_helpers.directionFromAngle(entry.angle).mul(82.0);
                        const speed_scale = narrowF32(@as(f64, @floatFromInt(state.rng.rand() % 10)) * 0.1);
                        entry.vel = .{
                            .x = narrowF32(bounce.x * speed_scale),
                            .y = narrowF32(bounce.y * speed_scale),
                        };

                        const damage = @max(0.0, entry.intensity * 10.0);
                        if (damage > 0.0) {
                            _ = creatures.applyProjectileDamage(
                                state,
                                players,
                                bonuses,
                                target_idx,
                                damage,
                                .{},
                                entry.owner,
                                dt_f32,
                                narrowF32(world_size),
                            );
                        }

                        if ((particle_idx % 3) == 0) {
                            _ = state.rng.rand() % 0x3c;
                            _ = state.rng.rand() % 0x3c;
                        }
                        runtime_helpers.consumeAddRandomRng(state);
                    }
                }
            }
        }
    }

    fn allocSlot(self: *ParticlePool, state: *state_mod.GameplayState) usize {
        for (self.entries, 0..) |entry, idx| {
            if (!entry.active) return idx;
        }
        return state.rng.rand() % self.entries.len;
    }
};

fn creatureFindInRadius(
    creatures: *creatures_mod.CreaturePool,
    pos: state_mod.Vec2,
    radius: f32,
) ?usize {
    const limit: usize = @min(creatures.entries.len, 0x180);
    for (creatures.entries[0..limit], 0..) |creature, idx| {
        if (!creature.active) continue;
        if (!creature_lifecycle.isCollidable(creature.lifecycle_stage)) continue;

        const size = narrowF32(creature.size);
        const dx = narrowF32(creature.pos.x - pos.x);
        const dy = narrowF32(creature.pos.y - pos.y);
        const dist_sq = narrowF32(narrowF32(dx * dx) + narrowF32(dy * dy));
        const dist = narrowF32(narrowF32(std.math.sqrt(dist_sq)) - radius);
        const threshold = narrowF32(narrowF32(size * 0.14285715) + 3.0);
        if (threshold < dist) continue;
        return idx;
    }
    return null;
}

fn wrapAngle(angle: f32) f32 {
    return native_math.wrapAngle0Tau(angle);
}
