const std = @import("std");
const native_math = @import("native_math.zig");

const survival_bonuses = @import("bonuses.zig");
const survival_creatures = @import("creatures.zig");
const survival_state = @import("state.zig");
const survival_math = @import("math.zig");

const asF32F64 = native_math.roundF32;

pub const particle_pool_size: usize = 0x80;

pub const ParticleStyleId = struct {
    pub const flamethrower: i32 = 0;
    pub const blow_torch: i32 = 1;
    pub const hr_flamer: i32 = 2;
    pub const bubblegun: i32 = 8;
};

pub const Particle = struct {
    active: bool = false,
    render_flag: bool = false,
    pos: survival_state.Vec2 = .{},
    vel: survival_state.Vec2 = .{},
    scale_x: f64 = 1.0,
    scale_y: f64 = 1.0,
    scale_z: f64 = 1.0,
    age: f64 = 0.0,
    intensity: f64 = 0.0,
    angle: f64 = 0.0,
    spin: f64 = 0.0,
    style_id: i32 = ParticleStyleId.flamethrower,
    target_id: i32 = -1,
    owner_id: i32 = -100,
};

pub const ParticlePool = struct {
    entries: [particle_pool_size]Particle = [_]Particle{.{}} ** particle_pool_size,

    pub fn reset(self: *ParticlePool) void {
        self.entries = [_]Particle{.{}} ** particle_pool_size;
    }

    pub fn spawnParticle(
        self: *ParticlePool,
        state: *survival_state.GameplayState,
        pos: survival_state.Vec2,
        angle: f64,
        intensity: f64,
        owner_id: i32,
    ) usize {
        const index = self.allocSlot(state);
        const entry = &self.entries[index];
        entry.* = .{
            .active = true,
            .render_flag = true,
            .pos = .{
                .x = asF32F64(pos.x),
                .y = asF32F64(pos.y),
            },
            .vel = directionFromAngle(angle).mul(90.0),
            .scale_x = 1.0,
            .scale_y = 1.0,
            .scale_z = 1.0,
            .age = 0.0,
            .intensity = asF32F64(intensity),
            .angle = asF32F64(angle),
            .spin = asF32F64(@as(f64, @floatFromInt(state.rng.rand() % 0x274)) * 0.01),
            .style_id = ParticleStyleId.flamethrower,
            .target_id = -1,
            .owner_id = owner_id,
        };
        return index;
    }

    pub fn spawnParticleSlow(
        self: *ParticlePool,
        state: *survival_state.GameplayState,
        pos: survival_state.Vec2,
        angle: f64,
        owner_id: i32,
    ) usize {
        const index = self.allocSlot(state);
        const entry = &self.entries[index];
        entry.* = .{
            .active = true,
            .render_flag = true,
            .pos = .{
                .x = asF32F64(pos.x),
                .y = asF32F64(pos.y),
            },
            .vel = directionFromAngle(angle).mul(30.0),
            .scale_x = 1.0,
            .scale_y = 1.0,
            .scale_z = 1.0,
            .age = 0.0,
            .intensity = 1.0,
            .angle = asF32F64(angle),
            .spin = asF32F64(@as(f64, @floatFromInt(state.rng.rand() % 0x274)) * 0.01),
            .style_id = ParticleStyleId.bubblegun,
            .target_id = -1,
            .owner_id = owner_id,
        };
        return index;
    }

    pub fn update(
        self: *ParticlePool,
        state: *survival_state.GameplayState,
        players: []survival_state.PlayerState,
        creatures: *survival_creatures.CreaturePool,
        bonuses: *survival_bonuses.BonusPool,
        dt: f64,
        world_size: f64,
    ) void {
        if (!(dt > 0.0)) return;
        const dt_f32 = asF32F64(dt);

        for (&self.entries, 0..) |*entry, particle_idx| {
            if (!entry.active) continue;
            const style = entry.style_id & 0xff;

            if (style == ParticleStyleId.bubblegun) {
                entry.intensity = asF32F64(entry.intensity - dt_f32 * 0.11);
                entry.spin = asF32F64(entry.spin + dt_f32 * 5.0);
                var move_scale = entry.intensity;
                if (move_scale <= 0.15) {
                    move_scale = asF32F64(move_scale * 0.55);
                }
                const move = entry.vel.mul(asF32F64(dt_f32 * move_scale));
                entry.pos = .{
                    .x = asF32F64(entry.pos.x + move.x),
                    .y = asF32F64(entry.pos.y + move.y),
                };
            } else {
                entry.intensity = asF32F64(entry.intensity - dt_f32 * 0.9);
                entry.spin = asF32F64(entry.spin + dt_f32);
                const move_scale = asF32F64(@max(entry.intensity, 0.15) * 2.5);
                const move = entry.vel.mul(asF32F64(dt_f32 * move_scale));
                entry.pos = .{
                    .x = asF32F64(entry.pos.x + move.x),
                    .y = asF32F64(entry.pos.y + move.y),
                };
            }

            const alive_cutoff: f64 = if (style == ParticleStyleId.flamethrower) 0.0 else 0.8;
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
                            entry.owner_id,
                            dt_f32,
                            world_size,
                        );
                    }
                }
                continue;
            }

            if (entry.render_flag) {
                const jitter_base = @as(f64, @floatFromInt(@as(i32, @intCast(state.rng.rand() % 100)) - 50)) * 0.06;
                var jitter = asF32F64(jitter_base * @max(entry.intensity, 0.0) * dt_f32);
                var speed: f64 = 82.0;
                if (style == ParticleStyleId.flamethrower) {
                    jitter = asF32F64(jitter * 1.96);
                    speed = 82.0;
                } else if (style == ParticleStyleId.bubblegun) {
                    jitter = asF32F64(jitter * 1.1);
                    speed = 62.0;
                } else {
                    jitter = asF32F64(jitter * 1.1);
                    speed = 82.0;
                }
                entry.angle = asF32F64(entry.angle - jitter);
                entry.vel = directionFromAngle(entry.angle).mul(asF32F64(speed));
            }

            const alpha = std.math.clamp(entry.intensity, 0.0, 1.0);
            const shade = 1.0 - @max(entry.intensity, 0.0) * 0.95;
            entry.age = asF32F64(alpha);
            entry.scale_x = asF32F64(shade);
            entry.scale_y = asF32F64(shade);

            if (style == ParticleStyleId.bubblegun and
                !entry.render_flag and
                entry.target_id != -1)
            {
                const target_idx_i32 = entry.target_id;
                if (target_idx_i32 >= 0 and target_idx_i32 < creatures.entries.len) {
                    const target = creatures.entries[@intCast(target_idx_i32)];
                    if (target.active) {
                        entry.pos = .{
                            .x = asF32F64(target.pos.x),
                            .y = asF32F64(target.pos.y),
                        };
                    }
                }
            }

            if (entry.render_flag) {
                const radius = asF32F64(@max(entry.intensity, 0.0) * 8.0);
                const hit_idx = creatureFindInRadius(creatures, entry.pos, radius);
                if (hit_idx) |target_idx| {
                    entry.render_flag = false;
                    const creature = &creatures.entries[target_idx];
                    if (style == ParticleStyleId.bubblegun) {
                        entry.target_id = @intCast(target_idx);
                        entry.pos = .{
                            .x = asF32F64(creature.pos.x),
                            .y = asF32F64(creature.pos.y),
                        };
                        entry.vel = .{};
                    } else {
                        entry.angle = wrapAngle(entry.angle);
                        const hit_delta = survival_state.Vec2{
                            .x = asF32F64((entry.pos.x - entry.vel.x * dt_f32) - creature.pos.x),
                            .y = asF32F64((entry.pos.y - entry.vel.y * dt_f32) - creature.pos.y),
                        };
                        const hit_angle = wrapAngle(hit_delta.toAngle());
                        const deflect_step = std.math.tau * 0.2;
                        if (entry.angle <= hit_angle) {
                            entry.angle = asF32F64(entry.angle + deflect_step);
                        } else {
                            entry.angle = asF32F64(entry.angle - deflect_step);
                        }

                        const bounce = directionFromAngle(entry.angle).mul(82.0);
                        const speed_scale = asF32F64(@as(f64, @floatFromInt(state.rng.rand() % 10)) * 0.1);
                        entry.vel = .{
                            .x = asF32F64(bounce.x * speed_scale),
                            .y = asF32F64(bounce.y * speed_scale),
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
                                entry.owner_id,
                                dt_f32,
                                world_size,
                            );
                        }

                        if ((particle_idx % 3) == 0) {
                            _ = state.rng.rand() % 0x3c;
                            _ = state.rng.rand() % 0x3c;
                        }
                        consumeAddRandomRng(state);
                    }
                }
            }
        }
    }

    fn allocSlot(self: *ParticlePool, state: *survival_state.GameplayState) usize {
        for (self.entries, 0..) |entry, idx| {
            if (!entry.active) return idx;
        }
        return state.rng.rand() % self.entries.len;
    }
};

fn creatureFindInRadius(
    creatures: *survival_creatures.CreaturePool,
    pos: survival_state.Vec2,
    radius: f64,
) ?usize {
    const limit: usize = @min(creatures.entries.len, 0x180);
    for (creatures.entries[0..limit], 0..) |creature, idx| {
        if (!creature.active) continue;
        if (!(creature.lifecycle_stage > 5.0)) continue;

        const size = asF32F64(creature.size);
        const dx = asF32F64(creature.pos.x - pos.x);
        const dy = asF32F64(creature.pos.y - pos.y);
        const dist_sq = asF32F64(asF32F64(dx * dx) + asF32F64(dy * dy));
        const dist = asF32F64(asF32F64(std.math.sqrt(dist_sq)) - radius);
        const threshold = asF32F64(asF32F64(size * 0.14285715) + 3.0);
        if (threshold < dist) continue;
        return idx;
    }
    return null;
}

fn directionFromAngle(angle: f64) survival_state.Vec2 {
    return .{
        .x = asF32F64(survival_math.cos(angle)),
        .y = asF32F64(survival_math.sin(angle)),
    };
}

fn wrapAngle(angle: f64) f64 {
    return asF32F64(@mod(asF32F64(angle), std.math.tau));
}

fn consumeAddRandomRng(state: *survival_state.GameplayState) void {
    _ = state.rng.rand();
    _ = state.rng.rand();
    _ = state.rng.rand();
    _ = state.rng.rand();
}
