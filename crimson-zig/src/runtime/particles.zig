const std = @import("std");
const native_math = @import("native_math.zig");
const rng_callers = @import("../rng_caller_static.zig");

const bonus_runtime = @import("bonuses.zig");
const creature_lifecycle = @import("lifecycle.zig").CreatureLifecycle;
const creatures_mod = @import("creatures.zig");
const effects_mod = @import("effects.zig");
const owner_ref = @import("owner_ref.zig");
const runtime_helpers = @import("helpers.zig");
const spawn_mod = @import("spawn.zig");
const state_mod = @import("state.zig");
const terrain_fx_mod = @import("terrain_fx.zig");

const narrowF32 = native_math.roundF32;

pub const particle_pool_size: usize = 0x80;

fn nativeParticleVelocity(angle: f32, speed: f32) state_mod.Vec2 {
    return .{
        .x = native_math.pc24Mul(@cos(@as(f64, angle)), speed),
        .y = native_math.pc24Mul(@sin(@as(f64, angle)), speed),
    };
}

fn nativeParticleSpin(draw: u32) f32 {
    return native_math.pc24Mul(
        @as(f32, @floatFromInt(draw % 0x274)),
        @as(f32, 0.01),
    );
}

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
        angle: f32,
        intensity: f32,
        owner: owner_ref.OwnerRef,
    ) usize {
        const index = self.allocSlot(state, rng_callers.fx_spawn_particle_alloc);
        const entry = &self.entries[index];
        entry.* = .{
            .active = true,
            .render_flag = true,
            .pos = .{
                .x = narrowF32(pos.x),
                .y = narrowF32(pos.y),
            },
            .vel = nativeParticleVelocity(angle, 90.0),
            .scale_x = 1.0,
            .scale_y = 1.0,
            .scale_z = 1.0,
            .age = 0.0,
            .intensity = intensity,
            .angle = angle,
            .spin = nativeParticleSpin(state.rng.randTagged(rng_callers.fx_spawn_particle_spin)),
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
        angle: f32,
        owner: owner_ref.OwnerRef,
    ) usize {
        const index = self.allocSlot(state, rng_callers.fx_spawn_particle_slow_alloc);
        const entry = &self.entries[index];
        entry.* = .{
            .active = true,
            .render_flag = true,
            .pos = .{
                .x = narrowF32(pos.x),
                .y = narrowF32(pos.y),
            },
            .vel = nativeParticleVelocity(angle, 30.0),
            .scale_x = 1.0,
            .scale_y = 1.0,
            .scale_z = 1.0,
            .age = 0.0,
            .intensity = 1.0,
            .angle = angle,
            .spin = nativeParticleSpin(state.rng.randTagged(rng_callers.fx_spawn_particle_slow_spin)),
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
        sprite_effects: *effects_mod.SpriteEffectPool,
        terrain_fx: *terrain_fx_mod.TerrainFxScratch,
        dt: f32,
        world_size: f32,
    ) void {
        if (!(dt > 0.0)) return;
        const dt_f32 = dt;

        for (&self.entries, 0..) |*entry, particle_idx| {
            if (!entry.active) continue;
            const style = entry.style_id;

            const bubblegun = style == ParticleStyleId.bubblegun;
            const decay: f32 = if (bubblegun) 0.11 else 0.9;
            entry.intensity = native_math.pc24Sub(entry.intensity, native_math.pc24Mul(dt_f32, decay));
            entry.spin = native_math.pc24Add(entry.spin, if (bubblegun) native_math.pc24Mul(dt_f32, @as(f32, 5.0)) else dt_f32);
            if (!bubblegun or entry.render_flag) {
                // The SDK vector chain multiplies dt into velocity first,
                // rounding each operation before adding the position.
                var move: state_mod.Vec2 = .{
                    .x = native_math.pc24Mul(dt_f32, entry.vel.x),
                    .y = native_math.pc24Mul(dt_f32, entry.vel.y),
                };
                if (!bubblegun or entry.intensity <= 0.15) {
                    const scale: f32 = if (bubblegun) 0.55 else 2.5;
                    move.x = native_math.pc24Mul(move.x, scale);
                    move.y = native_math.pc24Mul(move.y, scale);
                }
                const intensity = if (bubblegun) entry.intensity else @max(entry.intensity, 0.15);
                move.x = native_math.pc24Mul(move.x, intensity);
                move.y = native_math.pc24Mul(move.y, intensity);
                entry.pos = .{
                    .x = native_math.pc24Add(entry.pos.x, move.x),
                    .y = native_math.pc24Add(entry.pos.y, move.y),
                };
            }

            const alive_cutoff: f32 = if (style == ParticleStyleId.flamethrower) 0.0 else 0.8;
            if (!(entry.intensity > alive_cutoff)) {
                entry.active = false;
                if (style == ParticleStyleId.bubblegun and entry.target_id != -1) {
                    const target_idx_i32 = entry.target_id;
                    if (target_idx_i32 >= 0 and target_idx_i32 < creatures.entries.len) {
                        const target_idx: usize = @intCast(target_idx_i32);
                        if (creatures.entries[target_idx].active) {
                            const sound_slot = state.rng.randTagged(
                                rng_callers.projectile_update_particle_bubblegun_expiry_sfx,
                            ) % 3;
                            if (bubblegunExpirySfx(creatures.entries[target_idx].type_id, sound_slot)) |sfx_id| {
                                state.sfx_queue.append(sfx_id);
                            }
                            _ = creatures.killNoCorpse(
                                state,
                                players,
                                bonuses,
                                terrain_fx,
                                target_idx,
                                entry.owner,
                                dt_f32,
                                world_size,
                            );
                        }
                    }
                }
                continue;
            }

            if (entry.render_flag) {
                const jitter_caller = switch (style) {
                    .flamethrower => rng_callers.projectile_update_particle_jitter_flamethrower,
                    .blow_torch, .hr_flamer => rng_callers.projectile_update_particle_jitter_alt,
                    .bubblegun => rng_callers.projectile_update_particle_jitter_bubblegun,
                };
                const turn: f32 = @floatFromInt(@as(i32, @intCast(state.rng.randTagged(jitter_caller) % 100)) - 50);
                var jitter = native_math.pc24Mul(turn, @as(f32, 0.06));
                jitter = native_math.pc24Mul(jitter, entry.intensity);
                jitter = native_math.pc24Mul(jitter, dt_f32);
                const turn_scale: f32 = if (style == .flamethrower) 1.96 else 1.1;
                jitter = native_math.pc24Mul(jitter, turn_scale);
                entry.angle = native_math.pc24Sub(entry.angle, jitter);
                entry.vel = nativeParticleVelocity(entry.angle, if (bubblegun) 62.0 else 82.0);
            }

            const alpha = std.math.clamp(entry.intensity, 0.0, 1.0);
            const shade = native_math.pc24Sub(@as(f32, 1.0), native_math.pc24Mul(entry.intensity, @as(f32, 0.95)));
            entry.age = alpha;
            entry.scale_x = shade;
            entry.scale_y = shade;

            if (entry.render_flag) {
                const radius = @max(entry.intensity, 0.0) * 8.0;
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
                        // Native wraps the stored angle iteratively with the
                        // f32 tau literal, keeps the atan2 hit angle in
                        // extended precision for its wrap, and deflects by the
                        // f32 constant 1.2566371.
                        const native_tau_f32: f32 = native_math.roundF32(native_math.native_tau);
                        while (native_tau_f32 < entry.angle) {
                            entry.angle = narrowF32(entry.angle - native_tau_f32);
                        }
                        while (entry.angle < 0.0) {
                            entry.angle = narrowF32(entry.angle + native_tau_f32);
                        }
                        const hit_delta: state_mod.Vec2 = .{
                            .x = (entry.pos.x - entry.vel.x * dt_f32) - creature.pos.x,
                            .y = (entry.pos.y - entry.vel.y * dt_f32) - creature.pos.y,
                        };
                        var hit_angle: f64 = std.math.atan2(@as(f64, hit_delta.y), @as(f64, hit_delta.x));
                        while (@as(f64, native_tau_f32) < hit_angle) {
                            hit_angle -= @as(f64, native_tau_f32);
                        }
                        while (hit_angle < 0.0) {
                            hit_angle += @as(f64, native_tau_f32);
                        }
                        const deflect_step: f32 = 1.2566371;
                        if (@as(f64, entry.angle) <= hit_angle) {
                            entry.angle += deflect_step;
                        } else {
                            entry.angle -= deflect_step;
                        }

                        const bounce = runtime_helpers.directionFromAngle(entry.angle).mul(82.0);
                        const speed_scale = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.projectile_update_particle_bounce_speed_scale) % 10)) * 0.1;
                        entry.vel = .{
                            .x = bounce.x * speed_scale,
                            .y = bounce.y * speed_scale,
                        };

                        const damage = @max(0.0, entry.intensity * 10.0);
                        if (damage > 0.0) {
                            _ = creatures.applyProjectileDamage(
                                state,
                                players,
                                bonuses,
                                terrain_fx,
                                target_idx,
                                damage,
                                .{},
                                entry.owner,
                                dt_f32,
                                world_size,
                            );
                        }

                        const tint_sum = native_math.pc24Add(
                            native_math.pc24Add(creature.tint[1], creature.tint[2]),
                            creature.tint[0],
                        );
                        if (tint_sum > @as(f32, 1.6)) {
                            const tint_factor = native_math.pc24Sub(
                                @as(f32, 1.0),
                                native_math.pc24Mul(entry.intensity, @as(f32, 0.01)),
                            );
                            creature.tint[0] = native_math.pc24Mul(tint_factor, creature.tint[0]);
                            creature.tint[1] = native_math.pc24Mul(tint_factor, creature.tint[1]);
                            creature.tint[2] = native_math.pc24Mul(tint_factor, creature.tint[2]);
                        }
                        for (&creature.tint) |*channel| {
                            channel.* = nativeClampUnit(channel.*);
                        }

                        if ((particle_idx % 3) == 0) {
                            const sprite_vel: state_mod.Vec2 = .{
                                .x = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.projectile_update_particle_sprite_vel_x) % 60)) - 30.0,
                                .y = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.projectile_update_particle_sprite_vel_y) % 60)) - 30.0,
                            };
                            _ = sprite_effects.spawn(
                                state,
                                creature.pos,
                                sprite_vel,
                                13.0,
                                .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 0.7 },
                            );
                        }
                        _ = terrain_fx.decals.addRandom(state, creature.pos);
                        creature.pos = .{
                            .x = native_math.pc24Add(
                                creature.pos.x,
                                native_math.pc24Mul(entry.vel.x, dt_f32),
                            ),
                            .y = native_math.pc24Add(
                                creature.pos.y,
                                native_math.pc24Mul(entry.vel.y, dt_f32),
                            ),
                        };
                    }
                }
            }
        }
    }

    fn allocSlot(self: *ParticlePool, state: *state_mod.GameplayState, alloc_caller: rng_callers.Caller) usize {
        for (self.entries, 0..) |entry, idx| {
            if (!entry.active) return idx;
        }
        return state.rng.randTagged(alloc_caller) % self.entries.len;
    }
};

fn nativeClampUnit(value: f32) f32 {
    if (!(value >= 0.0)) return 0.0;
    if (value > 1.0) return 1.0;
    return value;
}

fn bubblegunExpirySfx(type_id: i32, sound_slot: u32) ?state_mod.SfxId {
    const creature_type = std.enums.fromInt(spawn_mod.CreatureTypeId, type_id) orelse return null;
    const bank: [3]state_mod.SfxId = switch (creature_type) {
        .zombie => .{ .zombie_die_01, .zombie_die_02, .zombie_die_03 },
        .lizard => .{ .lizard_die_01, .lizard_die_02, .lizard_die_03 },
        .alien => .{ .alien_die_01, .alien_die_02, .alien_die_03 },
        .spider_sp1, .spider_sp2 => .{ .spider_die_01, .spider_die_02, .spider_die_03 },
        .trooper => .{ .trooper_die_01, .trooper_die_02, .trooper_die_03 },
    };
    return bank[@intCast(sound_slot % 3)];
}

fn creatureFindInRadius(
    creatures: *creatures_mod.CreaturePool,
    pos: state_mod.Vec2,
    radius: f32,
) ?usize {
    const limit: usize = @min(creatures.entries.len, 0x180);
    for (creatures.entries[0..limit], 0..) |creature, idx| {
        if (!creature.active) continue;
        if (!creature_lifecycle.isCollidable(creature.lifecycle_stage)) continue;

        if (!runtime_helpers.withinNativeFindRadius(
            pos,
            creature.pos,
            radius,
            creature.size,
        )) continue;
        return idx;
    }
    return null;
}

fn wrapAngle(angle: f32) f32 {
    return native_math.wrapAngle0Tau(angle);
}

test "particle spawn math keeps native x87 operation boundaries" {
    const fast = nativeParticleVelocity(@bitCast(@as(u32, 0x3ab78034)), 90.0);
    try std.testing.expectEqual(@as(f32, @bitCast(@as(u32, 0x42b3fff4))), fast.x);
    try std.testing.expectEqual(@as(f32, @bitCast(@as(u32, 0x3e010622))), fast.y);

    const slow = nativeParticleVelocity(@bitCast(@as(u32, 0x3a6bedfa)), 30.0);
    try std.testing.expectEqual(@as(f32, @bitCast(@as(u32, 0x41effffa))), slow.x);
    try std.testing.expectEqual(@as(f32, @bitCast(@as(u32, 0x3cdd2f18))), slow.y);
    try std.testing.expectEqual(@as(f32, @bitCast(@as(u32, 0x3d4ccccc))), nativeParticleSpin(5));
}

test "particle update matches native no-hit trajectories and RNG callers" {
    // Regenerated from native projectile_update by the matching evidence package.
    const Sample = struct {
        index: usize,
        active: u8 = 1,
        render: u8,
        x: f32,
        y: f32,
        vx: f32,
        vy: f32,
        sx: f32 = 0,
        sy: f32 = 0,
        sz: f32 = 0,
        age: f32 = 0,
        intensity: f32,
        angle: f32,
        spin: f32,
        style: i32,
        target: i32,
    };
    const Witness = struct {
        input: struct { dt: f32, rng_seed: u32, particles: []Sample },
        particles: []Sample,
        rng_state: u32,
        draws: []u32,
        rng_callers: []u32,
    };
    const Trace = struct {
        const Self = @This();

        records: [128]spawn_mod.Crand.TraceDraw = undefined,
        count: usize = 0,
        fn record(ctx: ?*anyopaque, draw: spawn_mod.Crand.TraceDraw) void {
            const self: *Self = @ptrCast(@alignCast(ctx.?));
            self.records[self.count] = draw;
            self.count += 1;
        }
    };
    const parsed = try std.json.parseFromSlice(
        []Witness,
        std.testing.allocator,
        @embedFile("testdata/particle-update.json"),
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 80), parsed.value.len);
    for (parsed.value) |witness| {
        var state = state_mod.GameplayState.init(witness.input.rng_seed);
        var trace: Trace = .{};
        state.rng.setTraceSink(&trace, Trace.record, true);
        var players = [_]state_mod.PlayerState{.{ .index = 0, .pos = .{} }};
        var creatures: creatures_mod.CreaturePool = .{};
        var bonuses: bonus_runtime.BonusPool = .{};
        var sprites: effects_mod.SpriteEffectPool = .{};
        var terrain: terrain_fx_mod.TerrainFxScratch = .{};
        var pool: ParticlePool = .{};
        for (witness.input.particles) |item| {
            pool.entries[item.index] = .{
                .active = true,
                .render_flag = item.render != 0,
                .pos = .{ .x = item.x, .y = item.y },
                .vel = .{ .x = item.vx, .y = item.vy },
                .scale_x = 0,
                .scale_y = 0,
                .scale_z = 0,
                .age = 0,
                .intensity = item.intensity,
                .angle = item.angle,
                .spin = item.spin,
                .style_id = @enumFromInt(item.style),
                .target_id = item.target,
            };
        }
        pool.update(&state, &players, &creatures, &bonuses, &sprites, &terrain, witness.input.dt, 1024.0);
        for (witness.particles) |expected| {
            const entry = pool.entries[expected.index];
            const actual: Sample = .{
                .index = expected.index,
                .active = @intFromBool(entry.active),
                .render = @intFromBool(entry.render_flag),
                .x = entry.pos.x,
                .y = entry.pos.y,
                .vx = entry.vel.x,
                .vy = entry.vel.y,
                .sx = entry.scale_x,
                .sy = entry.scale_y,
                .sz = entry.scale_z,
                .age = entry.age,
                .intensity = entry.intensity,
                .angle = entry.angle,
                .spin = entry.spin,
                .style = @intFromEnum(entry.style_id),
                .target = entry.target_id,
            };
            inline for (std.meta.fields(Sample)) |field| {
                if (field.type == f32) {
                    try std.testing.expectEqual(@as(u32, @bitCast(@field(expected, field.name))), @as(u32, @bitCast(@field(actual, field.name))));
                } else {
                    try std.testing.expectEqual(@field(expected, field.name), @field(actual, field.name));
                }
            }
        }
        try std.testing.expectEqual(witness.rng_state, state.rng.state);
        try std.testing.expectEqual(witness.draws.len, trace.count);
        for (trace.records[0..trace.count], witness.draws, witness.rng_callers) |record, value, caller| {
            try std.testing.expectEqual(value, record.value_15);
            try std.testing.expectEqual(caller, @intFromEnum(record.caller.?));
        }
        try std.testing.expect(!state.rng.missing_trace_caller);
    }
}
