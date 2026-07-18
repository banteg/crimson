const std = @import("std");
const native_math = @import("native_math.zig");
const rng_callers = @import("../rng_caller_static.zig");

const state_mod = @import("state.zig");
const terrain_fx_mod = @import("terrain_fx.zig");

const narrowF32 = native_math.roundF32;

pub const effect_pool_size: usize = 0x200;
pub const sprite_effect_pool_size: usize = 0x180;

pub const EffectId = enum(i32) {
    burst = 0x00,
    ring = 0x01,
    shield_ring = 0x02,
    effect_03 = 0x03,
    effect_04 = 0x04,
    effect_05 = 0x05,
    effect_06 = 0x06,
    blood_splatter = 0x07,
    freeze_shard_0 = 0x08,
    freeze_shard_1 = 0x09,
    freeze_shard_2 = 0x0A,
    effect_0b = 0x0B,
    explosion_burst = 0x0C,
    glow = 0x0D,
    freeze_shatter = 0x0E,
    effect_0f = 0x0F,
    aura = 0x10,
    explosion_puff = 0x11,
    casing = 0x12,
};

pub const Color = struct {
    r: f32 = 1.0,
    g: f32 = 1.0,
    b: f32 = 1.0,
    a: f32 = 1.0,

    pub fn withAlpha(self: Color, alpha: f32) Color {
        return .{
            .r = self.r,
            .g = self.g,
            .b = self.b,
            .a = alpha,
        };
    }

    pub fn clamped(self: Color) Color {
        return .{
            .r = std.math.clamp(self.r, @as(f32, 0.0), @as(f32, 1.0)),
            .g = std.math.clamp(self.g, @as(f32, 0.0), @as(f32, 1.0)),
            .b = std.math.clamp(self.b, @as(f32, 0.0), @as(f32, 1.0)),
            .a = std.math.clamp(self.a, @as(f32, 0.0), @as(f32, 1.0)),
        };
    }

    pub fn scaled(self: Color, factor: f32) Color {
        return .{
            .r = self.r * factor,
            .g = self.g * factor,
            .b = self.b * factor,
            .a = self.a,
        };
    }
};

pub const SpriteEffect = struct {
    active: bool = false,
    color: Color = .{ .a = 0.0 },
    rotation: f32 = 0.0,
    pos: state_mod.Vec2 = .{},
    vel: state_mod.Vec2 = .{},
    scale: f32 = 1.0,
};

pub const SpriteEffectPool = struct {
    entries: [sprite_effect_pool_size]SpriteEffect = [_]SpriteEffect{.{}} ** sprite_effect_pool_size,

    pub fn reset(self: *SpriteEffectPool) void {
        self.entries = [_]SpriteEffect{.{}} ** sprite_effect_pool_size;
    }

    pub fn spawn(
        self: *SpriteEffectPool,
        state: *state_mod.GameplayState,
        pos: state_mod.Vec2,
        vel: state_mod.Vec2,
        scale: f32,
        color: ?Color,
    ) usize {
        var idx: usize = 0;
        while (idx < self.entries.len) : (idx += 1) {
            if (!self.entries[idx].active) break;
        }
        if (idx >= self.entries.len) {
            idx = state.rng.randTagged(rng_callers.fx_spawn_sprite_alloc) % self.entries.len;
        }

        self.entries[idx] = .{
            .active = true,
            .color = color orelse .{},
            .rotation = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.fx_spawn_sprite_rotation) % 628)) * 0.01,
            .pos = .{ .x = narrowF32(pos.x), .y = narrowF32(pos.y) },
            .vel = .{ .x = narrowF32(vel.x), .y = narrowF32(vel.y) },
            .scale = narrowF32(scale),
        };
        return idx;
    }

    pub fn update(self: *SpriteEffectPool, dt: f32) void {
        if (!(dt > 0.0)) return;
        for (&self.entries) |*entry| {
            if (!entry.active) continue;
            entry.pos = .{
                .x = narrowF32(entry.pos.x + entry.vel.x * dt),
                .y = narrowF32(entry.pos.y + entry.vel.y * dt),
            };
            entry.rotation = narrowF32(entry.rotation + dt * 3.0);
            entry.color.a = narrowF32(entry.color.a - dt);
            entry.scale = narrowF32(entry.scale + dt * 60.0);
            if (!(entry.color.a > 0.0)) {
                entry.active = false;
            }
        }
    }
};

pub const EffectEntry = struct {
    pos: state_mod.Vec2 = .{},
    effect_id: i32 = 0,
    vel: state_mod.Vec2 = .{},
    rotation: f32 = 0.0,
    scale: f32 = 1.0,
    half_width: f32 = 0.0,
    half_height: f32 = 0.0,
    age: f32 = 0.0,
    lifetime: f32 = 0.0,
    flags: i32 = 0,
    color: Color = .{},
    rotation_step: f32 = 0.0,
    scale_step: f32 = 0.0,
};

pub const EffectPool = struct {
    entries: [effect_pool_size]EffectEntry = [_]EffectEntry{.{}} ** effect_pool_size,
    free: [effect_pool_size]usize = initFree(),
    free_len: usize = effect_pool_size,
    detail_toggle: u32 = 0,
    overwrite_cursor: usize = 0,

    fn initFree() [effect_pool_size]usize {
        var free: [effect_pool_size]usize = undefined;
        var idx: usize = 0;
        while (idx < effect_pool_size) : (idx += 1) {
            free[idx] = effect_pool_size - 1 - idx;
        }
        return free;
    }

    pub fn reset(self: *EffectPool) void {
        self.entries = [_]EffectEntry{.{}} ** effect_pool_size;
        self.free = initFree();
        self.free_len = effect_pool_size;
        self.detail_toggle = 0;
        self.overwrite_cursor = 0;
    }

    fn allocSlot(self: *EffectPool, detail_preset: i32) ?usize {
        if (detail_preset < 3) {
            const skip = (self.detail_toggle & 1) != 0;
            self.detail_toggle += 1;
            if (skip) return null;
        }
        if (self.free_len > 0) {
            self.free_len -= 1;
            return self.free[self.free_len];
        }
        if (self.entries.len == 0) return null;
        const idx = self.overwrite_cursor % self.entries.len;
        self.overwrite_cursor = idx + 1;
        return idx;
    }

    pub fn freeSlot(self: *EffectPool, idx: usize) void {
        if (idx >= self.entries.len) return;
        self.entries[idx].flags = 0;
        if (self.free_len < self.free.len) {
            self.free[self.free_len] = idx;
            self.free_len += 1;
        }
    }

    pub fn spawn(
        self: *EffectPool,
        effect_id: i32,
        pos: state_mod.Vec2,
        vel: state_mod.Vec2,
        rotation: f32,
        scale: f32,
        half_width: f32,
        half_height: f32,
        age: f32,
        lifetime: f32,
        flags: i32,
        color: Color,
        rotation_step: f32,
        scale_step: f32,
        detail_preset: i32,
    ) ?usize {
        const idx = self.allocSlot(detail_preset) orelse return null;
        self.entries[idx] = .{
            .pos = .{ .x = narrowF32(pos.x), .y = narrowF32(pos.y) },
            .effect_id = effect_id,
            .vel = .{ .x = narrowF32(vel.x), .y = narrowF32(vel.y) },
            .rotation = narrowF32(rotation),
            .scale = narrowF32(scale),
            .half_width = narrowF32(half_width),
            .half_height = narrowF32(half_height),
            .age = narrowF32(age),
            .lifetime = narrowF32(lifetime),
            .flags = flags,
            .color = color,
            .rotation_step = narrowF32(rotation_step),
            .scale_step = narrowF32(scale_step),
        };
        return idx;
    }

    pub fn update(self: *EffectPool, dt: f32, fx_queue: ?*terrain_fx_mod.FxQueue) void {
        for (&self.entries, 0..) |*entry, idx| {
            const flags = entry.flags;
            if (flags == 0) continue;

            entry.age = narrowF32(entry.age + dt);
            if (entry.age < entry.lifetime) {
                if (entry.age >= 0.0) {
                    entry.pos = .{
                        .x = narrowF32(entry.pos.x + entry.vel.x * dt),
                        .y = narrowF32(entry.pos.y + entry.vel.y * dt),
                    };
                    if ((flags & 0x4) != 0) {
                        entry.rotation = narrowF32(entry.rotation + entry.rotation_step * dt);
                    }
                    if ((flags & 0x8) != 0) {
                        entry.scale = narrowF32(entry.scale + entry.scale_step * dt);
                    }
                    if ((flags & 0x10) != 0) {
                        entry.color.a = narrowF32(1.0 - entry.age / entry.lifetime);
                    }
                }
                continue;
            }
            if (fx_queue) |queue| {
                if ((flags & 0x80) != 0) {
                    const alpha: f32 = if ((flags & 0x100) != 0) 0.35 else 0.8;
                    entry.color.a = alpha;
                    _ = queue.add(
                        entry.effect_id,
                        entry.pos,
                        entry.half_width * 2.0,
                        entry.half_height * 2.0,
                        entry.rotation,
                        .{
                            .r = entry.color.r,
                            .g = entry.color.g,
                            .b = entry.color.b,
                            .a = entry.color.a,
                        },
                    );
                }
            }
            self.freeSlot(idx);
        }
    }

    pub fn spawnShellCasing(
        self: *EffectPool,
        detail_preset: i32,
        pos: state_mod.Vec2,
        aim_heading: f32,
        angle_draw: u32,
        speed_draw: u32,
        rotation_draw: u32,
        rotation_step_draw: u32,
    ) void {
        const angle = aim_heading + @as(f32, @floatFromInt(angle_draw & 0x3F)) * 0.01;
        const speed = @as(f32, @floatFromInt(speed_draw & 0x3F)) * 0.022727273 + 1.0;
        const velocity = state_mod.Vec2.fromAngle(angle).mul(speed * 100.0);
        const rotation = @as(f32, @floatFromInt((rotation_draw & 0x3F) -% 0x20)) * 0.1;
        const rotation_step = (@as(f32, @floatFromInt(rotation_step_draw % 20)) * 0.1 - 1.0) * 14.0;
        _ = self.spawn(
            @intFromEnum(EffectId.casing),
            pos,
            velocity,
            rotation,
            1.0,
            2.0,
            2.0,
            0.0,
            0.15,
            0x1C5,
            .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 0.6 },
            rotation_step,
            0.0,
            detail_preset,
        );
    }

    pub fn spawnBloodSplatter(
        self: *EffectPool,
        state: *state_mod.GameplayState,
        pos: state_mod.Vec2,
        angle: f32,
        age: f32,
        detail_preset: i32,
        violence_disabled: i32,
    ) void {
        if (violence_disabled != 0) return;
        const lifetime = narrowF32(0.25 - age);
        const base = narrowF32(angle + std.math.pi);
        const direction = state_mod.Vec2.fromAngle(base);
        for (0..2) |_| {
            const rotation = @as(f32, @floatFromInt((state.rng.randTagged(rng_callers.effect_spawn_blood_splatter_rotation) & 0x3F) -% 0x20)) * 0.1 + base;
            const half = @as(f32, @floatFromInt((state.rng.randTagged(rng_callers.effect_spawn_blood_splatter_half) & 7) + 1));
            const speed_x = @as(f32, @floatFromInt((state.rng.randTagged(rng_callers.effect_spawn_blood_splatter_speed_x) & 0x3F) + 100));
            const speed_y = @as(f32, @floatFromInt((state.rng.randTagged(rng_callers.effect_spawn_blood_splatter_speed_y) & 0x3F) + 100));
            const velocity: state_mod.Vec2 = .{
                .x = narrowF32(direction.x * speed_x),
                .y = narrowF32(direction.y * speed_y),
            };
            const scale_step = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.effect_spawn_blood_splatter_scale_step) & 0x7F)) * 0.03 + 0.1;
            _ = self.spawn(
                @intFromEnum(EffectId.blood_splatter),
                pos,
                velocity,
                rotation,
                1.0,
                half,
                half,
                age,
                lifetime,
                0xC9,
                .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 0.5 },
                0.0,
                scale_step,
                detail_preset,
            );
        }
    }

    pub const BurstCallers = struct {
        rotation: rng_callers.Caller = rng_callers.effect_spawn_burst_rotation,
        vel_x: rng_callers.Caller = rng_callers.effect_spawn_burst_vel_x,
        vel_y: rng_callers.Caller = rng_callers.effect_spawn_burst_vel_y,
        scale_step: rng_callers.Caller = rng_callers.effect_spawn_burst_scale_step,
    };

    // Native inlines the burst loop at the bonus-drop kill site, so those
    // draws carry dedicated 0x0041FBxx return addresses.
    pub const bonus_on_kill_burst_callers: BurstCallers = .{
        .rotation = rng_callers.bonus_try_spawn_on_kill_burst_rotation,
        .vel_x = rng_callers.bonus_try_spawn_on_kill_burst_vel_x,
        .vel_y = rng_callers.bonus_try_spawn_on_kill_burst_vel_y,
        .scale_step = rng_callers.bonus_try_spawn_on_kill_burst_scale_step,
    };

    pub const bonus_spawn_at_burst_callers: BurstCallers = .{
        .rotation = rng_callers.bonus_spawn_at_burst_rotation,
        .vel_x = rng_callers.bonus_spawn_at_burst_vel_x,
        .vel_y = rng_callers.bonus_spawn_at_burst_vel_y,
        .scale_step = rng_callers.bonus_spawn_at_burst_scale_step,
    };

    pub const bonus_pickup_burst_callers: BurstCallers = .{
        .rotation = rng_callers.bonus_apply_pickup_burst_rotation,
        .vel_x = rng_callers.bonus_apply_pickup_burst_vel_x,
        .vel_y = rng_callers.bonus_apply_pickup_burst_vel_y,
    };

    pub fn spawnBurst(
        self: *EffectPool,
        state: *state_mod.GameplayState,
        pos: state_mod.Vec2,
        count: i32,
        detail_preset: i32,
        lifetime: f32,
        scale_step: ?f32,
        color: Color,
    ) void {
        self.spawnBurstWithCallers(state, pos, count, detail_preset, lifetime, scale_step, color, .{});
    }

    pub fn spawnBurstWithCallers(
        self: *EffectPool,
        state: *state_mod.GameplayState,
        pos: state_mod.Vec2,
        count: i32,
        detail_preset: i32,
        lifetime: f32,
        scale_step: ?f32,
        color: Color,
        callers: BurstCallers,
    ) void {
        var idx: i32 = 0;
        const safe_count = @max(count, 0);
        while (idx < safe_count) : (idx += 1) {
            const rotation_draw = state.rng.randTagged(callers.rotation);
            const vel_x_draw = state.rng.randTagged(callers.vel_x);
            const vel_y_draw = state.rng.randTagged(callers.vel_y);
            const scale_step_draw = if (scale_step == null) state.rng.randTagged(callers.scale_step) else 0;
            self.spawnBurstParticle(
                pos,
                rotation_draw,
                vel_x_draw,
                vel_y_draw,
                if (scale_step == null) scale_step_draw else null,
                scale_step,
                lifetime,
                color,
                detail_preset,
            );
        }
    }

    pub fn spawnBurstParticle(
        self: *EffectPool,
        pos: state_mod.Vec2,
        rotation_draw: u32,
        vel_x_draw: u32,
        vel_y_draw: u32,
        scale_step_draw: ?u32,
        scale_step: ?f32,
        lifetime: f32,
        color: Color,
        detail_preset: i32,
    ) void {
        const rotation = @as(f32, @floatFromInt(rotation_draw & 0x7F)) * 0.049087387;
        const velocity: state_mod.Vec2 = .{
            .x = @as(f32, @floatFromInt((vel_x_draw & 0x7F) -% 0x40)),
            .y = @as(f32, @floatFromInt((vel_y_draw & 0x7F) -% 0x40)),
        };
        const step = if (scale_step) |fixed|
            fixed
        else
            @as(f32, @floatFromInt(scale_step_draw.? % 100)) * 0.01 + 0.1;
        _ = self.spawn(
            @intFromEnum(EffectId.burst),
            pos,
            velocity,
            rotation,
            1.0,
            32.0,
            32.0,
            0.0,
            lifetime,
            0x1D,
            color,
            0.0,
            step,
            detail_preset,
        );
    }

    pub fn spawnRing(
        self: *EffectPool,
        pos: state_mod.Vec2,
        detail_preset: i32,
        color: Color,
        lifetime: f32,
        scale_step: f32,
    ) void {
        _ = self.spawn(
            @intFromEnum(EffectId.ring),
            pos,
            .{},
            0.0,
            1.0,
            32.0,
            32.0,
            0.0,
            lifetime,
            0x19,
            color,
            0.0,
            scale_step,
            detail_preset,
        );
    }

    pub fn spawnFreezeShard(
        self: *EffectPool,
        state: *state_mod.GameplayState,
        pos: state_mod.Vec2,
        angle: f32,
        detail_preset: i32,
    ) void {
        const lifetime = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.effect_spawn_freeze_shard_lifetime) & 0xF)) * 0.01 + 0.2;
        const base = narrowF32(angle + std.math.pi);
        const rotation = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.effect_spawn_freeze_shard_rotation) % 100)) * 0.01 + base;
        const half = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.effect_spawn_freeze_shard_half) % 5 + 7));
        const velocity = state_mod.Vec2.fromAngle(base).mul(114.0);
        const rotation_step = (@as(f32, @floatFromInt(state.rng.randTagged(rng_callers.effect_spawn_freeze_shard_rotation_step) % 20)) * 0.1 - 1.0) * 4.0;
        const scale_step = -@as(f32, @floatFromInt(state.rng.randTagged(rng_callers.effect_spawn_freeze_shard_scale_step) & 0xF)) * 0.1;
        const effect_id = @as(i32, @intCast(state.rng.randTagged(rng_callers.effect_spawn_freeze_shard_effect_id) % 3)) + 8;
        _ = self.spawn(
            effect_id,
            pos,
            velocity,
            rotation,
            1.0,
            half,
            half,
            0.0,
            lifetime,
            0x1CD,
            .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 0.5 },
            rotation_step,
            scale_step,
            detail_preset,
        );
    }

    pub fn spawnFreezeShatter(
        self: *EffectPool,
        state: *state_mod.GameplayState,
        pos: state_mod.Vec2,
        angle: f32,
        detail_preset: i32,
    ) void {
        const lifetime: f32 = 1.1;
        for (0..4) |idx| {
            const rotation = @as(f32, @floatFromInt(idx)) * (std.math.pi / 2.0) + angle;
            const velocity = state_mod.Vec2.fromAngle(rotation).mul(42.0);
            const half = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.effect_spawn_freeze_shatter_half) % 10 + 18));
            const rotation_step = (@as(f32, @floatFromInt(state.rng.randTagged(rng_callers.effect_spawn_freeze_shatter_rotation_step) % 20)) * 0.1 - 1.0) * 1.9;
            _ = self.spawn(
                @intFromEnum(EffectId.freeze_shatter),
                pos,
                velocity,
                rotation,
                1.0,
                half,
                half,
                0.0,
                lifetime,
                0x5D,
                .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 0.5 },
                rotation_step,
                0.0,
                detail_preset,
            );
        }
        for (0..4) |_| {
            const shard_angle = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.effect_spawn_freeze_shatter_shard_angle) % 612)) * 0.01;
            self.spawnFreezeShard(state, pos, shard_angle, detail_preset);
        }
    }

    pub fn spawnExplosionBurst(
        self: *EffectPool,
        state: *state_mod.GameplayState,
        pos: state_mod.Vec2,
        scale: f32,
        detail_preset: i32,
    ) void {
        _ = self.spawn(
            @intFromEnum(EffectId.ring),
            pos,
            .{},
            0.0,
            1.0,
            32.0,
            32.0,
            -0.1,
            0.35,
            0x19,
            .{ .r = 0.6, .g = 0.6, .b = 0.6, .a = 1.0 },
            0.0,
            scale * 25.0,
            detail_preset,
        );

        if (detail_preset > 3) {
            for (0..2) |idx| {
                const age = @as(f32, @floatFromInt(idx)) * 0.2 - 0.5;
                const lifetime = @as(f32, @floatFromInt(idx)) * 0.2 + 0.6;
                const rotation = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.effect_spawn_explosion_burst_puff_rotation) % 614)) * 0.02;
                _ = self.spawn(
                    @intFromEnum(EffectId.explosion_puff),
                    pos,
                    .{},
                    rotation,
                    1.0,
                    32.0,
                    32.0,
                    age,
                    lifetime,
                    0x5D,
                    .{ .r = 0.1, .g = 0.1, .b = 0.1, .a = 1.0 },
                    1.4,
                    scale * 5.0,
                    detail_preset,
                );
            }
        }

        _ = self.spawn(
            @intFromEnum(EffectId.burst),
            pos,
            .{},
            0.0,
            1.0,
            32.0,
            32.0,
            0.0,
            0.3,
            0x19,
            .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 1.0 },
            0.0,
            scale * 45.0,
            detail_preset,
        );

        const count: usize = if (detail_preset < 2) 1 else 3 + (if (detail_preset > 3) @as(usize, 1) else 0);
        for (0..count) |_| {
            const rotation = @as(f32, @floatFromInt(state.rng.randTagged(rng_callers.effect_spawn_explosion_burst_rotation) % 314)) * 0.02;
            const velocity: state_mod.Vec2 = .{
                .x = @as(f32, @floatFromInt((state.rng.randTagged(rng_callers.effect_spawn_explosion_burst_vel_x) & 0x3F) * 2 -% 0x40)),
                .y = @as(f32, @floatFromInt((state.rng.randTagged(rng_callers.effect_spawn_explosion_burst_vel_y) & 0x3F) * 2 -% 0x40)),
            };
            const scale_step = @as(f32, @floatFromInt((state.rng.randTagged(rng_callers.effect_spawn_explosion_burst_scale_step) -% 3) & 7)) * scale;
            const rotation_step = @as(f32, @floatFromInt((state.rng.randTagged(rng_callers.effect_spawn_explosion_burst_rotation_step) +% 3) & 7));
            _ = self.spawn(
                @intFromEnum(EffectId.explosion_burst),
                pos,
                velocity,
                rotation,
                1.0,
                32.0,
                32.0,
                0.0,
                0.7,
                0x1D,
                .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 1.0 },
                rotation_step,
                scale_step,
                detail_preset,
            );
        }
    }
};

test "effect update runs at zero dt without a lifetime epsilon" {
    var pool: EffectPool = .{};
    pool.entries[0] = .{
        .age = 1.0,
        .lifetime = 1.0,
        .flags = 1,
    };

    pool.update(0.0, null);
    try std.testing.expectEqual(@as(i32, 0), pool.entries[0].flags);

    pool.entries[1] = .{
        .age = 0.0,
        .lifetime = 1e-12,
        .flags = 0x10,
        .color = .{ .a = 0.25 },
    };
    pool.update(0.0, null);

    try std.testing.expectEqual(@as(i32, 0x10), pool.entries[1].flags);
    try std.testing.expectEqual(@as(f32, 1.0), pool.entries[1].color.a);
}

test "effect expiry stores terrain decal alpha before queueing" {
    var pool: EffectPool = .{};
    var queue: terrain_fx_mod.FxQueue = .{};
    pool.entries[0] = .{
        .effect_id = @intFromEnum(EffectId.casing),
        .age = 1.0,
        .lifetime = 1.0,
        .flags = 0x80,
        .color = .{ .a = 0.25 },
    };
    pool.entries[1] = .{
        .effect_id = @intFromEnum(EffectId.casing),
        .age = 1.0,
        .lifetime = 1.0,
        .flags = 0x180,
        .color = .{ .a = 0.25 },
    };

    pool.update(0.0, &queue);

    try std.testing.expectEqual(@as(i32, 0), pool.entries[0].flags);
    try std.testing.expectEqual(@as(i32, 0), pool.entries[1].flags);
    try std.testing.expectEqual(@as(f32, 0.8), pool.entries[0].color.a);
    try std.testing.expectEqual(@as(f32, 0.35), pool.entries[1].color.a);
    try std.testing.expectEqual(@as(usize, 2), queue.count);
    try std.testing.expectEqual(@as(f32, 0.8), queue.entries[0].color.a);
    try std.testing.expectEqual(@as(f32, 0.35), queue.entries[1].color.a);
}
