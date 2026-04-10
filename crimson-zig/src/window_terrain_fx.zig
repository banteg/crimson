const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const window_assets = @import("window_assets.zig");
const window_atlas = cz.window_atlas;
const window_ground = @import("window_ground.zig");

const runtime_anim = cz.anim;
const game_ids = cz.game_ids;
const runtime_perks = cz.perks;
const projectiles_runtime = cz.projectiles;
const runtime_session = cz.session;
const secondary_projectiles_runtime = cz.secondary_projectiles;
const spawn_runtime = cz.spawn;
const state_mod = cz.state;

const max_decals_per_frame = 256;
const max_corpses_per_frame = 64;
const nearby_creature_radius_sq: f32 = 110.0 * 110.0;

const DecalBuffer = struct {
    items: [max_decals_per_frame]window_ground.GroundDecal = undefined,
    len: usize = 0,

    fn append(self: *DecalBuffer, item: window_ground.GroundDecal) void {
        if (self.len >= self.items.len) return;
        self.items[self.len] = item;
        self.len += 1;
    }

    fn slice(self: *const DecalBuffer) []const window_ground.GroundDecal {
        return self.items[0..self.len];
    }
};

const CorpseBuffer = struct {
    items: [max_corpses_per_frame]window_ground.GroundCorpseDecal = undefined,
    len: usize = 0,

    fn append(self: *CorpseBuffer, item: window_ground.GroundCorpseDecal) void {
        if (self.len >= self.items.len) return;
        self.items[self.len] = item;
        self.len += 1;
    }

    fn slice(self: *const CorpseBuffer) []const window_ground.GroundCorpseDecal {
        return self.items[0..self.len];
    }
};

const CreatureSnapshot = struct {
    active: bool = false,
    type_id: i32 = 0,
    pos: state_mod.Vec2 = .{},
    heading: f32 = 0.0,
    size: f32 = 0.0,
    lifecycle_stage: f32 = 0.0,
    flags: u32 = 0,
};

const ProjectileSnapshot = struct {
    active: bool = false,
    type_id: i32 = 0,
    origin: state_mod.Vec2 = .{},
    pos: state_mod.Vec2 = .{},
};

const SecondarySnapshot = struct {
    active: bool = false,
    type_id: secondary_projectiles_runtime.SecondaryProjectileTypeId = .none,
    pos: state_mod.Vec2 = .{},
    angle: f32 = 0.0,
};

pub const TerrainFxTracker = struct {
    rng: spawn_runtime.Crand = spawn_runtime.Crand.init(0xC01D_F00D),
    initialized: bool = false,
    prev_creatures: [cz.creatures.max_creatures]CreatureSnapshot = [_]CreatureSnapshot{.{}} ** cz.creatures.max_creatures,
    prev_projectiles: [projectiles_runtime.main_projectile_pool_size]ProjectileSnapshot = [_]ProjectileSnapshot{.{}} ** projectiles_runtime.main_projectile_pool_size,
    prev_secondary: [secondary_projectiles_runtime.secondary_projectile_pool_size]SecondarySnapshot = [_]SecondarySnapshot{.{}} ** secondary_projectiles_runtime.secondary_projectile_pool_size,

    pub fn init(seed: u32) TerrainFxTracker {
        return .{
            .rng = spawn_runtime.Crand.init(seed ^ 0x5A17_9C3D),
        };
    }

    pub fn capture(self: *TerrainFxTracker, session: *const runtime_session.DeterministicSession) void {
        for (session.creatures.entries, 0..) |creature, idx| {
            self.prev_creatures[idx] = .{
                .active = creature.active,
                .type_id = creature.type_id,
                .pos = creature.pos,
                .heading = creature.heading,
                .size = creature.size,
                .lifecycle_stage = creature.lifecycle_stage,
                .flags = creature.flags,
            };
        }
        for (session.projectiles.entries, 0..) |projectile, idx| {
            self.prev_projectiles[idx] = .{
                .active = projectile.active,
                .type_id = projectile.type_id,
                .origin = projectile.origin,
                .pos = projectile.pos,
            };
        }
        for (session.secondary_projectiles.entries, 0..) |projectile, idx| {
            self.prev_secondary[idx] = .{
                .active = projectile.active,
                .type_id = projectile.type_id,
                .pos = projectile.pos,
                .angle = projectile.angle,
            };
        }
        self.initialized = true;
    }

    pub fn bake(
        self: *TerrainFxTracker,
        session: *const runtime_session.DeterministicSession,
        ground: *window_ground.GroundRenderer,
        assets: *const window_assets.RuntimeAssets,
    ) void {
        if (!self.initialized) {
            self.capture(session);
            return;
        }

        defer self.capture(session);

        if (session.gore_disabled != 0) return;

        var decals: DecalBuffer = .{};
        var corpses: CorpseBuffer = .{};
        const freeze_active = session.state.bonuses.freeze > 0.0;
        const players = session.playersConst();
        const bloody_mess = players.len > 0 and runtime_perks.perkActive(&players[0], .bloody_mess_quick_learner);
        const particles_texture = assets.texture(.particles);

        self.collectCreatureDecals(session, freeze_active, particles_texture, &decals, &corpses);
        self.collectProjectileDecals(session, freeze_active, bloody_mess, particles_texture, &decals);
        self.collectSecondaryDecals(session, freeze_active, particles_texture, &decals);

        _ = ground.bakeDecals(decals.slice());
        _ = ground.bakeCorpseDecals(assets.texture(.bodyset), corpses.slice());
    }

    fn collectCreatureDecals(
        self: *TerrainFxTracker,
        session: *const runtime_session.DeterministicSession,
        freeze_active: bool,
        particles_texture: rl.Texture2D,
        decals: *DecalBuffer,
        corpses: *CorpseBuffer,
    ) void {
        for (self.prev_creatures, session.creatures.entries) |prev, creature| {
            if (!prev.active or !creature.active) continue;
            if (!(prev.lifecycle_stage > 0.0) or creature.lifecycle_stage > 0.0) continue;

            const corpse_size = @max(1.0, creature.size);
            const long_strip = runtime_anim.creatureAnimIsLongStrip(creature.flags);
            const corpse_type_id = if (long_strip) creature.type_id else 7;
            appendCorpseDecal(
                corpses,
                runtime_anim.creatureCorpseFrameForType(corpse_type_id),
                .{
                    .x = creature.pos.x - corpse_size * 0.5,
                    .y = creature.pos.y - corpse_size * 0.5,
                },
                corpse_size,
                creature.heading,
            );

            if (freeze_active) {
                self.queueFreezeCorpseShards(creature.pos, particles_texture, decals);
            } else if ((creature.flags & spawn_runtime.CreatureFlags.anim_ping_pong) != 0) {
                self.queueCorpseBloodBurst(creature.pos, particles_texture, decals);
            }
        }
    }

    fn collectProjectileDecals(
        self: *TerrainFxTracker,
        session: *const runtime_session.DeterministicSession,
        freeze_active: bool,
        bloody_mess: bool,
        particles_texture: rl.Texture2D,
        decals: *DecalBuffer,
    ) void {
        for (self.prev_projectiles, session.projectiles.entries) |prev, current| {
            if (!prev.active or current.active) continue;

            const target_pos = nearestCreaturePos(session.creatures.entries[0..], prev.pos) orelse continue;
            const base_angle = angleBetween(prev.origin, prev.pos);

            if (prev.type_id == @intFromEnum(game_ids.ProjectileTypeId.blade_gun)) {
                var idx: usize = 0;
                while (idx < 8) : (idx += 1) {
                    const angle = @as(f32, @floatFromInt(self.rng.rand() & 0xFF)) * 0.024543693;
                    self.queueBloodSplatter(target_pos, angle, 0.0, particles_texture, decals);
                }
            }

            if (bloody_mess) {
                var idx: usize = 0;
                while (idx < 8) : (idx += 1) {
                    const spread = (@as(f32, @floatFromInt(self.rng.rand() & 0x1F)) - 16.0) * 0.0625;
                    self.queueBloodSplatter(target_pos, base_angle + spread, 0.0, particles_texture, decals);
                }
                self.queueBloodSplatter(target_pos, base_angle + std.math.pi, 0.0, particles_texture, decals);

                var lo: i32 = -30;
                var hi: i32 = 30;
                while (lo > -60) : ({
                    lo -= 10;
                    hi += 10;
                }) {
                    const span: u32 = @intCast(hi - lo);
                    var band_idx: usize = 0;
                    while (band_idx < 2) : (band_idx += 1) {
                        const dx = @as(f32, @floatFromInt(@as(i32, @intCast(self.rng.rand() % span)) + lo));
                        const dy = @as(f32, @floatFromInt(@as(i32, @intCast(self.rng.rand() % span)) + lo));
                        self.queueRandomDecal(.{ .x = target_pos.x + dx, .y = target_pos.y + dy }, particles_texture, decals);
                    }
                }
            } else if (!freeze_active) {
                var idx: usize = 0;
                while (idx < 2) : (idx += 1) {
                    self.queueBloodSplatter(target_pos, base_angle, 0.0, particles_texture, decals);
                    if ((self.rng.rand() & 7) == 2) {
                        self.queueBloodSplatter(target_pos, base_angle + std.math.pi, 0.0, particles_texture, decals);
                    }
                }
            }

            _ = self.rng.rand();

            if (prev.type_id == @intFromEnum(game_ids.ProjectileTypeId.gauss_gun) or
                prev.type_id == @intFromEnum(game_ids.ProjectileTypeId.fire_bullets))
            {
                self.queueLargeHitStreak(target_pos, base_angle, freeze_active, particles_texture, decals);
                continue;
            }
            if (freeze_active) continue;

            var streak_idx: usize = 0;
            while (streak_idx < 3) : (streak_idx += 1) {
                const spread = (@as(f32, @floatFromInt(@as(i32, @intCast(self.rng.rand() % 20)) - 10))) * 0.1;
                const angle = base_angle + spread;
                const direction = state_mod.Vec2.fromAngle(angle).mul(20.0);
                self.queueRandomDecal(target_pos, particles_texture, decals);
                self.queueRandomDecal(state_mod.Vec2.add(target_pos, direction.mul(1.5)), particles_texture, decals);
                self.queueRandomDecal(state_mod.Vec2.add(target_pos, direction.mul(2.0)), particles_texture, decals);
                self.queueRandomDecal(state_mod.Vec2.add(target_pos, direction.mul(2.5)), particles_texture, decals);
            }
        }
    }

    fn collectSecondaryDecals(
        self: *TerrainFxTracker,
        session: *const runtime_session.DeterministicSession,
        freeze_active: bool,
        particles_texture: rl.Texture2D,
        decals: *DecalBuffer,
    ) void {
        for (self.prev_secondary, session.secondary_projectiles.entries) |prev, current| {
            if (!prev.active or prev.type_id == .detonation) continue;
            if (!current.active or current.type_id != .detonation) continue;

            const target_pos = nearestCreaturePos(session.creatures.entries[0..], prev.pos) orelse prev.pos;

            if (freeze_active) {
                var pre_idx: usize = 0;
                while (pre_idx < 4) : (pre_idx += 1) {
                    const shard_angle = @as(f32, @floatFromInt(self.rng.rand() % 612)) * 0.01;
                    self.queueFreezeShard(prev.pos, shard_angle, particles_texture, decals);
                }
            } else {
                var pre_idx: usize = 0;
                while (pre_idx < 3) : (pre_idx += 1) {
                    const dx = @as(f32, @floatFromInt(@as(i32, @intCast(self.rng.rand() % 20)) - 10));
                    const dy = @as(f32, @floatFromInt(@as(i32, @intCast(self.rng.rand() % 20)) - 10));
                    self.queueRandomDecal(.{ .x = target_pos.x + dx, .y = target_pos.y + dy }, particles_texture, decals);
                }
            }

            if (freeze_active) {
                const freeze_origin = if (prev.type_id == .rocket_minigun) target_pos else prev.pos;
                var idx: usize = 0;
                while (idx < 8) : (idx += 1) {
                    const shard_angle = @as(f32, @floatFromInt(self.rng.rand() % 612)) * 0.01;
                    self.queueFreezeShard(freeze_origin, shard_angle, particles_texture, decals);
                }
                continue;
            }

            const extra_decals: usize = switch (prev.type_id) {
                .rocket => 20,
                .homing_rocket => 10,
                .rocket_minigun => 3,
                else => 0,
            };
            const extra_radius: i32 = switch (prev.type_id) {
                .rocket => 90,
                .homing_rocket => 64,
                .rocket_minigun => 44,
                else => 0,
            };
            var idx: usize = 0;
            while (idx < extra_decals) : (idx += 1) {
                const angle = @as(f32, @floatFromInt(self.rng.rand() % 628)) * 0.01;
                const radius = if (prev.type_id == .homing_rocket)
                    @as(f32, @floatFromInt(self.rng.rand() & 0x3F))
                else
                    @as(f32, @floatFromInt(self.rng.rand() % @as(u32, @intCast(@max(extra_radius, 1)))));
                const offset = state_mod.Vec2.fromAngle(angle).mul(radius);
                self.queueRandomDecal(state_mod.Vec2.add(target_pos, offset), particles_texture, decals);
            }
        }
    }

    fn queueLargeHitStreak(
        self: *TerrainFxTracker,
        target_pos: state_mod.Vec2,
        base_angle: f32,
        freeze_active: bool,
        particles_texture: rl.Texture2D,
        decals: *DecalBuffer,
    ) void {
        const direction = state_mod.Vec2.fromAngle(base_angle);
        var idx: usize = 0;
        while (idx < 6) : (idx += 1) {
            var dist = @as(f32, @floatFromInt(self.rng.rand() % 100)) * 0.1;
            if (dist > 4.0) {
                dist = @as(f32, @floatFromInt(self.rng.rand() % 90 + 10)) * 0.1;
            }
            if (dist > 7.0) {
                dist = @as(f32, @floatFromInt(self.rng.rand() % 80 + 20)) * 0.1;
            }
            _ = self.rng.rand();
            const pos = state_mod.Vec2.add(target_pos, direction.mul(dist * 20.0));
            if (freeze_active) {
                const freeze_angle = base_angle + @as(f32, @floatFromInt(self.rng.rand() % 100)) * 0.01;
                self.queueFreezeShard(pos, freeze_angle, particles_texture, decals);
            } else {
                self.queueRandomDecal(pos, particles_texture, decals);
            }
        }
    }

    fn queueCorpseBloodBurst(
        self: *TerrainFxTracker,
        pos: state_mod.Vec2,
        particles_texture: rl.Texture2D,
        decals: *DecalBuffer,
    ) void {
        for ([_]struct { count: usize, age: f32 }{
            .{ .count = 8, .age = 0.0 },
            .{ .count = 6, .age = -0.07 },
            .{ .count = 5, .age = -0.12 },
        }) |spec| {
            var idx: usize = 0;
            while (idx < spec.count) : (idx += 1) {
                const angle = @as(f32, @floatFromInt(self.rng.rand() % 612)) * 0.01;
                self.queueBloodSplatter(pos, angle, spec.age, particles_texture, decals);
            }
        }
    }

    fn queueBloodSplatter(
        self: *TerrainFxTracker,
        pos: state_mod.Vec2,
        angle: f32,
        age: f32,
        particles_texture: rl.Texture2D,
        decals: *DecalBuffer,
    ) void {
        const lifetime = 0.25 - age;
        const base = angle + std.math.pi;
        const direction = state_mod.Vec2.fromAngle(base);

        var idx: usize = 0;
        while (idx < 2) : (idx += 1) {
            const rotation = @as(f32, @floatFromInt(@as(i32, @intCast(self.rng.rand() & 0x3F)) - 0x20)) * 0.1 + base;
            const half = @as(f32, @floatFromInt((self.rng.rand() & 7) + 1));
            const speed_x = @as(f32, @floatFromInt((self.rng.rand() & 0x3F) + 100));
            const speed_y = @as(f32, @floatFromInt((self.rng.rand() & 0x3F) + 100));
            _ = self.rng.rand();
            const velocity: state_mod.Vec2 = .{
                .x = direction.x * speed_x,
                .y = direction.y * speed_y,
            };
            const final_pos = state_mod.Vec2.add(pos, velocity.mul(lifetime));
            appendEffectDecal(
                decals,
                particles_texture,
                .blood_splatter,
                final_pos,
                half * 2.0,
                half * 2.0,
                rotation,
                colorFromFloats(1.0, 1.0, 1.0, 0.8),
            );
        }
    }

    fn queueFreezeShard(
        self: *TerrainFxTracker,
        pos: state_mod.Vec2,
        angle: f32,
        particles_texture: rl.Texture2D,
        decals: *DecalBuffer,
    ) void {
        const lifetime = @as(f32, @floatFromInt(self.rng.rand() & 0xF)) * 0.01 + 0.2;
        const base = angle + std.math.pi;
        const rotation = @as(f32, @floatFromInt(self.rng.rand() % 100)) * 0.01 + base;
        const half = @as(f32, @floatFromInt(self.rng.rand() % 5 + 7));
        const velocity = state_mod.Vec2.fromAngle(base).mul(114.0);
        _ = self.rng.rand();
        _ = self.rng.rand();
        const effect_id = switch (self.rng.rand() % 3) {
            0 => window_atlas.EffectId.freeze_shard_0,
            1 => window_atlas.EffectId.freeze_shard_1,
            else => window_atlas.EffectId.freeze_shard_2,
        };
        const final_pos = state_mod.Vec2.add(pos, velocity.mul(lifetime));
        appendEffectDecal(
            decals,
            particles_texture,
            effect_id,
            final_pos,
            half * 2.0,
            half * 2.0,
            rotation,
            colorFromFloats(1.0, 1.0, 1.0, 0.35),
        );
    }

    fn queueFreezeCorpseShards(
        self: *TerrainFxTracker,
        pos: state_mod.Vec2,
        particles_texture: rl.Texture2D,
        decals: *DecalBuffer,
    ) void {
        var idx: usize = 0;
        while (idx < 4) : (idx += 1) {
            const shard_angle = @as(f32, @floatFromInt(self.rng.rand() % 612)) * 0.01;
            self.queueFreezeShard(pos, shard_angle, particles_texture, decals);
        }
    }

    fn queueRandomDecal(
        self: *TerrainFxTracker,
        pos: state_mod.Vec2,
        particles_texture: rl.Texture2D,
        decals: *DecalBuffer,
    ) void {
        const gray = @as(f32, @floatFromInt(self.rng.rand() & 0xF)) * 0.01 + 0.84;
        const width = @as(f32, @floatFromInt(@as(i32, @intCast(self.rng.rand() % 24)) - 12)) + 30.0;
        const rotation = @as(f32, @floatFromInt(self.rng.rand() % 628)) * 0.01;
        const effect_id = switch (self.rng.rand() % 5) {
            0 => window_atlas.EffectId.effect_03,
            1 => window_atlas.EffectId.effect_04,
            2 => window_atlas.EffectId.effect_05,
            3 => window_atlas.EffectId.effect_06,
            else => window_atlas.EffectId.blood_splatter,
        };
        appendEffectDecal(
            decals,
            particles_texture,
            effect_id,
            pos,
            width,
            width,
            rotation,
            colorFromFloats(gray, gray, gray, 1.0),
        );
    }
};

fn appendEffectDecal(
    decals: *DecalBuffer,
    texture: rl.Texture2D,
    effect_id: window_atlas.EffectId,
    pos: state_mod.Vec2,
    width: f32,
    height: f32,
    rotation: f32,
    tint: rl.Color,
) void {
    const src = window_atlas.effectRectById(texture.width, texture.height, @intFromEnum(effect_id)) orelse return;
    decals.append(.{
        .texture = texture,
        .src = src,
        .pos = .{ .x = pos.x, .y = pos.y },
        .width = width,
        .height = height,
        .rotation_rad = rotation,
        .tint = tint,
    });
}

fn appendCorpseDecal(
    corpses: *CorpseBuffer,
    bodyset_frame: i32,
    top_left: state_mod.Vec2,
    size: f32,
    rotation: f32,
) void {
    corpses.append(.{
        .bodyset_frame = bodyset_frame,
        .top_left = .{ .x = top_left.x, .y = top_left.y },
        .size = size,
        .rotation_rad = rotation,
        .tint = colorFromFloats(1.0, 1.0, 1.0, 0.8),
    });
}

fn nearestCreaturePos(creatures: []const cz.creatures.CreatureState, pos: state_mod.Vec2) ?state_mod.Vec2 {
    var best: ?state_mod.Vec2 = null;
    var best_dist_sq = nearby_creature_radius_sq;
    for (creatures) |creature| {
        if (!creature.active) continue;
        const delta = state_mod.Vec2.sub(creature.pos, pos);
        const dist_sq = delta.lengthSq();
        if (dist_sq > best_dist_sq) continue;
        best = creature.pos;
        best_dist_sq = dist_sq;
    }
    return best;
}

fn angleBetween(origin: state_mod.Vec2, target: state_mod.Vec2) f32 {
    return state_mod.Vec2.sub(target, origin).toAngle();
}

fn colorFromFloats(r: f32, g: f32, b: f32, a: f32) rl.Color {
    return .{
        .r = @intFromFloat(std.math.clamp(r, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
        .g = @intFromFloat(std.math.clamp(g, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
        .b = @intFromFloat(std.math.clamp(b, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
        .a = @intFromFloat(std.math.clamp(a, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
    };
}
