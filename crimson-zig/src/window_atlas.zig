const std = @import("std");

const bonuses_runtime = @import("runtime/bonuses.zig");
const creature_lifecycle = @import("runtime/lifecycle.zig").CreatureLifecycle;
const creatures_runtime = @import("runtime/creatures.zig");
const game_ids = @import("game_ids.zig");
const runtime_anim = @import("runtime/anim.zig");
const spawn_runtime = @import("runtime/spawn.zig");

pub const AtlasRect = struct {
    x: f32,
    y: f32,
    width: f32,
    height: f32,
};

pub const EffectId = enum(i32) {
    shield_ring = 0x02,
    glow = 0x0D,
    aura = 0x10,
};

pub const ColorRgb = struct {
    r: u8,
    g: u8,
    b: u8,
};

pub const ColorRgbf = struct {
    r: f32,
    g: f32,
    b: f32,
};

pub const KnownProjectileFrame = struct {
    grid: i32,
    frame: i32,
};

pub const PlasmaRenderConfig = struct {
    rgb: ColorRgbf,
    spacing: f32,
    seg_limit: i32,
    tail_size: f32,
    head_size: f32,
    head_alpha_mul: f32,
    aura_rgb: ColorRgbf,
    aura_size: f32,
    aura_alpha_mul: f32,
};

pub const CreatureTextureKind = enum {
    alien,
    lizard,
    spider_sp1,
    spider_sp2,
    trooper,
    zombie,
};

pub const CreatureRenderFrame = struct {
    texture_kind: CreatureTextureKind,
    frame: i32,
    lifecycle: creature_lifecycle.Phase,
};

const default_plasma_render_config: PlasmaRenderConfig = .{
    .rgb = .{ .r = 1.0, .g = 1.0, .b = 1.0 },
    .spacing = 2.1,
    .seg_limit = 3,
    .tail_size = 12.0,
    .head_size = 16.0,
    .head_alpha_mul = 0.45,
    .aura_rgb = .{ .r = 1.0, .g = 1.0, .b = 1.0 },
    .aura_size = 120.0,
    .aura_alpha_mul = 0.15,
};

pub fn atlasRect(texture_width: i32, texture_height: i32, grid: i32, frame: i32) AtlasRect {
    const safe_grid = @max(grid, 1);
    const cell_w = @as(f32, @floatFromInt(texture_width)) / @as(f32, @floatFromInt(safe_grid));
    const cell_h = @as(f32, @floatFromInt(texture_height)) / @as(f32, @floatFromInt(safe_grid));
    const safe_frame = @max(frame, 0);
    const col = @mod(safe_frame, safe_grid);
    const row = @divFloor(safe_frame, safe_grid);
    return .{
        .x = cell_w * @as(f32, @floatFromInt(col)),
        .y = cell_h * @as(f32, @floatFromInt(row)),
        .width = cell_w,
        .height = cell_h,
    };
}

pub fn atlasRectSpan(texture_width: i32, texture_height: i32, grid: i32, frame: i32, span_w: i32, span_h: i32) AtlasRect {
    const base = atlasRect(texture_width, texture_height, grid, frame);
    return .{
        .x = base.x,
        .y = base.y,
        .width = base.width * @as(f32, @floatFromInt(@max(span_w, 1))),
        .height = base.height * @as(f32, @floatFromInt(@max(span_h, 1))),
    };
}

pub fn effectRect(texture_width: i32, texture_height: i32, effect_id: EffectId) ?AtlasRect {
    const EffectEntry = struct {
        size_code: i32,
        frame: i32,
    };
    const entry = switch (effect_id) {
        .shield_ring => EffectEntry{ .size_code = 0x20, .frame = 0x00 },
        .glow => EffectEntry{ .size_code = 0x40, .frame = 0x03 },
        .aura => EffectEntry{ .size_code = 0x40, .frame = 0x06 },
    };
    const grid: i32 = switch (entry.size_code) {
        0x10 => 16,
        0x20 => 8,
        0x40 => 4,
        0x80 => 2,
        else => return null,
    };
    return atlasRect(texture_width, texture_height, grid, entry.frame);
}

pub fn bonusIconRect(texture_width: i32, texture_height: i32, icon_id: i32) AtlasRect {
    return atlasRect(texture_width, texture_height, 4, icon_id);
}

pub fn weaponIconRect(texture_width: i32, texture_height: i32, icon_index: i32) AtlasRect {
    return atlasRectSpan(texture_width, texture_height, 8, icon_index * 2, 2, 1);
}

pub fn bonusFade(time_left: f32, time_max: f32) f32 {
    if (!(time_left > 0.0) or !(time_max > 0.0)) return 0.0;
    if (time_left < 0.5) return std.math.clamp(time_left * 2.0, @as(f32, 0.0), @as(f32, 1.0));
    const age = time_max - time_left;
    if (age < 0.5) return std.math.clamp(age * 2.0, @as(f32, 0.0), @as(f32, 1.0));
    return 1.0;
}

pub fn creatureSizeScale(size: f32) f32 {
    return std.math.clamp(size / 64.0, @as(f32, 0.25), @as(f32, 2.0));
}

pub fn creatureRenderFrame(creature: creatures_runtime.CreatureState) ?CreatureRenderFrame {
    const info = runtime_anim.creatureAnimInfoForRawTypeId(creature.type_id) orelse return null;
    const creature_type = std.meta.intToEnum(spawn_runtime.CreatureTypeId, creature.type_id) catch return null;
    var phase = creature.anim_phase;
    if (runtime_anim.creatureAnimIsLongStrip(creature.flags)) {
        if (creature.lifecycle_stage < 0.0) {
            phase = -1.0;
        } else if (creature.lifecycle_stage < creature_lifecycle.alive) {
            phase = @as(f32, @floatFromInt(info.base + 0x0F)) - creature.lifecycle_stage - 0.5;
        }
    }

    const selection = runtime_anim.creatureAnimSelectFrame(
        phase,
        info.base,
        info.mirror and creature.lifecycle_stage >= creature_lifecycle.alive,
        creature.flags,
    );
    return .{
        .texture_kind = switch (creature_type) {
            .alien => .alien,
            .lizard => .lizard,
            .spider_sp1 => .spider_sp1,
            .spider_sp2 => .spider_sp2,
            .trooper => .trooper,
            .zombie => .zombie,
        },
        .frame = selection.frame,
        .lifecycle = creature_lifecycle.classify(creature.lifecycle_stage),
    };
}

pub fn bonusIconId(entry: bonuses_runtime.BonusEntry) ?i32 {
    return switch (entry.bonus_id) {
        .unused => null,
        .points => if (entry.amount == 1000) 13 else 12,
        .energizer => 10,
        .weapon => null,
        .weapon_power_up => 7,
        .nuke => 1,
        .double_experience => 4,
        .shock_chain => 3,
        .fireblast => 2,
        .reflex_boost => 5,
        .shield => 6,
        .freeze => 8,
        .medikit => 14,
        .speed => 9,
        .fire_bullets => 11,
    };
}

pub fn projectileKnownFrame(type_id_raw: i32) ?KnownProjectileFrame {
    const type_id = std.meta.intToEnum(game_ids.ProjectileTypeId, type_id_raw) catch return null;
    return switch (type_id) {
        .pulse_gun => .{ .grid = 2, .frame = 0 },
        .splitter_gun => .{ .grid = 4, .frame = 3 },
        .blade_gun => .{ .grid = 4, .frame = 6 },
        .ion_minigun, .ion_cannon, .shrinkifier, .fire_bullets, .ion_rifle => .{ .grid = 4, .frame = 2 },
        else => null,
    };
}

pub fn knownProjectileRgb(type_id_raw: i32) ColorRgb {
    const type_id = std.meta.intToEnum(game_ids.ProjectileTypeId, type_id_raw) catch return .{ .r = 240, .g = 220, .b = 160 };
    return switch (type_id) {
        .ion_rifle, .ion_minigun, .ion_cannon => .{ .r = 120, .g = 200, .b = 255 },
        .fire_bullets => .{ .r = 255, .g = 170, .b = 90 },
        .shrinkifier => .{ .r = 160, .g = 255, .b = 170 },
        .blade_gun => .{ .r = 240, .g = 120, .b = 255 },
        else => .{ .r = 240, .g = 220, .b = 160 },
    };
}

pub fn isBulletTrailType(type_id_raw: i32) bool {
    return (type_id_raw >= 0 and type_id_raw < 8) or
        type_id_raw == @intFromEnum(game_ids.ProjectileTypeId.splitter_gun);
}

pub fn bulletSpriteSize(type_id_raw: i32) f32 {
    const type_id = std.meta.intToEnum(game_ids.ProjectileTypeId, type_id_raw) catch return 4.0;
    return switch (type_id) {
        .assault_rifle => 6.0,
        .submachine_gun => 8.0,
        else => 4.0,
    };
}

pub fn isBeamType(type_id_raw: i32) bool {
    const type_id = std.meta.intToEnum(game_ids.ProjectileTypeId, type_id_raw) catch return false;
    return switch (type_id) {
        .ion_rifle, .ion_minigun, .ion_cannon, .fire_bullets => true,
        else => false,
    };
}

pub fn beamEffectScale(type_id_raw: i32) f32 {
    const type_id = std.meta.intToEnum(game_ids.ProjectileTypeId, type_id_raw) catch return 0.8;
    return switch (type_id) {
        .ion_minigun => 1.05,
        .ion_rifle => 2.2,
        .ion_cannon => 3.5,
        else => 0.8,
    };
}

pub fn isPlasmaParticleType(type_id_raw: i32) bool {
    const type_id = std.meta.intToEnum(game_ids.ProjectileTypeId, type_id_raw) catch return false;
    return switch (type_id) {
        .plasma_rifle, .plasma_minigun, .spider_plasma, .plasma_cannon, .shrinkifier => true,
        else => false,
    };
}

pub fn plasmaRenderConfig(type_id_raw: i32) PlasmaRenderConfig {
    const type_id = std.meta.intToEnum(game_ids.ProjectileTypeId, type_id_raw) catch return default_plasma_render_config;
    return switch (type_id) {
        .plasma_rifle => .{
            .rgb = .{ .r = 1.0, .g = 1.0, .b = 1.0 },
            .spacing = 2.5,
            .seg_limit = 8,
            .tail_size = 22.0,
            .head_size = 56.0,
            .head_alpha_mul = 0.45,
            .aura_rgb = .{ .r = 1.0, .g = 1.0, .b = 1.0 },
            .aura_size = 256.0,
            .aura_alpha_mul = 0.3,
        },
        .plasma_cannon => .{
            .rgb = .{ .r = 1.0, .g = 1.0, .b = 1.0 },
            .spacing = 2.6,
            .seg_limit = 18,
            .tail_size = 44.0,
            .head_size = 84.0,
            .head_alpha_mul = 0.45,
            .aura_rgb = .{ .r = 1.0, .g = 1.0, .b = 1.0 },
            .aura_size = 256.0,
            .aura_alpha_mul = 0.4,
        },
        .spider_plasma => .{
            .rgb = .{ .r = 0.3, .g = 1.0, .b = 0.3 },
            .spacing = default_plasma_render_config.spacing,
            .seg_limit = default_plasma_render_config.seg_limit,
            .tail_size = default_plasma_render_config.tail_size,
            .head_size = default_plasma_render_config.head_size,
            .head_alpha_mul = default_plasma_render_config.head_alpha_mul,
            .aura_rgb = .{ .r = 0.3, .g = 1.0, .b = 0.3 },
            .aura_size = default_plasma_render_config.aura_size,
            .aura_alpha_mul = default_plasma_render_config.aura_alpha_mul,
        },
        .shrinkifier => .{
            .rgb = .{ .r = 0.3, .g = 0.3, .b = 1.0 },
            .spacing = default_plasma_render_config.spacing,
            .seg_limit = default_plasma_render_config.seg_limit,
            .tail_size = default_plasma_render_config.tail_size,
            .head_size = default_plasma_render_config.head_size,
            .head_alpha_mul = default_plasma_render_config.head_alpha_mul,
            .aura_rgb = .{ .r = 0.3, .g = 0.3, .b = 1.0 },
            .aura_size = default_plasma_render_config.aura_size,
            .aura_alpha_mul = default_plasma_render_config.aura_alpha_mul,
        },
        else => default_plasma_render_config,
    };
}

test "weapon icon rect spans two ui wicon cells" {
    const rect = weaponIconRect(256, 256, 3);
    try std.testing.expectApproxEqAbs(@as(f32, 192.0), rect.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 64.0), rect.width, 1e-6);
}

test "bonus icon mapping mirrors metadata" {
    try std.testing.expectEqual(@as(?i32, 7), bonusIconId(.{ .bonus_id = .weapon_power_up }));
    try std.testing.expectEqual(@as(?i32, 13), bonusIconId(.{ .bonus_id = .points, .amount = 1000 }));
    try std.testing.expectEqual(@as(?i32, null), bonusIconId(.{ .bonus_id = .weapon }));
}

test "projectile lookup tables expose atlas fallback data" {
    const known = projectileKnownFrame(@intFromEnum(game_ids.ProjectileTypeId.ion_rifle)).?;
    try std.testing.expectEqual(@as(i32, 4), known.grid);
    try std.testing.expectEqual(@as(i32, 2), known.frame);
    try std.testing.expect(isBeamType(@intFromEnum(game_ids.ProjectileTypeId.fire_bullets)));
    try std.testing.expect(isPlasmaParticleType(@intFromEnum(game_ids.ProjectileTypeId.plasma_cannon)));
}
