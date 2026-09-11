const std = @import("std");

const bonuses_runtime = @import("runtime/bonuses.zig");
const creature_lifecycle = @import("runtime/lifecycle.zig").CreatureLifecycle;
const creatures_runtime = @import("runtime/creatures.zig");
const game_ids = @import("game_ids.zig");
const native_math = @import("runtime/native_math.zig");
const runtime_anim = @import("runtime/anim.zig");
const spawn_runtime = @import("runtime/spawn.zig");

pub const AtlasRect = struct {
    x: f32,
    y: f32,
    width: f32,
    height: f32,
};

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
    .head_alpha_mul = 0.5,
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
    return effectRectById(texture_width, texture_height, @intFromEnum(effect_id));
}

pub fn effectRectById(texture_width: i32, texture_height: i32, effect_id_raw: i32) ?AtlasRect {
    const EffectEntry = struct {
        size_code: i32,
        frame: i32,
    };
    const entry = switch (effect_id_raw) {
        0x00 => EffectEntry{ .size_code = 0x80, .frame = 0x02 },
        0x01 => EffectEntry{ .size_code = 0x80, .frame = 0x03 },
        0x02 => EffectEntry{ .size_code = 0x20, .frame = 0x00 },
        0x03 => EffectEntry{ .size_code = 0x20, .frame = 0x01 },
        0x04 => EffectEntry{ .size_code = 0x20, .frame = 0x02 },
        0x05 => EffectEntry{ .size_code = 0x20, .frame = 0x03 },
        0x06 => EffectEntry{ .size_code = 0x20, .frame = 0x04 },
        0x07 => EffectEntry{ .size_code = 0x20, .frame = 0x05 },
        0x08 => EffectEntry{ .size_code = 0x20, .frame = 0x08 },
        0x09 => EffectEntry{ .size_code = 0x20, .frame = 0x09 },
        0x0A => EffectEntry{ .size_code = 0x20, .frame = 0x0A },
        0x0B => EffectEntry{ .size_code = 0x20, .frame = 0x0B },
        0x0C => EffectEntry{ .size_code = 0x40, .frame = 0x05 },
        0x0D => EffectEntry{ .size_code = 0x40, .frame = 0x03 },
        0x0E => EffectEntry{ .size_code = 0x40, .frame = 0x04 },
        0x0F => EffectEntry{ .size_code = 0x40, .frame = 0x05 },
        0x10 => EffectEntry{ .size_code = 0x40, .frame = 0x06 },
        0x11 => EffectEntry{ .size_code = 0x40, .frame = 0x07 },
        0x12 => EffectEntry{ .size_code = 0x10, .frame = 0x26 },
        else => return null,
    };
    const grid: i32 = switch (entry.size_code) {
        0x10 => 16,
        0x20 => 8,
        0x40 => 4,
        0x80 => 2,
        else => return null,
    };
    const rect = atlasRect(texture_width, texture_height, grid, entry.frame);
    return .{
        .x = rect.x,
        .y = rect.y,
        .width = @max(0.0, rect.width - 2.0),
        .height = @max(0.0, rect.height - 2.0),
    };
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
    const creature_type = std.enums.fromInt(spawn_runtime.CreatureTypeId, creature.type_id) orelse return null;
    const selection = runtime_anim.creatureAnimSelectFrame(
        creature.anim_phase,
        creature.lifecycle_stage,
        info.base,
        info.mirror,
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

/// The flash pass omits the shock offset for dying long-strip creatures.
pub fn creatureRenderFlashFrame(creature: creatures_runtime.CreatureState) ?CreatureRenderFrame {
    var flash = creature;
    if (flash.lifecycle_stage < 16.0) {
        flash.flags &= ~spawn_runtime.CreatureFlags.ranged_attack_shock;
    }
    return creatureRenderFrame(flash);
}

/// Native body blend order, lifecycle fading, and transition at PC24.
pub fn creatureRenderTint(
    base_tint: [4]f32,
    max_hp: f32,
    energizer_timer: f32,
    lifecycle_stage: f32,
    transition: f32,
) [4]f32 {
    var tint = base_tint;
    if (energizer_timer > 0.0 and max_hp < 500.0) {
        const blend = @min(energizer_timer, @as(f32, 1.0));
        const inverse = native_math.pc24Sub(@as(f32, 1.0), blend);
        const half_blend = native_math.pc24Mul(blend, @as(f32, 0.5));
        for (0..4) |channel| {
            tint[channel] = native_math.pc24Add(
                native_math.pc24Mul(inverse, tint[channel]),
                if (channel < 2) half_blend else blend,
            );
        }
    }
    if (lifecycle_stage < 0.0) {
        tint[3] = @max(@as(f32, 0.0), native_math.pc24Add(tint[3], native_math.pc24Mul(lifecycle_stage, @as(f32, 0.1))));
    }
    tint[3] = native_math.pc24Mul(tint[3], transition);
    return tint;
}

/// Native shadow alpha before Grim2D packs it into a byte.
pub fn creatureShadowAlpha(tint_alpha: f32, flags: u32, lifecycle_stage: f32, transition: f32) f32 {
    var alpha = native_math.pc24Mul(tint_alpha, @as(f32, 0.4));
    if (lifecycle_stage < 0.0) {
        const fade: f32 = if (runtime_anim.creatureAnimIsLongStrip(flags)) 0.5 else 0.1;
        alpha = @max(@as(f32, 0.0), native_math.pc24Add(alpha, native_math.pc24Mul(lifecycle_stage, fade)));
    }
    return native_math.pc24Mul(alpha, transition);
}

/// Grim2D truncates the scaled channel and keeps its low byte.
pub fn creatureColorByte(channel: f32) u8 {
    const scaled: i32 = @intFromFloat(native_math.pc24Mul(channel, @as(f32, 255.0)));
    return @truncate(@as(u32, @bitCast(scaled)));
}

pub fn creatureColorBytes(tint: [4]f32) [4]u8 {
    var result: [4]u8 = undefined;
    for (tint, 0..) |channel, index| result[index] = creatureColorByte(channel);
    return result;
}

/// Packed alpha from the native flash and Grim2D color-pointer paths at PC24.
pub fn creatureFlashAlphaByte(timer: f32, transition: f32) u8 {
    const fade = @min(native_math.pc24Mul(timer, @as(f32, 5.0)), @as(f32, 1.0));
    const alpha = native_math.pc24Mul(fade, transition);
    return creatureColorByte(alpha);
}

pub const CreatureHitFlash = struct {
    frame: CreatureRenderFrame,
    alpha: u8,
};

/// Select a flash in the current species pass after native body retirement.
pub fn creatureHitFlash(creature: creatures_runtime.CreatureState, type_id: i32, transition: f32) ?CreatureHitFlash {
    if (!creature.active or creature.type_id != type_id or
        creature.lifecycle_stage < -10.0 or creature.hit_flash_timer <= 0.0) return null;
    return .{
        .frame = creatureRenderFlashFrame(creature) orelse return null,
        .alpha = creatureFlashAlphaByte(creature.hit_flash_timer, transition),
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
    const type_id = std.enums.fromInt(game_ids.ProjectileTypeId, type_id_raw) orelse return null;
    return switch (type_id) {
        .pulse_gun => .{ .grid = 2, .frame = 0 },
        .splitter_gun => .{ .grid = 4, .frame = 3 },
        .blade_gun => .{ .grid = 4, .frame = 6 },
        .ion_minigun, .ion_cannon, .shrinkifier, .fire_bullets, .ion_rifle => .{ .grid = 4, .frame = 2 },
        else => null,
    };
}

pub fn knownProjectileRgb(type_id_raw: i32) ColorRgb {
    const type_id = std.enums.fromInt(game_ids.ProjectileTypeId, type_id_raw) orelse return .{ .r = 240, .g = 220, .b = 160 };
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
    const type_id = std.enums.fromInt(game_ids.ProjectileTypeId, type_id_raw) orelse return 4.0;
    return switch (type_id) {
        .assault_rifle => 6.0,
        .submachine_gun => 8.0,
        else => 4.0,
    };
}

pub fn isBeamType(type_id_raw: i32) bool {
    const type_id = std.enums.fromInt(game_ids.ProjectileTypeId, type_id_raw) orelse return false;
    return switch (type_id) {
        .ion_rifle, .ion_minigun, .ion_cannon, .fire_bullets => true,
        else => false,
    };
}

pub fn beamEffectScale(type_id_raw: i32) f32 {
    const type_id = std.enums.fromInt(game_ids.ProjectileTypeId, type_id_raw) orelse return 0.8;
    return switch (type_id) {
        .ion_minigun => 1.05,
        .ion_rifle => 2.2,
        .ion_cannon => 3.5,
        else => 0.8,
    };
}

pub fn isPlasmaParticleType(type_id_raw: i32) bool {
    const type_id = std.enums.fromInt(game_ids.ProjectileTypeId, type_id_raw) orelse return false;
    return switch (type_id) {
        .plasma_rifle, .plasma_minigun, .spider_plasma, .plasma_cannon, .shrinkifier => true,
        else => false,
    };
}

pub fn plasmaRenderConfig(type_id_raw: i32) PlasmaRenderConfig {
    const type_id = std.enums.fromInt(game_ids.ProjectileTypeId, type_id_raw) orelse return default_plasma_render_config;
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

test "creature atlas frames match native PC24 witnesses" {
    const Witness = struct {
        case: []const u8,
        slot: usize,
        type_id: i32,
        flags: u32,
        lifecycle_stage: f32,
        phase: f32,
        frame: i32,
        flash_frame: i32,
    };
    const parsed = try std.json.parseFromSlice(
        struct { fpcw: u16, witnesses: []const Witness },
        std.testing.allocator,
        @embedFile("runtime/testdata/creature-frame-selection.json"),
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 0x7F), parsed.value.fpcw);
    try std.testing.expectEqual(@as(usize, 2640), parsed.value.witnesses.len);
    for (parsed.value.witnesses) |witness| {
        errdefer std.debug.print("native creature frame {s}, slot {d}\n", .{ witness.case, witness.slot });
        const creature: creatures_runtime.CreatureState = .{
            .active = true,
            .type_id = witness.type_id,
            .flags = witness.flags,
            .lifecycle_stage = witness.lifecycle_stage,
            .anim_phase = witness.phase,
        };
        try std.testing.expectEqual(witness.frame, creatureRenderFrame(creature).?.frame);
        try std.testing.expectEqual(witness.flash_frame, creatureRenderFlashFrame(creature).?.frame);
    }
}

test "creature body and shadow color words match native PC24 witnesses" {
    const Creature = struct {
        index: usize,
        flags: u32,
        lifecycle_stage: f32,
        max_health: f32,
        tint_r: f32,
        tint_g: f32,
        tint_b: f32,
        tint_a: f32,
    };
    const Draw = struct { pass: enum { shadow, body, flash }, index: usize, rgba_bits: [4]u32, packed_color: u32 };
    const Case = struct {
        input: struct { name: []const u8, energizer: f32, transition: f32, creatures: []Creature },
        expected: []Draw,
    };
    const parsed = try std.json.parseFromSlice(
        struct { fpcw: u16, cases: []Case },
        std.testing.allocator,
        @embedFile("runtime/testdata/creature-render-colors.json"),
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 0x7F), parsed.value.fpcw);
    try std.testing.expectEqual(@as(usize, 40), parsed.value.cases.len);
    var checked: usize = 0;
    for (parsed.value.cases) |case| {
        for (case.expected) |draw| {
            if (draw.pass == .flash) continue;
            errdefer std.debug.print("native creature color {s}, index {d}, pass {s}\n", .{ case.input.name, draw.index, @tagName(draw.pass) });
            const creature = for (case.input.creatures) |creature| {
                if (creature.index == draw.index) break creature;
            } else return error.MissingCreature;
            if (draw.pass == .body) {
                const tint = creatureRenderTint(
                    .{ creature.tint_r, creature.tint_g, creature.tint_b, creature.tint_a },
                    creature.max_health,
                    case.input.energizer,
                    creature.lifecycle_stage,
                    case.input.transition,
                );
                for (tint, draw.rgba_bits) |channel, bits| {
                    try std.testing.expectEqual(bits, @as(u32, @bitCast(channel)));
                }
                const rgba = creatureColorBytes(tint);
                const packed_color = (@as(u32, rgba[3]) << 24) | (@as(u32, rgba[0]) << 16) |
                    (@as(u32, rgba[1]) << 8) | @as(u32, rgba[2]);
                try std.testing.expectEqual(draw.packed_color, packed_color);
            } else {
                const alpha = creatureShadowAlpha(creature.tint_a, creature.flags, creature.lifecycle_stage, case.input.transition);
                try std.testing.expectEqual(draw.rgba_bits[3], @as(u32, @bitCast(alpha)));
                try std.testing.expectEqual(@as(u8, @truncate(draw.packed_color >> 24)), creatureColorByte(alpha));
            }
            checked += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2160), checked);
}

test "creature flash selection and packed alpha match native witnesses" {
    const Creature = struct {
        index: usize,
        active: u8,
        type_id: i32,
        hit_flash_timer: f32,
        lifecycle_stage: f32,
        flags: u32,
        anim_phase: f32,
    };
    const Draw = struct { slot: usize, frame: i32, packed_color: u32 };
    const Case = struct {
        input: struct { name: []const u8, type_id: i32, transition: f32, flash: u8, creatures: []Creature },
        expected: []Draw,
    };
    const parsed = try std.json.parseFromSlice(
        struct { fpcw: u16, render: []Case },
        std.testing.allocator,
        @embedFile("runtime/testdata/creature-hit-flash.json"),
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 0x7F), parsed.value.fpcw);
    try std.testing.expectEqual(@as(usize, 84), parsed.value.render.len);
    for (parsed.value.render) |case| {
        errdefer std.debug.print("native hit-flash case {s}\n", .{case.input.name});
        var count: usize = 0;
        for (case.input.creatures) |row| {
            if (case.input.flash == 0) continue;
            const creature: creatures_runtime.CreatureState = .{
                .active = row.active != 0,
                .type_id = row.type_id,
                .hit_flash_timer = row.hit_flash_timer,
                .lifecycle_stage = row.lifecycle_stage,
                .flags = row.flags,
                .anim_phase = row.anim_phase,
            };
            const flash = creatureHitFlash(creature, case.input.type_id, case.input.transition) orelse continue;
            try std.testing.expect(count < case.expected.len);
            const expected = case.expected[count];
            try std.testing.expectEqual(expected.slot, row.index);
            try std.testing.expectEqual(expected.frame, flash.frame.frame);
            try std.testing.expectEqual(expected.packed_color, @as(u32, flash.alpha) << 24 | 0xFFFFFF);
            count += 1;
        }
        try std.testing.expectEqual(case.expected.len, count);
    }
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
