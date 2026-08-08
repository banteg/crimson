const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const window_assets = @import("window_assets.zig");
const window_atlas = cz.window_atlas;

const effects_runtime = cz.effects;
const runtime_particles = cz.particles;
const runtime_session = cz.session;
const state_mod = cz.state;

pub const DrawCtx = struct {
    session: *const runtime_session.DeterministicSession,
    assets: *const window_assets.RuntimeAssets,
    entity_alpha: f32 = 1.0,
    flame_glow_enabled: bool = true,
    smoke_enabled: bool = true,
};

pub fn drawParticlePool(ctx: DrawCtx) void {
    const texture = ctx.assets.texture(.particles);
    const src_large = window_atlas.effectRectById(texture.width, texture.height, @intFromEnum(window_atlas.EffectId.glow)) orelse return;
    const src_normal = window_atlas.effectRectById(texture.width, texture.height, @intFromEnum(window_atlas.EffectId.explosion_burst)) orelse return;
    const src_style_8 = window_atlas.effectRectById(texture.width, texture.height, @intFromEnum(window_atlas.EffectId.shield_ring)) orelse return;

    rl.beginBlendMode(.additive);
    if (ctx.flame_glow_enabled) {
        for (ctx.session.particles.entries, 0..) |entry, idx| {
            if (!entry.active or entry.style_id == .bubblegun or (idx & 1) != 0) continue;
            const radius = @max((std.math.sin((1.0 - entry.intensity) * std.math.pi / 2.0) + 0.1) * 55.0 + 4.0, 16.0);
            drawTextureRegionCenteredRotated(
                texture,
                src_large,
                toRlVec(entry.pos),
                radius * 2.0,
                radius * 2.0,
                0.0,
                colorWithAlpha(rl.Color.white, 0.065 * ctx.entity_alpha),
            );
        }
    }

    for (ctx.session.particles.entries) |entry| {
        if (!entry.active or entry.style_id == .bubblegun) continue;
        var radius = std.math.sin((1.0 - entry.intensity) * std.math.pi / 2.0) * 24.0;
        if (entry.style_id == .blow_torch) radius *= 0.8;
        radius = @max(radius, 2.0);
        drawTextureRegionCenteredRotated(
            texture,
            src_normal,
            toRlVec(entry.pos),
            radius * 2.0,
            radius * 2.0,
            radiansToDegrees(entry.spin),
            rlColorFromRgbAlpha(entry.scale_x, entry.scale_y, entry.scale_z, entry.age * ctx.entity_alpha),
        );
    }

    for (ctx.session.particles.entries) |entry| {
        if (!entry.active or entry.style_id != .bubblegun) continue;
        const wobble = std.math.sin(entry.spin) * 3.0;
        const half_h = (wobble + 15.0) * entry.scale_x * 7.0;
        const half_w = (15.0 - wobble) * entry.scale_x * 7.0;
        drawTextureRegionCenteredRotated(
            texture,
            src_style_8,
            toRlVec(entry.pos),
            half_w * 2.0,
            half_h * 2.0,
            0.0,
            colorWithAlpha(rl.Color.white, entry.age * ctx.entity_alpha),
        );
    }
    rl.endBlendMode();
}

pub fn drawSpriteEffectPool(ctx: DrawCtx) void {
    if (!ctx.smoke_enabled) return;
    const texture = ctx.assets.texture(.particles);
    const src = window_atlas.atlasRect(texture.width, texture.height, 4, 7);

    rl.beginBlendMode(.alpha);
    for (ctx.session.sprite_effects.entries) |entry| {
        if (!entry.active) continue;
        drawTextureRegionCenteredRotated(
            texture,
            src,
            toRlVec(entry.pos),
            entry.scale,
            entry.scale,
            radiansToDegrees(entry.rotation),
            rlColorFromRgbAlpha(entry.color.r, entry.color.g, entry.color.b, entry.color.a * ctx.entity_alpha),
        );
    }
    rl.endBlendMode();
}

pub fn drawEffectPool(ctx: DrawCtx) void {
    const texture = ctx.assets.texture(.particles);

    rl.beginBlendMode(.alpha);
    for (ctx.session.effects.entries) |entry| {
        if (entry.flags == 0 or entry.age < 0.0 or (entry.flags & 0x40) == 0) continue;
        drawEffectEntryScaled(texture, entry, ctx.entity_alpha);
    }
    rl.endBlendMode();

    rl.beginBlendMode(.additive);
    for (ctx.session.effects.entries) |entry| {
        if (entry.flags == 0 or entry.age < 0.0 or (entry.flags & 0x40) != 0) continue;
        drawEffectEntryScaled(texture, entry, ctx.entity_alpha);
    }
    rl.endBlendMode();
}

fn drawEffectEntryScaled(texture: rl.Texture, entry: effects_runtime.EffectEntry, entity_alpha: f32) void {
    const src = window_atlas.effectRectById(texture.width, texture.height, entry.effect_id) orelse return;
    drawTextureRegionCenteredRotated(
        texture,
        src,
        toRlVec(entry.pos),
        entry.half_width * 2.0 * entry.scale,
        entry.half_height * 2.0 * entry.scale,
        radiansToDegrees(entry.rotation),
        rlColorFromRgbAlpha(entry.color.r, entry.color.g, entry.color.b, entry.color.a * entity_alpha),
    );
}

fn rlColorFromRgbAlpha(r: f32, g: f32, b: f32, a: f32) rl.Color {
    return rl.Color.init(
        floatByte(r),
        floatByte(g),
        floatByte(b),
        floatByte(a),
    );
}

fn floatByte(value: f32) u8 {
    return @intFromFloat(std.math.clamp(value, @as(f32, 0.0), @as(f32, 1.0)) * 255.0 + 0.5);
}

fn colorWithAlpha(color: rl.Color, alpha: f32) rl.Color {
    return rl.Color.init(color.r, color.g, color.b, floatByte(alpha));
}

fn toRlVec(vec: state_mod.Vec2) rl.Vector2 {
    return .{ .x = vec.x, .y = vec.y };
}

fn radiansToDegrees(radians: f32) f32 {
    return radians * (180.0 / std.math.pi);
}

fn drawTextureRegionCenteredRotated(
    texture: rl.Texture,
    src_rect: window_atlas.AtlasRect,
    center: rl.Vector2,
    width: f32,
    height: f32,
    rotation_deg: f32,
    tint: rl.Color,
) void {
    if (!(width > 0.0) or !(height > 0.0)) return;
    const dst = rl.Rectangle.init(center.x, center.y, width, height);
    const origin = rl.Vector2.init(width * 0.5, height * 0.5);
    const src = rl.Rectangle.init(src_rect.x, src_rect.y, src_rect.width, src_rect.height);
    rl.drawTexturePro(texture, src, dst, origin, rotation_deg, tint);
}
