const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const window_assets = @import("window_assets.zig");
const window_atlas = cz.window_atlas;

const creature_lifecycle = cz.lifecycle.CreatureLifecycle;
const game_ids = cz.game_ids;
const runtime_helpers = cz.helpers;
const runtime_perks = cz.perks;
const runtime_session = cz.session;
const secondary_projectiles_runtime = cz.secondary_projectiles;
const state_mod = cz.state;

const SecondaryRocketStyle = struct {
    base_size: f32,
    glow_size: f32,
    glow_rgb: window_atlas.ColorRgbf,
    glow_alpha_mul: f32,
};

const secondary_rocket_style_by_type = std.EnumArray(secondary_projectiles_runtime.SecondaryProjectileTypeId, ?SecondaryRocketStyle).init(.{
    .none = null,
    .rocket = .{
        .base_size = 14.0,
        .glow_size = 60.0,
        .glow_rgb = .{ .r = 1.0, .g = 1.0, .b = 1.0 },
        .glow_alpha_mul = 0.68,
    },
    .homing_rocket = .{
        .base_size = 10.0,
        .glow_size = 40.0,
        .glow_rgb = .{ .r = 1.0, .g = 1.0, .b = 1.0 },
        .glow_alpha_mul = 0.58,
    },
    .detonation = null,
    .rocket_minigun = .{
        .base_size = 8.0,
        .glow_size = 30.0,
        .glow_rgb = .{ .r = 0.7, .g = 0.7, .b = 1.0 },
        .glow_alpha_mul = 0.158,
    },
});

pub const DrawCtx = struct {
    session: *const runtime_session.DeterministicSession,
    assets: *const window_assets.RuntimeAssets,
    render_time_s: f32 = 0.0,
    entity_alpha: f32 = 1.0,
    flame_glow_enabled: bool = true,
};

pub fn drawMainProjectile(
    projectile: cz.projectiles.Projectile,
    proj_index: usize,
    ctx: DrawCtx,
) bool {
    if (drawBulletTrail(projectile, ctx)) return true;
    if (drawPlasmaParticles(projectile, ctx)) return true;
    if (drawBeamEffect(projectile, ctx)) return true;
    if (drawPulseGun(projectile, ctx)) return true;
    if (drawSplitterOrBlade(projectile, proj_index, ctx)) return true;
    if (drawPlagueSpreader(projectile, proj_index, ctx)) return true;
    if (window_atlas.projectileKnownFrame(projectile.type_id)) |known| {
        const rgb = window_atlas.knownProjectileRgb(projectile.type_id);
        drawAtlasFrameCenteredRotated(
            ctx.assets.texture(.projs),
            known.grid,
            known.frame,
            toRlVec(projectile.pos),
            0.6,
            projectile.angle,
            colorWithAlpha(
                rl.Color.init(rgb.r, rgb.g, rgb.b, 255),
                std.math.clamp(projectile.life_timer / 0.4, @as(f32, 0.0), @as(f32, 1.0)),
            ),
        );
        return true;
    }
    return false;
}

pub fn drawSecondaryProjectile(
    projectile: secondary_projectiles_runtime.SecondaryProjectile,
    ctx: DrawCtx,
) bool {
    if (drawSecondaryRocket(projectile, ctx)) return true;
    if (drawSecondaryDetonation(projectile, ctx)) return true;
    return false;
}

fn drawBulletTrail(projectile: cz.projectiles.Projectile, ctx: DrawCtx) bool {
    if (!window_atlas.isBulletTrailType(projectile.type_id)) return false;

    const start = toRlVec(projectile.origin);
    const end = toRlVec(projectile.pos);
    const segment = vecSub(end, start);
    const distance = vecLength(segment);
    const alpha = std.math.clamp(projectile.life_timer, @as(f32, 0.0), @as(f32, 1.0)) * ctx.entity_alpha;

    drawBulletTrailQuad(projectile.type_id, start, end, distance, projectile.angle, alpha, ctx.assets.texture(.bullet_trail));

    if (projectile.life_timer >= 0.39) {
        const size = window_atlas.bulletSpriteSize(projectile.type_id);
        drawTextureCenteredRotated(
            ctx.assets.texture(.bullet_i),
            end,
            size,
            size,
            radiansToDegrees(projectile.angle),
            colorWithAlpha(rl.Color.init(220, 220, 220, 255), alpha),
        );
    }
    return true;
}

fn drawPlasmaParticles(projectile: cz.projectiles.Projectile, ctx: DrawCtx) bool {
    if (!window_atlas.isPlasmaParticleType(projectile.type_id)) return false;

    const src_rect = window_atlas.effectRect(
        ctx.assets.texture(.particles).width,
        ctx.assets.texture(.particles).height,
        .glow,
    ) orelse return false;
    const cfg = window_atlas.plasmaRenderConfig(projectile.type_id);
    const alpha = if (projectile.life_timer >= 0.4)
        1.0
    else
        std.math.clamp(projectile.life_timer * 2.5, @as(f32, 0.0), @as(f32, 1.0));
    const origin = toRlVec(projectile.origin);
    const head = toRlVec(projectile.pos);
    const direction = vecNormalizeOr(vecSub(head, origin), .{ .x = 0.0, .y = -1.0 });

    rl.beginBlendMode(.additive);
    if (projectile.life_timer >= 0.4) {
        if (ctx.flame_glow_enabled) {
            var seg_count = @as(i32, @intFromFloat(projectile.travel_budget));
            if (seg_count < 0) seg_count = 0;
            seg_count = @divTrunc(seg_count, 5);
            if (seg_count > cfg.seg_limit) seg_count = cfg.seg_limit;

            var idx: i32 = 0;
            while (idx < seg_count) : (idx += 1) {
                const pos = vecAdd(head, vecScale(direction, -@as(f32, @floatFromInt(idx)) * cfg.spacing));
                drawTextureRegionCenteredRotated(
                    ctx.assets.texture(.particles),
                    src_rect,
                    pos,
                    cfg.tail_size,
                    cfg.tail_size,
                    0.0,
                    rgbfColor(cfg.rgb, alpha * 0.4 * ctx.entity_alpha),
                );
            }
        }

        drawTextureRegionCenteredRotated(
            ctx.assets.texture(.particles),
            src_rect,
            head,
            cfg.head_size,
            cfg.head_size,
            0.0,
            rgbfColor(cfg.rgb, alpha * cfg.head_alpha_mul * ctx.entity_alpha),
        );
        if (ctx.flame_glow_enabled) {
            drawTextureRegionCenteredRotated(
                ctx.assets.texture(.particles),
                src_rect,
                head,
                cfg.aura_size,
                cfg.aura_size,
                0.0,
                rgbfColor(cfg.aura_rgb, alpha * cfg.aura_alpha_mul * ctx.entity_alpha),
            );
        }
    } else {
        drawTextureRegionCenteredRotated(
            ctx.assets.texture(.particles),
            src_rect,
            head,
            56.0,
            56.0,
            0.0,
            colorWithAlpha(rl.Color.white, alpha * ctx.entity_alpha),
        );
    }
    rl.endBlendMode();
    return true;
}

fn drawBeamEffect(projectile: cz.projectiles.Projectile, ctx: DrawCtx) bool {
    if (!window_atlas.isBeamType(projectile.type_id)) return false;

    const origin = toRlVec(projectile.origin);
    const head = toRlVec(projectile.pos);
    const delta = vecSub(head, origin);
    const dist = vecLength(delta);
    if (!(dist > 1e-6)) return true;

    const direction = vecNormalizeOr(delta, .{ .x = 1.0, .y = 0.0 });
    const effect_scale = window_atlas.beamEffectScale(projectile.type_id);
    const start = if (dist > 256.0) dist - 256.0 else 0.0;
    const span = dist - start;
    const step = @min(effect_scale * 3.1, 9.0);
    const base_alpha = if (projectile.life_timer >= 0.4)
        1.0
    else
        std.math.clamp(projectile.life_timer * 2.5, @as(f32, 0.0), @as(f32, 1.0));
    const streak_rgb = if (projectile.type_id == @intFromEnum(game_ids.ProjectileTypeId.fire_bullets))
        rl.Color.init(255, 153, 26, 255)
    else
        rl.Color.init(128, 153, 255, 255);

    rl.beginBlendMode(.additive);
    var s: f32 = start;
    while (s < dist) : (s += step) {
        const t = if (span > 1e-6) (s - start) / span else 1.0;
        const seg_alpha = std.math.clamp(t * base_alpha, @as(f32, 0.0), @as(f32, 1.0));
        if (seg_alpha <= 1e-3) continue;
        const pos = vecAdd(origin, vecScale(direction, s));
        drawAtlasFrameCenteredRotated(
            ctx.assets.texture(.projs),
            4,
            2,
            pos,
            effect_scale,
            0.0,
            colorWithAlpha(streak_rgb, seg_alpha),
        );
    }

    const head_rgb = if (projectile.life_timer >= 0.4)
        rl.Color.init(255, 255, 179, 255)
    else
        rl.Color.init(128, 153, 255, 255);
    drawAtlasFrameCenteredRotated(
        ctx.assets.texture(.projs),
        4,
        2,
        head,
        effect_scale,
        projectile.angle,
        colorWithAlpha(head_rgb, base_alpha),
    );

    if (projectile.type_id == @intFromEnum(game_ids.ProjectileTypeId.fire_bullets)) {
        if (window_atlas.effectRect(ctx.assets.texture(.particles).width, ctx.assets.texture(.particles).height, .glow)) |src_rect| {
            drawTextureRegionCenteredRotated(
                ctx.assets.texture(.particles),
                src_rect,
                head,
                64.0,
                64.0,
                radiansToDegrees(projectile.angle),
                colorWithAlpha(rl.Color.white, base_alpha * ctx.entity_alpha),
            );
        }
    } else if (projectile.life_timer < 0.4 and isIonType(projectile.type_id)) {
        drawIonChains(projectile, effect_scale, base_alpha * ctx.entity_alpha, ctx);
    }

    rl.endBlendMode();
    return true;
}

fn drawPulseGun(projectile: cz.projectiles.Projectile, ctx: DrawCtx) bool {
    if (projectile.type_id != @intFromEnum(game_ids.ProjectileTypeId.pulse_gun)) return false;

    const known = window_atlas.projectileKnownFrame(projectile.type_id) orelse return true;
    const texture = ctx.assets.texture(.projs);
    const cell_w = @as(f32, @floatFromInt(texture.width)) / @as(f32, @floatFromInt(known.grid));
    if (!(cell_w > 1e-6)) return true;

    const alpha: f32 = ctx.entity_alpha;
    if (projectile.life_timer >= 0.4) {
        const dist = vecLength(vecSub(toRlVec(projectile.pos), toRlVec(projectile.origin)));
        const desired_size = dist * 0.16;
        if (!(desired_size > 1e-3)) return true;
        rl.beginBlendMode(.additive);
        drawAtlasFrameCenteredRotated(
            texture,
            known.grid,
            known.frame,
            toRlVec(projectile.pos),
            desired_size / cell_w,
            projectile.angle,
            colorWithAlpha(rl.Color.init(26, 153, 51, 255), alpha * 0.7),
        );
        rl.endBlendMode();
        return true;
    }

    const fade_alpha = std.math.clamp(projectile.life_timer * 2.5, @as(f32, 0.0), @as(f32, 1.0));
    if (fade_alpha <= 1e-3) return true;

    rl.beginBlendMode(.additive);
    drawAtlasFrameCenteredRotated(
        texture,
        known.grid,
        known.frame,
        toRlVec(projectile.pos),
        56.0 / cell_w,
        projectile.angle,
        colorWithAlpha(rl.Color.white, fade_alpha),
    );
    rl.endBlendMode();
    return true;
}

fn drawSplitterOrBlade(projectile: cz.projectiles.Projectile, proj_index: usize, ctx: DrawCtx) bool {
    if (projectile.type_id != @intFromEnum(game_ids.ProjectileTypeId.splitter_gun) and
        projectile.type_id != @intFromEnum(game_ids.ProjectileTypeId.blade_gun))
    {
        return false;
    }
    if (projectile.life_timer < 0.4) return true;

    const known = window_atlas.projectileKnownFrame(projectile.type_id) orelse return true;
    const texture = ctx.assets.texture(.projs);
    const cell_w = @as(f32, @floatFromInt(texture.width)) / @as(f32, @floatFromInt(known.grid));
    if (!(cell_w > 1e-6)) return true;

    const dist = vecLength(vecSub(toRlVec(projectile.pos), toRlVec(projectile.origin)));
    const desired_size = @min(dist, 20.0);
    if (!(desired_size > 1e-3)) return true;

    const rotation = if (projectile.type_id == @intFromEnum(game_ids.ProjectileTypeId.blade_gun))
        @as(f32, @floatFromInt(proj_index)) * 0.1 - ctx.render_time_s * 100.0
    else
        projectile.angle;
    const tint = if (projectile.type_id == @intFromEnum(game_ids.ProjectileTypeId.blade_gun))
        rl.Color.init(204, 204, 204, 255)
    else
        rl.Color.white;

    drawAtlasFrameCenteredRotated(
        texture,
        known.grid,
        known.frame,
        toRlVec(projectile.pos),
        desired_size / cell_w,
        rotation,
        tint,
    );
    return true;
}

fn drawPlagueSpreader(projectile: cz.projectiles.Projectile, proj_index: usize, ctx: DrawCtx) bool {
    if (projectile.type_id != @intFromEnum(game_ids.ProjectileTypeId.plague_spreader)) return false;

    const texture = ctx.assets.texture(.projs);
    const cell_w = @as(f32, @floatFromInt(texture.width)) / 4.0;
    if (!(cell_w > 1e-6)) return true;

    if (projectile.life_timer >= 0.4) {
        const tint = rl.Color.white;
        rl.beginBlendMode(.multiplied);
        drawPlagueQuad(texture, toRlVec(projectile.pos), 60.0, tint);

        const offset = runtime_helpers.directionFromHeading(projectile.angle).mul(15.0);
        drawPlagueQuad(
            texture,
            rl.Vector2.init(projectile.pos.x + offset.x, projectile.pos.y + offset.y),
            60.0,
            tint,
        );

        const phase = @as(f32, @floatFromInt(proj_index)) + ctx.render_time_s * 10.0;
        const cos_phase = std.math.cos(phase);
        const sin_phase = std.math.sin(phase);
        drawPlagueQuad(
            texture,
            rl.Vector2.init(projectile.pos.x + cos_phase * cos_phase - 5.0, projectile.pos.y + sin_phase * 11.0 - 5.0),
            52.0,
            tint,
        );

        const phase_120 = phase + 2.0943952;
        drawPlagueQuad(
            texture,
            rl.Vector2.init(projectile.pos.x + std.math.cos(phase_120) * 10.0, projectile.pos.y + std.math.sin(phase_120) * 10.0),
            62.0,
            tint,
        );

        const phase_240 = phase + 4.1887903;
        drawPlagueQuad(
            texture,
            rl.Vector2.init(projectile.pos.x + std.math.cos(phase_240) * 10.0, projectile.pos.y + std.math.sin(phase_240) * std.math.sin(phase_120)),
            62.0,
            tint,
        );
        rl.endBlendMode();
        return true;
    }

    const fade = std.math.clamp(projectile.life_timer * 2.5, @as(f32, 0.0), @as(f32, 1.0));
    if (fade <= 1e-3) return true;
    rl.beginBlendMode(.multiplied);
    drawPlagueQuad(
        texture,
        toRlVec(projectile.pos),
        fade * 40.0 + 32.0,
        colorWithAlpha(rl.Color.white, fade),
    );
    rl.endBlendMode();
    return true;
}

fn drawSecondaryRocket(
    projectile: secondary_projectiles_runtime.SecondaryProjectile,
    ctx: DrawCtx,
) bool {
    const style = secondary_rocket_style_by_type.get(projectile.type_id) orelse return false;
    const texture = ctx.assets.texture(.projs);
    const cell_w = @as(f32, @floatFromInt(texture.width)) / 4.0;
    if (!(cell_w > 1e-6)) return true;

    const alpha = secondaryAlpha(projectile);
    if (ctx.flame_glow_enabled) drawSecondaryRocketGlow(projectile, style, alpha * ctx.entity_alpha, ctx);
    drawAtlasFrameCenteredRotated(
        texture,
        4,
        3,
        toRlVec(projectile.pos),
        style.base_size / cell_w,
        projectile.angle,
        colorWithAlpha(rl.Color.init(204, 204, 204, 255), alpha * 0.9 * ctx.entity_alpha),
    );
    return true;
}

fn drawSecondaryRocketGlow(
    projectile: secondary_projectiles_runtime.SecondaryProjectile,
    style: SecondaryRocketStyle,
    alpha: f32,
    ctx: DrawCtx,
) void {
    const src_rect = window_atlas.effectRect(
        ctx.assets.texture(.particles).width,
        ctx.assets.texture(.particles).height,
        .glow,
    ) orelse return;
    const direction = runtime_helpers.directionFromHeading(projectile.angle);
    const center = toRlVec(projectile.pos);

    rl.beginBlendMode(.additive);
    drawTextureRegionCenteredRotated(
        ctx.assets.texture(.particles),
        src_rect,
        rl.Vector2.init(center.x - direction.x * 5.0, center.y - direction.y * 5.0),
        140.0,
        140.0,
        0.0,
        colorWithAlpha(rl.Color.white, alpha * 0.48),
    );
    drawTextureRegionCenteredRotated(
        ctx.assets.texture(.particles),
        src_rect,
        rl.Vector2.init(center.x - direction.x * 9.0, center.y - direction.y * 9.0),
        style.glow_size,
        style.glow_size,
        0.0,
        rgbfColor(style.glow_rgb, alpha * style.glow_alpha_mul),
    );
    rl.endBlendMode();
}

fn drawSecondaryDetonation(
    projectile: secondary_projectiles_runtime.SecondaryProjectile,
    ctx: DrawCtx,
) bool {
    if (projectile.type_id != .detonation) return false;

    const t = std.math.clamp(projectile.detonation_t, @as(f32, 0.0), @as(f32, 1.0));
    const fade = 1.0 - t;
    if (fade <= 1e-3 or projectile.detonation_scale <= 1e-6) return true;

    if (window_atlas.effectRect(ctx.assets.texture(.particles).width, ctx.assets.texture(.particles).height, .glow)) |src_rect| {
        rl.beginBlendMode(.additive);
        drawTextureRegionCenteredRotated(
            ctx.assets.texture(.particles),
            src_rect,
            toRlVec(projectile.pos),
            projectile.detonation_scale * t * 64.0,
            projectile.detonation_scale * t * 64.0,
            0.0,
            rgbfColor(.{ .r = 1.0, .g = 0.6, .b = 0.1 }, fade * ctx.entity_alpha),
        );
        if (ctx.flame_glow_enabled) {
            drawTextureRegionCenteredRotated(
                ctx.assets.texture(.particles),
                src_rect,
                toRlVec(projectile.pos),
                projectile.detonation_scale * t * 200.0,
                projectile.detonation_scale * t * 200.0,
                0.0,
                rgbfColor(.{ .r = 1.0, .g = 0.6, .b = 0.1 }, fade * 0.3 * ctx.entity_alpha),
            );
        }
        rl.endBlendMode();
    } else {
        rl.drawCircleLines(
            @intFromFloat(projectile.pos.x),
            @intFromFloat(projectile.pos.y),
            @max(1.0, projectile.detonation_scale * t * 80.0),
            colorWithAlpha(rl.Color.init(255, 180, 100, 255), fade),
        );
    }
    return true;
}

fn drawIonChains(
    projectile: cz.projectiles.Projectile,
    effect_scale: f32,
    base_alpha: f32,
    ctx: DrawCtx,
) void {
    const perk_scale: f32 = if (anyIonGunMaster(ctx.session.playersConst())) 1.2 else 1.0;
    const radius = effect_scale * perk_scale * 40.0;
    const head = projectile.pos;
    for (ctx.session.creatures.entries) |creature| {
        if (!creature.active) continue;
        if (!creature_lifecycle.isCollidable(creature.lifecycle_stage)) continue;
        if (!runtime_helpers.withinNativeFindRadius(head, creature.pos, radius, creature.size)) continue;
        drawIonChainSegment(head, creature.pos, effect_scale, base_alpha, ctx);
    }
}

fn drawIonChainSegment(
    start_world: state_mod.Vec2,
    end_world: state_mod.Vec2,
    effect_scale: f32,
    base_alpha: f32,
    ctx: DrawCtx,
) void {
    const start = toRlVec(start_world);
    const end = toRlVec(end_world);
    const delta = vecSub(end, start);
    const dist = vecLength(delta);
    if (!(dist > 1e-6)) return;
    const direction = vecNormalizeOr(delta, .{ .x = 1.0, .y = 0.0 });
    const side = rl.Vector2.init(-direction.y, direction.x);
    const outer_half = 14.0 * effect_scale;
    const inner_half = 10.0 * effect_scale;
    const tint = colorWithAlpha(rl.Color.init(128, 153, 255, 255), base_alpha);

    drawIonChainStrip(ctx.assets.texture(.projs), start, end, side, outer_half, tint);
    drawIonChainStrip(ctx.assets.texture(.projs), start, end, side, inner_half, tint);
    drawAtlasFrameCenteredRotated(
        ctx.assets.texture(.projs),
        4,
        2,
        end,
        effect_scale,
        0.0,
        tint,
    );
}

fn drawIonChainStrip(
    texture: rl.Texture2D,
    start: rl.Vector2,
    end: rl.Vector2,
    side: rl.Vector2,
    half_width: f32,
    tint: rl.Color,
) void {
    const side_offset = rl.Vector2.init(side.x * half_width, side.y * half_width);
    const p0 = rl.Vector2.init(start.x - side_offset.x, start.y - side_offset.y);
    const p1 = rl.Vector2.init(start.x + side_offset.x, start.y + side_offset.y);
    const p2 = rl.Vector2.init(end.x + side_offset.x, end.y + side_offset.y);
    const p3 = rl.Vector2.init(end.x - side_offset.x, end.y - side_offset.y);

    rl.gl.rlSetTexture(texture.id);
    rl.gl.rlBegin(rl.gl.rl_quads);
    rl.gl.rlColor4ub(tint.r, tint.g, tint.b, tint.a);
    rl.gl.rlTexCoord2f(0.625, 0.0);
    rl.gl.rlVertex2f(p0.x, p0.y);
    rl.gl.rlTexCoord2f(0.625, 0.25);
    rl.gl.rlVertex2f(p1.x, p1.y);
    rl.gl.rlTexCoord2f(0.625, 0.25);
    rl.gl.rlVertex2f(p2.x, p2.y);
    rl.gl.rlTexCoord2f(0.625, 0.0);
    rl.gl.rlVertex2f(p3.x, p3.y);
    rl.gl.rlEnd();
    rl.gl.rlSetTexture(0);
}

fn drawPlagueQuad(texture: rl.Texture2D, center: rl.Vector2, desired_size: f32, tint: rl.Color) void {
    const cell_w = @as(f32, @floatFromInt(texture.width)) / 4.0;
    if (!(cell_w > 1e-6)) return;
    drawAtlasFrameCenteredRotated(texture, 4, 2, center, desired_size / cell_w, 0.0, tint);
}

fn isIonType(type_id_raw: i32) bool {
    const type_id = std.enums.fromInt(game_ids.ProjectileTypeId, type_id_raw) orelse return false;
    return switch (type_id) {
        .ion_rifle, .ion_minigun, .ion_cannon => true,
        else => false,
    };
}

fn anyIonGunMaster(players: []const state_mod.PlayerState) bool {
    for (players) |player| {
        if (runtime_perks.perkActive(&player, .ion_gun_master)) return true;
    }
    return false;
}

fn secondaryAlpha(projectile: secondary_projectiles_runtime.SecondaryProjectile) f32 {
    return switch (projectile.type_id) {
        .detonation => std.math.clamp(1.0 - projectile.detonation_t * 0.5, @as(f32, 0.15), @as(f32, 1.0)),
        else => 1.0,
    };
}

fn toRlVec(vec: state_mod.Vec2) rl.Vector2 {
    return .{ .x = vec.x, .y = vec.y };
}

fn drawTextureCenteredRotated(texture: rl.Texture2D, center: rl.Vector2, width: f32, height: f32, rotation_deg: f32, tint: rl.Color) void {
    const src = rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height));
    const dest = rl.Rectangle.init(center.x, center.y, width, height);
    rl.drawTexturePro(texture, src, dest, rl.Vector2.init(width * 0.5, height * 0.5), rotation_deg, tint);
}

fn drawBulletTrailQuad(
    type_id: i32,
    start: rl.Vector2,
    end: rl.Vector2,
    distance: f32,
    angle: f32,
    alpha: f32,
    texture: rl.Texture2D,
) void {
    if (!(alpha > 1e-3)) return;

    const side_mul: f32 = switch (type_id) {
        @intFromEnum(game_ids.ProjectileTypeId.pistol),
        @intFromEnum(game_ids.ProjectileTypeId.assault_rifle),
        => 1.2,
        @intFromEnum(game_ids.ProjectileTypeId.gauss_gun) => 1.1,
        else => 0.7,
    };
    const half = 1.5 * side_mul;
    const side = if (distance > 1e-6) blk: {
        const inv_len = 1.0 / distance;
        break :blk rl.Vector2.init(-(end.y - start.y) * inv_len, (end.x - start.x) * inv_len);
    } else rl.Vector2.init(-std.math.sin(angle), std.math.cos(angle));

    const side_offset = rl.Vector2.init(side.x * half, side.y * half);
    const p0 = rl.Vector2.init(start.x - side_offset.x, start.y - side_offset.y);
    const p1 = rl.Vector2.init(start.x + side_offset.x, start.y + side_offset.y);
    const p2 = rl.Vector2.init(end.x + side_offset.x, end.y + side_offset.y);
    const p3 = rl.Vector2.init(end.x - side_offset.x, end.y - side_offset.y);

    const head = if (type_id == @intFromEnum(game_ids.ProjectileTypeId.gauss_gun))
        colorWithAlpha(rl.Color.init(51, 128, 255, 255), alpha)
    else
        colorWithAlpha(rl.Color.init(128, 128, 128, 255), alpha);
    const tail = rl.Color.init(128, 128, 128, 0);

    rl.beginBlendMode(.additive);
    rl.gl.rlSetTexture(texture.id);
    rl.gl.rlBegin(rl.gl.rl_quads);
    rl.gl.rlColor4ub(tail.r, tail.g, tail.b, tail.a);
    rl.gl.rlTexCoord2f(0.0, 0.0);
    rl.gl.rlVertex2f(p0.x, p0.y);
    rl.gl.rlColor4ub(tail.r, tail.g, tail.b, tail.a);
    rl.gl.rlTexCoord2f(1.0, 0.0);
    rl.gl.rlVertex2f(p1.x, p1.y);
    rl.gl.rlColor4ub(head.r, head.g, head.b, head.a);
    rl.gl.rlTexCoord2f(1.0, 0.5);
    rl.gl.rlVertex2f(p2.x, p2.y);
    rl.gl.rlColor4ub(head.r, head.g, head.b, head.a);
    rl.gl.rlTexCoord2f(0.0, 0.5);
    rl.gl.rlVertex2f(p3.x, p3.y);
    rl.gl.rlEnd();
    rl.gl.rlSetTexture(0);
    rl.endBlendMode();
}

fn drawTextureRegionCenteredRotated(
    texture: rl.Texture2D,
    src_rect: window_atlas.AtlasRect,
    center: rl.Vector2,
    width: f32,
    height: f32,
    rotation_deg: f32,
    tint: rl.Color,
) void {
    const src = rl.Rectangle.init(src_rect.x, src_rect.y, src_rect.width, src_rect.height);
    const dest = rl.Rectangle.init(center.x, center.y, width, height);
    rl.drawTexturePro(texture, src, dest, rl.Vector2.init(width * 0.5, height * 0.5), rotation_deg, tint);
}

fn drawAtlasFrameCenteredRotated(
    texture: rl.Texture2D,
    grid: i32,
    frame: i32,
    center: rl.Vector2,
    scale: f32,
    rotation_rad: f32,
    tint: rl.Color,
) void {
    const src_rect = window_atlas.atlasRect(texture.width, texture.height, grid, frame);
    drawTextureRegionCenteredRotated(
        texture,
        src_rect,
        center,
        src_rect.width * scale,
        src_rect.height * scale,
        radiansToDegrees(rotation_rad),
        tint,
    );
}

fn radiansToDegrees(radians: f32) f32 {
    return radians * (180.0 / std.math.pi);
}

fn vecSub(a: rl.Vector2, b: rl.Vector2) rl.Vector2 {
    return .{ .x = a.x - b.x, .y = a.y - b.y };
}

fn vecAdd(a: rl.Vector2, b: rl.Vector2) rl.Vector2 {
    return .{ .x = a.x + b.x, .y = a.y + b.y };
}

fn vecScale(vec: rl.Vector2, scale: f32) rl.Vector2 {
    return .{ .x = vec.x * scale, .y = vec.y * scale };
}

fn vecLength(vec: rl.Vector2) f32 {
    return std.math.sqrt(vec.x * vec.x + vec.y * vec.y);
}

fn vecNormalizeOr(vec: rl.Vector2, fallback: rl.Vector2) rl.Vector2 {
    const len = vecLength(vec);
    if (!(len > 1e-6)) return fallback;
    return .{ .x = vec.x / len, .y = vec.y / len };
}

fn colorWithAlpha(color: rl.Color, alpha: f32) rl.Color {
    return rl.Color.init(
        color.r,
        color.g,
        color.b,
        @intFromFloat(std.math.clamp(alpha, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
    );
}

fn rgbfColor(rgb: window_atlas.ColorRgbf, alpha: f32) rl.Color {
    return .{
        .r = @intFromFloat(std.math.clamp(rgb.r, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
        .g = @intFromFloat(std.math.clamp(rgb.g, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
        .b = @intFromFloat(std.math.clamp(rgb.b, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
        .a = @intFromFloat(std.math.clamp(alpha, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
    };
}
