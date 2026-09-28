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
const state_mod = cz.state;

const ProjectileTypeId = game_ids.ProjectileTypeId;

pub const DrawCtx = struct {
    session: *const runtime_session.DeterministicSession,
    assets: *const window_assets.RuntimeAssets,
    render_time_s: f32 = 0.0,
    entity_alpha: f32 = 1.0,
    flame_glow_enabled: bool = true,
};

/// Native `projectile_render`: each pass walks a whole pool with one texture and
/// blend before the next starts. Only the Gauss trail ignores `entity_alpha`, so
/// at zero transition it is all that shows.
pub fn projectileRender(ctx: DrawCtx) void {
    sharpshooterLaserPass(ctx);
    bulletTrailPass(ctx);
    if (ctx.entity_alpha <= 1e-3) return;
    plasmaGlowPass(ctx);
    projectileSpritePass(ctx);
    plaguePass(ctx);
    fireBulletsGlowPass(ctx);
    bulletHeadPass(ctx);
    secondaryGlowPass(ctx);
    rocketSpritePass(ctx);
    rocketExhaustPass(ctx);
}

/// Detonation flashes; native `bonus_render` draws them after the particle pool.
pub fn secondaryDetonationPass(ctx: DrawCtx) void {
    const texture = ctx.assets.texture(.particles);
    const src = glowRect(texture);
    rl.beginBlendMode(.additive);
    defer rl.endBlendMode();
    for (ctx.session.secondary_projectiles.entries) |projectile| {
        if (!projectile.active or projectile.type_id != .detonation) continue;
        const t = std.math.clamp(projectile.detonation_t, @as(f32, 0.0), @as(f32, 1.0));
        const fade = 1.0 - t;
        const center = toRlVec(projectile.pos);
        const size = projectile.detonation_scale * t;
        drawSprite(texture, src, center, size * 64.0, 0.0, tint(1.0, 0.6, 0.1, fade));
        drawSprite(texture, src, center, size * 200.0, 0.0, tint(1.0, 0.6, 0.1, fade * 0.3));
    }
}

fn sharpshooterLaserPass(ctx: DrawCtx) void {
    if (ctx.entity_alpha <= 1e-3) return;
    const players = ctx.session.playersConst();
    // Native reads the perk from player 0 and draws a laser for every living player.
    if (players.len == 0 or !runtime_perks.perkActive(&players[0], .sharpshooter)) return;
    const texture = ctx.assets.texture(.bullet_trail);
    rl.beginBlendMode(.additive);
    defer rl.endBlendMode();
    for (players) |player| {
        if (player.health <= 0.0) continue;
        const heading = player.aim_heading - std.math.pi / 2.0;
        const start_heading = heading - 0.150915;
        const pos = toRlVec(player.pos);
        const start = vecAdd(pos, .{ .x = @cos(start_heading) * 15.0, .y = @sin(start_heading) * 15.0 });
        const end = vecAdd(pos, .{ .x = @cos(heading) * 512.0, .y = @sin(heading) * 512.0 });
        const half_width: rl.Vector2 = .{ .x = @cos(player.aim_heading) * 1.1, .y = @sin(player.aim_heading) * 1.1 };
        drawTrailQuad(.{
            .points = .{ vecSub(start, half_width), vecAdd(start, half_width), vecAdd(end, half_width), vecSub(end, half_width) },
            .tail = tint(1.0, 0.0, 0.0, ctx.entity_alpha * 0.5),
            .head = tint(0.0, 0.0, 0.0, ctx.entity_alpha * 0.2),
        }, texture);
    }
}

fn bulletTrailPass(ctx: DrawCtx) void {
    const texture = ctx.assets.texture(.bullet_trail);
    rl.beginBlendMode(.additive);
    defer rl.endBlendMode();
    for (ctx.session.projectiles.entries) |projectile| {
        if (!projectile.active) continue;
        if (!(projectile.type_id <= 7 or projectile.type_id == @intFromEnum(ProjectileTypeId.splitter_gun))) continue;
        drawTrailQuad(bulletTrailQuad(projectile, ctx.entity_alpha), texture);
    }
}

const PlasmaGlow = struct {
    rgb: [3]f32,
    divisor: f32,
    step: f32,
    cap: i32,
    tail_size: f32,
    head_size: f32,
    head_alpha: f32,
    aura_size: f32,
    aura_alpha: f32,
};

fn plasmaGlow(type_id: ProjectileTypeId) ?PlasmaGlow {
    return switch (type_id) {
        .plasma_rifle => .{ .rgb = .{ 1.0, 1.0, 1.0 }, .divisor = 2.5, .step = 2.5, .cap = 8, .tail_size = 22.0, .head_size = 56.0, .head_alpha = 0.45, .aura_size = 256.0, .aura_alpha = 0.3 },
        .plasma_minigun => .{ .rgb = .{ 1.0, 1.0, 1.0 }, .divisor = 2.1, .step = 2.1, .cap = 3, .tail_size = 12.0, .head_size = 16.0, .head_alpha = 0.5, .aura_size = 120.0, .aura_alpha = 0.15 },
        .plasma_cannon => .{ .rgb = .{ 1.0, 1.0, 1.0 }, .divisor = 3.5, .step = 2.6, .cap = 18, .tail_size = 44.0, .head_size = 84.0, .head_alpha = 0.45, .aura_size = 256.0, .aura_alpha = 0.4 },
        .spider_plasma => .{ .rgb = .{ 0.3, 1.0, 0.3 }, .divisor = 2.1, .step = 2.1, .cap = 3, .tail_size = 12.0, .head_size = 16.0, .head_alpha = 0.5, .aura_size = 120.0, .aura_alpha = 0.15 },
        .shrinkifier => .{ .rgb = .{ 0.3, 0.3, 1.0 }, .divisor = 2.1, .step = 2.1, .cap = 3, .tail_size = 12.0, .head_size = 16.0, .head_alpha = 0.5, .aura_size = 120.0, .aura_alpha = 0.15 },
        else => null,
    };
}

/// Native converts the distance and the scaled divisor to integers before dividing.
fn plasmaSegmentCount(distance: f32, speed_scale: f32, divisor: f32, cap: i32) i32 {
    const distance_i: i32 = @intFromFloat(distance);
    const divisor_i: i32 = @intFromFloat(speed_scale * divisor);
    if (distance_i <= 0 or divisor_i <= 0) return 0;
    return @min(@divTrunc(distance_i, divisor_i), cap);
}

fn plasmaGlowPass(ctx: DrawCtx) void {
    const texture = ctx.assets.texture(.particles);
    const src = glowRect(texture);
    rl.beginBlendMode(.additive);
    defer rl.endBlendMode();
    for (ctx.session.projectiles.entries) |projectile| {
        if (!projectile.active) continue;
        const type_id = std.enums.fromInt(ProjectileTypeId, projectile.type_id) orelse continue;
        const glow = plasmaGlow(type_id) orelse continue;
        const head = toRlVec(projectile.pos);
        if (projectile.life_timer < 0.4) {
            const fade = std.math.clamp(projectile.life_timer * 2.5, @as(f32, 0.0), @as(f32, 1.0));
            drawSprite(texture, src, head, 56.0, 0.0, tint(1.0, 1.0, 1.0, fade * ctx.entity_alpha));
            continue;
        }
        const r, const g, const b = glow.rgb;
        const segments = plasmaSegmentCount(
            vecLength(vecSub(toRlVec(projectile.origin), head)),
            projectile.speed_scale,
            glow.divisor,
            glow.cap,
        );
        // The stored angle is a quarter turn ahead of travel; the tail steps back along it.
        const step = runtime_helpers.directionFromHeading(projectile.angle).mul(-projectile.speed_scale * glow.step);
        var index: i32 = 0;
        while (index < segments) : (index += 1) {
            const offset = step.mul(@floatFromInt(index));
            drawSprite(texture, src, vecAdd(head, toRlVec(offset)), glow.tail_size, 0.0, tint(r, g, b, ctx.entity_alpha * 0.4));
        }
        drawSprite(texture, src, head, glow.head_size, 0.0, tint(r, g, b, ctx.entity_alpha * glow.head_alpha));
        if (ctx.flame_glow_enabled) {
            drawSprite(texture, src, head, glow.aura_size, 0.0, tint(r, g, b, ctx.entity_alpha * glow.aura_alpha));
        }
    }
}

fn projectileSpritePass(ctx: DrawCtx) void {
    const texture = ctx.assets.texture(.projs);
    const alpha = ctx.entity_alpha;
    rl.beginBlendMode(.additive);
    defer rl.endBlendMode();
    for (ctx.session.projectiles.entries, 0..) |projectile, proj_index| {
        if (!projectile.active) continue;
        const type_id = std.enums.fromInt(ProjectileTypeId, projectile.type_id) orelse continue;
        const life = projectile.life_timer;
        const center = toRlVec(projectile.pos);
        const dist = vecLength(vecSub(center, toRlVec(projectile.origin)));
        switch (type_id) {
            .pulse_gun => if (life >= 0.4) {
                drawAtlasCell(texture, 2, 0, center, dist * 0.16, projectile.angle, tint(0.1, 0.6, 0.2, alpha * 0.7));
            } else {
                const fade = std.math.clamp(life * 2.5, @as(f32, 0.0), @as(f32, 1.0));
                drawAtlasCell(texture, 2, 0, center, 56.0, projectile.angle, tint(1.0, 1.0, 1.0, fade * alpha));
            },
            .splitter_gun => if (life >= 0.4) {
                drawAtlasCell(texture, 4, 3, center, @min(dist, 20.0), projectile.angle, tint(1.0, 1.0, 1.0, alpha));
            },
            .blade_gun => if (life >= 0.4) {
                const rotation = @as(f32, @floatFromInt(proj_index)) * 0.1 - ctx.render_time_s * 100.0;
                drawAtlasCell(texture, 4, 6, center, @min(dist, 20.0), rotation, tint(0.8, 0.8, 0.8, alpha));
            },
            .ion_minigun => drawStreak(ctx, texture, projectile, 1.05, true),
            .ion_rifle => drawStreak(ctx, texture, projectile, 2.2, true),
            .ion_cannon => drawStreak(ctx, texture, projectile, 3.5, true),
            .fire_bullets => drawStreak(ctx, texture, projectile, 0.8, false),
            else => {},
        }
    }
}

/// Ion and Fire Bullets streak: the last 256 units of the path, then its head.
/// After impact the head dims to a small blue core and an ion shot arcs to every
/// creature within reach.
fn drawStreak(
    ctx: DrawCtx,
    texture: rl.Texture2D,
    projectile: cz.projectiles.Projectile,
    effect_scale: f32,
    chain: bool,
) void {
    const in_flight = projectile.life_timer >= 0.4;
    const base_alpha = if (in_flight)
        ctx.entity_alpha
    else
        std.math.clamp(projectile.life_timer * 2.5, @as(f32, 0.0), @as(f32, 1.0)) * ctx.entity_alpha;
    const origin = toRlVec(projectile.origin);
    const head = toRlVec(projectile.pos);
    const delta = vecSub(head, origin);
    const dist = vecLength(delta);
    if (!(dist > 1e-6)) return;
    const direction = vecScale(delta, 1.0 / dist);
    const cell = @as(f32, @floatFromInt(texture.width)) / 4.0;
    const rgb: [3]f32 = if (chain) .{ 0.5, 0.6, 1.0 } else .{ 1.0, 0.6, 0.1 };

    const start = if (dist > 256.0) dist - 256.0 else 0.0;
    const span = dist - start;
    const step = @min(effect_scale * 3.1, 9.0);
    var along: f32 = start;
    while (along < dist) : (along += step) {
        const t = if (span > 1e-6) (along - start) / span else 1.0;
        drawAtlasCell(texture, 4, 2, vecAdd(origin, vecScale(direction, along)), cell * effect_scale, 0.0, tint(rgb[0], rgb[1], rgb[2], t * base_alpha));
    }

    if (in_flight) {
        drawAtlasCell(texture, 4, 2, head, cell * effect_scale, projectile.angle, tint(1.0, 1.0, 0.7, base_alpha));
        return;
    }
    // The fading core is one unscaled cell whatever the streak's scale.
    drawAtlasCell(texture, 4, 2, head, cell, projectile.angle, tint(0.5, 0.6, 1.0, base_alpha));
    if (!chain) return;

    const reach = effect_scale * (if (anyIonGunMaster(ctx.session.playersConst())) @as(f32, 1.2) else 1.0) * 40.0;
    const chain_tint = tint(0.5, 0.6, 1.0, base_alpha);
    // Native walks `creature_find_in_radius(pos, reach, 1)`: the inner strip, the
    // outer strip, then the glow on that creature, one creature at a time.
    for (ctx.session.creatures.entries[1..]) |creature| {
        if (!creature.active) continue;
        if (!creature_lifecycle.isCollidable(creature.lifecycle_stage)) continue;
        if (!runtime_helpers.withinNativeFindRadius(projectile.pos, creature.pos, reach, creature.size)) continue;
        const target = toRlVec(creature.pos);
        const to_target = vecSub(target, head);
        const length = vecLength(to_target);
        if (!(length > 1e-6)) continue;
        const side: rl.Vector2 = .{ .x = -to_target.y / length, .y = to_target.x / length };
        drawIonChainStrip(texture, head, target, side, 10.0 * effect_scale, chain_tint);
        drawIonChainStrip(texture, head, target, side, 14.0 * effect_scale, chain_tint);
        drawAtlasCell(texture, 4, 2, target, cell * effect_scale, 0.0, chain_tint);
    }
}

fn drawIonChainStrip(
    texture: rl.Texture2D,
    start: rl.Vector2,
    end: rl.Vector2,
    side: rl.Vector2,
    half_width: f32,
    color: rl.Color,
) void {
    const offset = vecScale(side, half_width);
    const points = [_]rl.Vector2{ vecSub(start, offset), vecAdd(start, offset), vecAdd(end, offset), vecSub(end, offset) };
    const vs = [_]f32{ 0.0, 0.25, 0.25, 0.0 };

    rl.gl.rlSetTexture(texture.id);
    rl.gl.rlBegin(rl.gl.rl_quads);
    rl.gl.rlColor4ub(color.r, color.g, color.b, color.a);
    for (points, vs) |point, v| {
        rl.gl.rlTexCoord2f(0.625, v);
        rl.gl.rlVertex2f(point.x, point.y);
    }
    rl.gl.rlEnd();
    rl.gl.rlSetTexture(0);
}

fn plaguePass(ctx: DrawCtx) void {
    const texture = ctx.assets.texture(.projs);
    const alpha = ctx.entity_alpha;
    // Native switches to D3D8 SRC=ZERO / DST=INVSRCALPHA: the cloud darkens what lies under it.
    rl.gl.rlSetBlendFactors(rl.gl.rl_zero, rl.gl.rl_one_minus_src_alpha, rl.gl.rl_func_add);
    rl.beginBlendMode(.custom);
    rl.gl.rlSetBlendFactors(rl.gl.rl_zero, rl.gl.rl_one_minus_src_alpha, rl.gl.rl_func_add);
    defer rl.endBlendMode();
    for (ctx.session.projectiles.entries, 0..) |projectile, proj_index| {
        if (!projectile.active or projectile.type_id != @intFromEnum(ProjectileTypeId.plague_spreader)) continue;
        const pos = toRlVec(projectile.pos);
        if (projectile.life_timer < 0.4) {
            const fade = std.math.clamp(projectile.life_timer * 2.5, @as(f32, 0.0), @as(f32, 1.0));
            drawAtlasCell(texture, 4, 2, pos, fade * 40.0 + 32.0, 0.0, tint(1.0, 1.0, 1.0, fade * alpha));
            continue;
        }
        const color = tint(1.0, 1.0, 1.0, alpha);
        const behind = runtime_helpers.directionFromHeading(projectile.angle).mul(-15.0);
        const phase = @as(f32, @floatFromInt(proj_index)) + ctx.render_time_s * 10.0;
        const phase_120 = phase + 2.0943952;
        const phase_240 = phase + 4.1887903;
        const puffs = [_]struct { offset: rl.Vector2, size: f32 }{
            .{ .offset = .{ .x = 0.0, .y = 0.0 }, .size = 60.0 },
            .{ .offset = toRlVec(behind), .size = 60.0 },
            .{ .offset = .{ .x = @cos(phase) * @cos(phase) - 5.0, .y = @sin(phase) * 11.0 - 5.0 }, .size = 52.0 },
            .{ .offset = .{ .x = @cos(phase_120) * 10.0, .y = @sin(phase_120) * 10.0 }, .size = 62.0 },
            .{ .offset = .{ .x = @cos(phase_240) * 10.0, .y = @sin(phase_240) * @sin(phase_120) }, .size = 62.0 },
        };
        for (puffs) |puff| drawAtlasCell(texture, 4, 2, vecAdd(pos, puff.offset), puff.size, 0.0, color);
    }
}

fn fireBulletsGlowPass(ctx: DrawCtx) void {
    const texture = ctx.assets.texture(.particles);
    const src = glowRect(texture);
    rl.beginBlendMode(.additive);
    defer rl.endBlendMode();
    for (ctx.session.projectiles.entries) |projectile| {
        if (!projectile.active or projectile.life_timer < 0.4) continue;
        if (projectile.type_id != @intFromEnum(ProjectileTypeId.fire_bullets)) continue;
        drawSprite(texture, src, toRlVec(projectile.pos), 64.0, projectile.angle, tint(1.0, 1.0, 1.0, ctx.entity_alpha));
    }
}

fn bulletHeadPass(ctx: DrawCtx) void {
    const texture = ctx.assets.texture(.bullet_i);
    const src: window_atlas.AtlasRect = .{ .x = 0.0, .y = 0.0, .width = @floatFromInt(texture.width), .height = @floatFromInt(texture.height) };
    const color = tint(0.8, 0.8, 0.8, ctx.entity_alpha * 0.9);
    for (ctx.session.projectiles.entries) |projectile| {
        if (!projectile.active or projectile.life_timer < 0.4) continue;
        const size: f32 = switch (projectile.type_id) {
            @intFromEnum(ProjectileTypeId.plasma_rifle),
            @intFromEnum(ProjectileTypeId.plasma_minigun),
            @intFromEnum(ProjectileTypeId.pulse_gun),
            => continue,
            @intFromEnum(ProjectileTypeId.pistol) => 6.0,
            4 => 8.0,
            else => 4.0,
        };
        drawSprite(texture, src, toRlVec(projectile.pos), size, projectile.angle, color);
    }
}

fn secondaryGlowPass(ctx: DrawCtx) void {
    if (!ctx.flame_glow_enabled) return;
    const texture = ctx.assets.texture(.particles);
    const src = glowRect(texture);
    rl.beginBlendMode(.additive);
    defer rl.endBlendMode();
    for (ctx.session.secondary_projectiles.entries) |projectile| {
        if (!projectile.active) continue;
        const center = projectile.pos.sub(runtime_helpers.directionFromHeading(projectile.angle).mul(5.0));
        drawSprite(texture, src, toRlVec(center), 140.0, 0.0, tint(1.0, 1.0, 1.0, ctx.entity_alpha * 0.48));
    }
}

fn rocketSpritePass(ctx: DrawCtx) void {
    const texture = ctx.assets.texture(.projs);
    const color = tint(0.8, 0.8, 0.8, ctx.entity_alpha * 0.9);
    for (ctx.session.secondary_projectiles.entries) |projectile| {
        if (!projectile.active) continue;
        const size: f32 = switch (projectile.type_id) {
            .rocket => 14.0,
            .homing_rocket => 10.0,
            .rocket_minigun => 8.0,
            .none, .detonation => continue,
        };
        drawAtlasCell(texture, 4, 3, toRlVec(projectile.pos), size, projectile.angle, color);
    }
}

fn rocketExhaustPass(ctx: DrawCtx) void {
    if (!ctx.flame_glow_enabled) return;
    const texture = ctx.assets.texture(.particles);
    const src = glowRect(texture);
    const alpha = ctx.entity_alpha;
    rl.beginBlendMode(.additive);
    defer rl.endBlendMode();
    for (ctx.session.secondary_projectiles.entries) |projectile| {
        if (!projectile.active) continue;
        const exhaust: struct { size: f32, color: rl.Color } = switch (projectile.type_id) {
            .rocket_minigun => .{ .size = 30.0, .color = tint(0.7, 0.7, 1.0, alpha * 0.158) },
            .rocket => .{ .size = 60.0, .color = tint(1.0, 1.0, 1.0, alpha * 0.68) },
            .homing_rocket => .{ .size = 40.0, .color = tint(1.0, 1.0, 1.0, alpha * 0.58) },
            .none, .detonation => continue,
        };
        const center = projectile.pos.sub(runtime_helpers.directionFromHeading(projectile.angle).mul(9.0));
        drawSprite(texture, src, toRlVec(center), exhaust.size, 0.0, exhaust.color);
    }
}

fn anyIonGunMaster(players: []const state_mod.PlayerState) bool {
    for (players) |player| {
        if (runtime_perks.perkActive(&player, .ion_gun_master)) return true;
    }
    return false;
}

/// `particles` effect 13, the glow every additive projectile pass selects.
fn glowRect(texture: rl.Texture2D) window_atlas.AtlasRect {
    return window_atlas.effectRect(texture.width, texture.height, .glow).?;
}

fn toRlVec(vec: state_mod.Vec2) rl.Vector2 {
    return .{ .x = vec.x, .y = vec.y };
}

/// Two quad corners at the origin (`tail`) and two at the head (`head`), textured
/// with the top half of the trail texture.
const TrailQuad = struct {
    points: [4]rl.Vector2,
    tail: rl.Color,
    head: rl.Color,
};

fn bulletTrailQuad(projectile: cz.projectiles.Projectile, transition_alpha: f32) TrailQuad {
    const side_mul: f32 = switch (projectile.type_id) {
        @intFromEnum(ProjectileTypeId.assault_rifle) => 1.0,
        @intFromEnum(ProjectileTypeId.pistol) => 1.2,
        @intFromEnum(ProjectileTypeId.gauss_gun) => 1.1,
        else => 0.7,
    };
    // Native 0x423108/0x423120 uses stored vel, already scaled by 1.5 at spawn.
    const side_offset = vecScale(toRlVec(projectile.vel), side_mul);
    const start = toRlVec(projectile.origin);
    const end = toRlVec(projectile.pos);
    const life_alpha = std.math.clamp(projectile.life_timer, @as(f32, 0.0), @as(f32, 1.0));
    const is_gauss = projectile.type_id == @intFromEnum(ProjectileTypeId.gauss_gun);
    // Native 0x42334e overwrites Gauss slots 2/3 with life, without transition.
    return .{
        .points = .{
            vecSub(start, side_offset),
            vecAdd(start, side_offset),
            vecAdd(end, side_offset),
            vecSub(end, side_offset),
        },
        .head = if (is_gauss)
            colorWithAlpha(rl.Color.init(51, 127, 255, 255), life_alpha)
        else
            colorWithAlpha(rl.Color.init(127, 127, 127, 255), life_alpha * transition_alpha),
        .tail = rl.Color.init(127, 127, 127, 0),
    };
}

fn drawTrailQuad(quad: TrailQuad, texture: rl.Texture2D) void {
    if (quad.head.a == 0 and quad.tail.a == 0) return;
    const colors = [_]rl.Color{ quad.tail, quad.tail, quad.head, quad.head };
    const uvs = [_][2]f32{ .{ 0.0, 0.0 }, .{ 1.0, 0.0 }, .{ 1.0, 0.5 }, .{ 0.0, 0.5 } };

    rl.gl.rlSetTexture(texture.id);
    rl.gl.rlBegin(rl.gl.rl_quads);
    for (quad.points, colors, uvs) |point, color, uv| {
        rl.gl.rlColor4ub(color.r, color.g, color.b, color.a);
        rl.gl.rlTexCoord2f(uv[0], uv[1]);
        rl.gl.rlVertex2f(point.x, point.y);
    }
    rl.gl.rlEnd();
    rl.gl.rlSetTexture(0);
}

/// Draw `src` as a `size`-wide square centered on `center`.
fn drawSprite(
    texture: rl.Texture2D,
    src: window_atlas.AtlasRect,
    center: rl.Vector2,
    size: f32,
    rotation_rad: f32,
    color: rl.Color,
) void {
    rl.drawTexturePro(
        texture,
        rl.Rectangle.init(src.x, src.y, src.width, src.height),
        rl.Rectangle.init(center.x, center.y, size, size),
        rl.Vector2.init(size * 0.5, size * 0.5),
        rotation_rad * (180.0 / std.math.pi),
        color,
    );
}

/// Draw one cell of a `grid`x`grid` atlas as a `size`-wide square centered on `center`.
fn drawAtlasCell(
    texture: rl.Texture2D,
    grid: i32,
    frame: i32,
    center: rl.Vector2,
    size: f32,
    rotation_rad: f32,
    color: rl.Color,
) void {
    drawSprite(texture, window_atlas.atlasRect(texture.width, texture.height, grid, frame), center, size, rotation_rad, color);
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

fn colorWithAlpha(color: rl.Color, alpha: f32) rl.Color {
    return rl.Color.init(
        color.r,
        color.g,
        color.b,
        @intFromFloat(std.math.clamp(alpha, @as(f32, 0.0), @as(f32, 1.0)) * 255.0),
    );
}

/// Grim truncates each scaled float channel to a byte.
fn tint(r: f32, g: f32, b: f32, a: f32) rl.Color {
    const byte = struct {
        fn f(value: f32) u8 {
            return @intFromFloat(std.math.clamp(value, @as(f32, 0.0), @as(f32, 1.0)) * 255.0);
        }
    }.f;
    return .{ .r = byte(r), .g = byte(g), .b = byte(b), .a = byte(a) };
}

test "plasma segment count truncates both operands before dividing" {
    try std.testing.expectEqual(@as(i32, 8), plasmaSegmentCount(20.9, 1.0, 2.5, 8));
    try std.testing.expectEqual(@as(i32, 3), plasmaSegmentCount(11.9, 1.55, 2.5, 8));
    try std.testing.expectEqual(@as(i32, 0), plasmaSegmentCount(100.0, 0.0, 2.1, 3));
}

test "plasma cannon counts segments by its wider divisor, not its step" {
    const glow = plasmaGlow(.plasma_cannon).?;
    // 40 units / int(3.5) = 13 tails; the 2.6 step would have given the cap of 18.
    try std.testing.expectEqual(@as(i32, 13), plasmaSegmentCount(40.0, 1.0, glow.divisor, glow.cap));
}

test "bullet trail native widths keep origin at slots zero and one" {
    const cases = .{
        .{ game_ids.ProjectileTypeId.assault_rifle, @as(f32, 1.5) },
        .{ game_ids.ProjectileTypeId.pistol, @as(f32, 1.8) },
        .{ game_ids.ProjectileTypeId.gauss_gun, @as(f32, 1.65) },
        .{ game_ids.ProjectileTypeId.shotgun, @as(f32, 1.05) },
        .{ game_ids.ProjectileTypeId.splitter_gun, @as(f32, 1.05) },
    };
    inline for (cases) |case| {
        const projectile: cz.projectiles.Projectile = .{
            .type_id = @intFromEnum(case[0]),
            .origin = .{ .x = 120, .y = 90 },
            .pos = .{ .x = 120, .y = 80 },
            .vel = .{ .x = 1.5, .y = 0 },
            .life_timer = 1.0,
        };
        const quad = bulletTrailQuad(projectile, 1.0);
        const expected = [_]rl.Vector2{
            .{ .x = 120 - case[1], .y = 90 },
            .{ .x = 120 + case[1], .y = 90 },
            .{ .x = 120 + case[1], .y = 80 },
            .{ .x = 120 - case[1], .y = 80 },
        };
        for (quad.points, expected) |actual, point| {
            try std.testing.expectApproxEqAbs(point.x, actual.x, 1e-5);
            try std.testing.expectApproxEqAbs(point.y, actual.y, 1e-5);
        }
        try std.testing.expectEqual(rl.Color.init(127, 127, 127, 0), quad.tail);
        try std.testing.expectEqual(@as(u8, 255), quad.head.a);
    }
}

test "bullet trail width uses stored velocity for both nonzero and zero length" {
    const cases = [_]struct { vel: state_mod.Vec2, offset: rl.Vector2 }{
        .{ .vel = .{ .x = 1.2, .y = 0.9 }, .offset = .{ .x = 1.44, .y = 1.08 } },
        .{ .vel = .{ .x = 2, .y = 1 }, .offset = .{ .x = 2.4, .y = 1.2 } },
    };
    for (cases) |case| {
        for ([_]f32{ 80, 90 }) |end_y| {
            const projectile: cz.projectiles.Projectile = .{
                .type_id = @intFromEnum(game_ids.ProjectileTypeId.pistol),
                .origin = .{ .x = 120, .y = 90 },
                .pos = .{ .x = 120, .y = end_y },
                .vel = case.vel,
                .angle = 0,
                .life_timer = 1.0,
            };
            const quad = bulletTrailQuad(projectile, 1.0);
            const expected = [_]rl.Vector2{
                .{ .x = 120 - case.offset.x, .y = 90 - case.offset.y },
                .{ .x = 120 + case.offset.x, .y = 90 + case.offset.y },
                .{ .x = 120 + case.offset.x, .y = end_y + case.offset.y },
                .{ .x = 120 - case.offset.x, .y = end_y - case.offset.y },
            };
            for (quad.points, expected) |actual, point| {
                try std.testing.expectApproxEqAbs(point.x, actual.x, 1e-5);
                try std.testing.expectApproxEqAbs(point.y, actual.y, 1e-5);
            }
        }
    }
}

test "Gauss trail retains life alpha through a zero world transition" {
    const projectile: cz.projectiles.Projectile = .{
        .type_id = @intFromEnum(game_ids.ProjectileTypeId.gauss_gun),
        .life_timer = 0.5,
    };
    for ([_]f32{ 1.0, 0.5, 0.0 }) |transition_alpha| {
        const quad = bulletTrailQuad(projectile, transition_alpha);
        try std.testing.expectEqual(rl.Color.init(51, 127, 255, 127), quad.head);
    }
}

test "bullet trail packs alpha after applying world transition" {
    const cases = [_]struct { life: f32, transition: f32, expected_alpha: u8 }{
        .{ .life = 0.5, .transition = 0.5, .expected_alpha = 63 },
        .{ .life = 0.5, .transition = 0.4, .expected_alpha = 51 },
        .{ .life = 1.5, .transition = 0.5, .expected_alpha = 127 },
    };
    for (cases) |case| {
        const projectile: cz.projectiles.Projectile = .{
            .type_id = @intFromEnum(game_ids.ProjectileTypeId.pistol),
            .life_timer = case.life,
        };
        const quad = bulletTrailQuad(projectile, case.transition);
        try std.testing.expectEqual(rl.Color.init(127, 127, 127, case.expected_alpha), quad.head);
    }
}
