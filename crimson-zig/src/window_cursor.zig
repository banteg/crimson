const std = @import("std");
const rl = @import("raylib");

const cz = @import("crimson_zig");
const state_mod = cz.state;
const window_atlas = cz.window_atlas;
const window_assets = @import("window_assets.zig");
const window_ui = @import("window_ui.zig");

pub fn drawMenuCursor(runtime_assets: *const window_assets.RuntimeAssets, pulse_time: f32) void {
    const mouse = rl.getMousePosition();
    drawCursorGlow(runtime_assets, mouse, pulse_time);

    const texture = runtime_assets.texture(.ui_cursor);
    rl.drawTexturePro(
        texture,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(texture.width), @floatFromInt(texture.height)),
        rl.Rectangle.init(mouse.x - 2.0, mouse.y - 2.0, 32.0, 32.0),
        rl.Vector2.zero(),
        0.0,
        rl.Color.white,
    );
}

pub fn drawAimEnhancements(
    runtime_assets: *const window_assets.RuntimeAssets,
    player: state_mod.PlayerState,
    zoom: f32,
    entity_alpha: f32,
) void {
    if (player.health <= 0.0) return;
    if (!(zoom > 0.0)) return;
    if (!(entity_alpha > 1e-3)) return;

    const aim = rl.Vector2.init(player.aim.x, player.aim.y);
    const dist = state_mod.Vec2.sub(player.aim, player.pos).length();
    const radius = @max(6.0, dist * player.spread_heat * 0.5);
    const screen_radius = @max(1.0, radius * zoom);
    drawAimCircle(aim, screen_radius / zoom, entity_alpha);

    const reload_timer = player.weapon.reload_timer;
    const reload_timer_max = player.weapon.reload_timer_max;
    if (reload_timer_max > 1e-6 and reload_timer > 1e-6) {
        const progress = reload_timer / reload_timer_max;
        if (progress > 0.0) {
            const ms: i32 = @intFromFloat(progress * 60000.0);
            drawClockGauge(runtime_assets, aim, ms, 1.0 / zoom, entity_alpha);
        }
    }

    drawAimCursor(runtime_assets, aim, 1.0 / zoom);
}

fn drawCursorGlow(runtime_assets: *const window_assets.RuntimeAssets, pos: rl.Vector2, pulse_time: f32) void {
    const particles = runtime_assets.texture(.particles);
    const src_rect = window_atlas.effectRect(particles.width, particles.height, .glow) orelse return;
    const alpha = clamp01((std.math.pow(f32, 2.0, std.math.sin(pulse_time)) + 2.0) * 0.32);
    const tint = rl.Color.init(255, 255, 255, @intFromFloat(alpha * 255.0 + 0.5));

    rl.beginBlendMode(.additive);
    defer rl.endBlendMode();

    const offsets = [_]struct { dx: f32, dy: f32, size: f32 }{
        .{ .dx = -28.0, .dy = -28.0, .size = 64.0 },
        .{ .dx = -10.0, .dy = -18.0, .size = 64.0 },
        .{ .dx = -18.0, .dy = -10.0, .size = 64.0 },
        .{ .dx = -48.0, .dy = -48.0, .size = 128.0 },
    };
    for (offsets) |item| {
        rl.drawTexturePro(
            particles,
            rl.Rectangle.init(src_rect.x, src_rect.y, src_rect.width, src_rect.height),
            rl.Rectangle.init(pos.x + item.dx, pos.y + item.dy, item.size, item.size),
            rl.Vector2.zero(),
            0.0,
            tint,
        );
    }
}

fn drawAimCursor(runtime_assets: *const window_assets.RuntimeAssets, pos: rl.Vector2, world_scale: f32) void {
    const particles = runtime_assets.texture(.particles);
    if (window_atlas.effectRect(particles.width, particles.height, .glow)) |src_rect| {
        rl.beginBlendMode(.additive);
        rl.drawTexturePro(
            particles,
            rl.Rectangle.init(src_rect.x, src_rect.y, src_rect.width, src_rect.height),
            rl.Rectangle.init(pos.x - 32.0 * world_scale, pos.y - 32.0 * world_scale, 64.0 * world_scale, 64.0 * world_scale),
            rl.Vector2.zero(),
            0.0,
            rl.Color.white,
        );
        rl.endBlendMode();
    }

    const aim = runtime_assets.texture(.ui_aim);
    rl.drawTexturePro(
        aim,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(aim.width), @floatFromInt(aim.height)),
        rl.Rectangle.init(pos.x - 10.0 * world_scale, pos.y - 10.0 * world_scale, 20.0 * world_scale, 20.0 * world_scale),
        rl.Vector2.zero(),
        0.0,
        rl.Color.white,
    );
}

fn grim2dCircleSegmentsFilled(radius: f32) i32 {
    return @max(3, @as(i32, @intFromFloat(radius * 0.125 + 12.0)));
}

fn grim2dCircleSegmentsOutline(radius: f32) i32 {
    return @max(3, @as(i32, @intFromFloat(radius * 0.2 + 14.0)));
}

fn drawAimCircle(center: rl.Vector2, radius: f32, alpha: f32) void {
    if (!(radius > 1e-3)) return;
    const clamped_alpha = clamp01(alpha);
    if (!(clamped_alpha > 1e-3)) return;

    const fill_alpha: u8 = @intFromFloat(77.0 * clamped_alpha + 0.5);
    const outline_alpha: u8 = @intFromFloat(255.0 * 0.55 * clamped_alpha + 0.5);
    const fill = rl.Color.init(0, 0, 26, fill_alpha);
    const outline = rl.Color.init(255, 255, 255, outline_alpha);
    const seg_fill = @max(grim2dCircleSegmentsFilled(radius), @max(@as(i32, 64), @as(i32, @intFromFloat(radius))));
    const seg_outline = @max(grim2dCircleSegmentsOutline(radius), seg_fill);

    rl.beginBlendMode(.alpha);
    defer rl.endBlendMode();
    rl.drawCircleSector(center, radius, 0.0, 360.0, seg_fill, fill);
    rl.drawRing(center, radius, radius + 2.0, 0.0, 360.0, seg_outline, outline);
}

fn drawClockGauge(
    runtime_assets: *const window_assets.RuntimeAssets,
    pos: rl.Vector2,
    ms: i32,
    scale: f32,
    alpha: f32,
) void {
    const size = 32.0 * scale;
    if (!(size > 1e-3)) return;
    const tint = window_ui.colorWithAlpha(rl.Color.white, alpha);
    const half = size * 0.5;

    const table = runtime_assets.texture(.ui_clock_table);
    rl.drawTexturePro(
        table,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(table.width), @floatFromInt(table.height)),
        rl.Rectangle.init(pos.x, pos.y, size, size),
        rl.Vector2.zero(),
        0.0,
        tint,
    );

    const pointer = runtime_assets.texture(.ui_clock_pointer);
    const seconds = @divTrunc(ms, 1000);
    rl.drawTexturePro(
        pointer,
        rl.Rectangle.init(0.0, 0.0, @floatFromInt(pointer.width), @floatFromInt(pointer.height)),
        rl.Rectangle.init(pos.x + half, pos.y + half, size, size),
        rl.Vector2.init(half, half),
        @as(f32, @floatFromInt(seconds)) * 6.0,
        tint,
    );
}

fn clamp01(value: f32) f32 {
    return std.math.clamp(value, @as(f32, 0.0), @as(f32, 1.0));
}
