const cz = @import("crimson_zig");
const formats = cz.formats;
const state_mod = cz.state;

pub const ViewTransform = struct {
    camera: state_mod.Vec2,
    view_scale: state_mod.Vec2,
    screen_size: state_mod.Vec2,
};

pub fn cameraScreenSize(
    world_size: f32,
    config: ?*const formats.crimson_cfg.CrimsonCfg,
    runtime_w: f32,
    runtime_h: f32,
) state_mod.Vec2 {
    const screen_w: f32 = if (runtime_w > 0.0 and runtime_h > 0.0)
        runtime_w
    else if (config) |cfg|
        @floatFromInt(cfg.screen_width)
    else
        @max(1.0, runtime_w);
    const screen_h: f32 = if (runtime_w > 0.0 and runtime_h > 0.0)
        runtime_h
    else if (config) |cfg|
        @floatFromInt(cfg.screen_height)
    else
        @max(1.0, runtime_h);

    if (!(world_size > 0.0)) {
        return .{ .x = @max(1.0, screen_w), .y = @max(1.0, screen_h) };
    }

    const out_w = @max(1.0, screen_w);
    const out_h = @max(1.0, screen_h);
    const scale = @max(@max(out_w / world_size, out_h / world_size), 1.0);
    return .{
        .x = @min(world_size, out_w / scale),
        .y = @min(world_size, out_h / scale),
    };
}

pub fn clampCamera(world_size: f32, camera: state_mod.Vec2, screen_size: state_mod.Vec2) state_mod.Vec2 {
    var cam_x = camera.x;
    var cam_y = camera.y;
    if (cam_x > -1.0) cam_x = -1.0;
    if (cam_y > -1.0) cam_y = -1.0;
    const min_x = screen_size.x - world_size;
    const min_y = screen_size.y - world_size;
    if (cam_x < min_x) cam_x = min_x;
    if (cam_y < min_y) cam_y = min_y;
    return .{ .x = cam_x, .y = cam_y };
}

pub fn viewTransform(
    world_size: f32,
    config: ?*const formats.crimson_cfg.CrimsonCfg,
    camera: state_mod.Vec2,
    out_size: state_mod.Vec2,
) ViewTransform {
    const screen_size = cameraScreenSize(world_size, config, out_size.x, out_size.y);
    const clamped = clampCamera(world_size, camera, screen_size);
    return .{
        .camera = clamped,
        .view_scale = .{
            .x = if (screen_size.x > 0.0) out_size.x / screen_size.x else 1.0,
            .y = if (screen_size.y > 0.0) out_size.y / screen_size.y else 1.0,
        },
        .screen_size = screen_size,
    };
}

pub fn viewScaleAvg(view_scale: state_mod.Vec2) f32 {
    return (view_scale.x + view_scale.y) * 0.5;
}
