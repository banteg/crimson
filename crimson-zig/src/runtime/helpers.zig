const std = @import("std");
const native_math = @import("native_math.zig");

const state_mod = @import("state.zig");
const runtime_math = @import("math.zig");

const narrowF32 = native_math.roundF32;

pub fn directionFromHeading(heading: f32) state_mod.Vec2 {
    const radians = narrowF32(heading - std.math.pi / 2.0);
    return .{
        .x = narrowF32(runtime_math.cos(radians)),
        .y = narrowF32(runtime_math.sin(radians)),
    };
}

pub fn directionFromAngle(angle: f32) state_mod.Vec2 {
    return .{
        .x = narrowF32(runtime_math.cos(angle)),
        .y = narrowF32(runtime_math.sin(angle)),
    };
}

pub fn withinNativeFindRadius(
    origin: state_mod.Vec2,
    target: state_mod.Vec2,
    radius: f32,
    target_size: f32,
) bool {
    const dx = target.x - origin.x;
    const dy = target.y - origin.y;
    const size_margin = target_size * 0.14285715 + 3.0;
    const max_axis_delta = radius + size_margin;
    if (@abs(dx) > max_axis_delta or @abs(dy) > max_axis_delta) return false;
    const margin = std.math.sqrt(dx * dx + dy * dy) - radius - size_margin;
    return margin < 0.0;
}

pub fn distanceSq(a: state_mod.Vec2, b: state_mod.Vec2) f32 {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    return dx * dx + dy * dy;
}

pub fn distanceSqRoundedF32(a: state_mod.Vec2, b: state_mod.Vec2) f32 {
    return narrowF32(distanceSq(a, b));
}
