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
    const dx = native_math.pc24Sub(target.x, origin.x);
    const dy = native_math.pc24Sub(target.y, origin.y);
    const distance = native_math.pc24Hypot(dx, dy);
    const distance_outside_radius = native_math.pc24Sub(distance, radius);
    const size_margin = native_math.pc24Add(
        native_math.pc24Mul(target_size, @as(f32, 0.14285715)),
        @as(f32, 3.0),
    );
    return distance_outside_radius < size_margin;
}

test "native find radius keeps x87 pc24 boundary decisions" {
    try std.testing.expect(!withinNativeFindRadius(
        .{},
        .{ .x = -9.429215431213379, .y = -91.945556640625 },
        66.75615692138672,
        158.70140075683594,
    ));
    try std.testing.expect(withinNativeFindRadius(
        .{},
        .{ .x = -18.60686492919922, .y = 56.534645080566406 },
        36.1519889831543,
        142.56143188476562,
    ));
}

pub fn distanceSq(a: state_mod.Vec2, b: state_mod.Vec2) f32 {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    return dx * dx + dy * dy;
}

pub fn distanceSqRoundedF32(a: state_mod.Vec2, b: state_mod.Vec2) f32 {
    return narrowF32(distanceSq(a, b));
}
