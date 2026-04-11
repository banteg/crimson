const std = @import("std");
const native_math = @import("native_math.zig");
const rng_callers = @import("../rng_caller_static.zig");

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

pub fn consumeRngDraws(state: *state_mod.GameplayState, count: i32) void {
    if (count <= 0) return;
    var draw_idx: i32 = 0;
    while (draw_idx < count) : (draw_idx += 1) {
        _ = state.rng.rand();
    }
}

pub fn consumeBurstRng(
    state: *state_mod.GameplayState,
    count: usize,
    include_scale_step: bool,
) void {
    for (0..count) |_| {
        _ = state.rng.randTagged(rng_callers.effect_spawn_burst_rotation);
        _ = state.rng.randTagged(rng_callers.effect_spawn_burst_vel_x);
        _ = state.rng.randTagged(rng_callers.effect_spawn_burst_vel_y);
        if (include_scale_step) {
            _ = state.rng.randTagged(rng_callers.effect_spawn_burst_scale_step);
        }
    }
}

pub fn consumeAddRandomRng(state: *state_mod.GameplayState) void {
    _ = state.rng.randTagged(rng_callers.fx_queue_add_random_gray);
    _ = state.rng.randTagged(rng_callers.fx_queue_add_random_width);
    _ = state.rng.randTagged(rng_callers.fx_queue_add_random_rotation);
    _ = state.rng.randTagged(rng_callers.fx_queue_add_random_effect_id);
}

pub fn consumeFreezeShardRng(state: *state_mod.GameplayState) void {
    _ = state.rng.randTagged(rng_callers.effect_spawn_freeze_shard_lifetime);
    _ = state.rng.randTagged(rng_callers.effect_spawn_freeze_shard_rotation);
    _ = state.rng.randTagged(rng_callers.effect_spawn_freeze_shard_half);
    _ = state.rng.randTagged(rng_callers.effect_spawn_freeze_shard_rotation_step);
    _ = state.rng.randTagged(rng_callers.effect_spawn_freeze_shard_scale_step);
    _ = state.rng.randTagged(rng_callers.effect_spawn_freeze_shard_effect_id);
}

pub fn consumeFreezeShatterRng(
    state: *state_mod.GameplayState,
    shard_angle_caller: u32,
    shatter_angle_caller: u32,
) void {
    for (0..8) |_| {
        _ = state.rng.randTagged(shard_angle_caller) % 0x264;
        consumeFreezeShardRng(state);
    }
    _ = state.rng.randTagged(shatter_angle_caller) % 0x264;
    for (0..4) |_| {
        _ = state.rng.randTagged(rng_callers.effect_spawn_freeze_shatter_half);
        _ = state.rng.randTagged(rng_callers.effect_spawn_freeze_shatter_rotation_step);
    }
    for (0..4) |_| {
        _ = state.rng.randTagged(rng_callers.effect_spawn_freeze_shatter_shard_angle) % 0x264;
        consumeFreezeShardRng(state);
    }
}
