const std = @import("std");

pub const native_pi: f32 = @bitCast(@as(u32, 0x40490FDB));
pub const native_half_pi: f32 = @bitCast(@as(u32, 0x3FC90FDB));
pub const native_tau: f32 = @bitCast(@as(u32, 0x40C90FDB));
pub const native_turn_rate_scale: f32 = @bitCast(@as(u32, 0x3FAAAAAB));

pub const native_left_axis_heading_pos: f32 = roundF32(native_tau - native_half_pi);
pub const native_left_axis_heading_eps: f32 = 1e-6;
pub const native_left_axis_dy_eps: f32 = 5e-4;

pub inline fn roundF32(value: anytype) f32 {
    return @floatCast(value);
}

pub inline fn f64f32(value: anytype) f64 {
    const rounded: f32 = roundF32(value);
    return @floatCast(rounded);
}

pub inline fn sinNative(value: f32) f32 {
    return @floatCast(std.math.sin(@as(f64, @floatCast(value))));
}

pub inline fn cosNative(value: f32) f32 {
    return @floatCast(std.math.cos(@as(f64, @floatCast(value))));
}

pub inline fn atan2Native(y: f32, x: f32) f32 {
    return @floatCast(std.math.atan2(@as(f64, @floatCast(y)), @as(f64, @floatCast(x))));
}

pub inline fn wrapAngle0Tau(value: f32) f32 {
    var angle = roundF32(value);
    while (angle < 0.0) {
        angle = roundF32(angle + native_tau);
    }
    while (native_tau < angle) {
        angle = roundF32(angle - native_tau);
    }
    return angle;
}

pub inline fn headingFromDeltaNative(dx: f32, dy: f32) f32 {
    var heading = roundF32(atan2Native(dy, dx) + native_half_pi);
    if (dx < 0.0 and
        @abs(heading - native_left_axis_heading_pos) <= native_left_axis_heading_eps and
        @abs(dy) <= native_left_axis_dy_eps)
    {
        heading = roundF32(heading - native_tau);
    }
    return heading;
}

pub inline fn headingAddPiNative(heading: f32) f32 {
    return roundF32(heading + native_pi);
}
