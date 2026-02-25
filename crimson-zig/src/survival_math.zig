const std = @import("std");
pub inline fn cos(value: f64) f64 {
    return std.math.cos(value);
}

pub inline fn sin(value: f64) f64 {
    return std.math.sin(value);
}

pub inline fn atan2(y: f64, x: f64) f64 {
    return std.math.atan2(y, x);
}
