const std = @import("std");
const builtin = @import("builtin");
const c = if (builtin.target.os.tag == .freestanding)
    struct {}
else
    @cImport({
        @cInclude("math.h");
    });

pub inline fn cos(value: f64) f64 {
    if (builtin.target.os.tag != .freestanding) {
        return c.cos(value);
    }
    return std.math.cos(value);
}

pub inline fn sin(value: f64) f64 {
    if (builtin.target.os.tag != .freestanding) {
        return c.sin(value);
    }
    return std.math.sin(value);
}

pub inline fn atan2(y: f64, x: f64) f64 {
    if (builtin.target.os.tag != .freestanding) {
        return c.atan2(y, x);
    }
    return std.math.atan2(y, x);
}
