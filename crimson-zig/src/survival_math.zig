const std = @import("std");
const builtin = @import("builtin");

const use_libc_math = builtin.os.tag != .freestanding;
const c = if (use_libc_math) @cImport({
    @cInclude("math.h");
}) else struct {};

pub inline fn cos(value: f64) f64 {
    if (comptime use_libc_math) {
        return c.cos(value);
    }
    return std.math.cos(value);
}

pub inline fn sin(value: f64) f64 {
    if (comptime use_libc_math) {
        return c.sin(value);
    }
    return std.math.sin(value);
}

pub inline fn atan2(y: f64, x: f64) f64 {
    if (comptime use_libc_math) {
        return c.atan2(y, x);
    }
    return std.math.atan2(y, x);
}
