const std = @import("std");
const builtin = @import("builtin");
const native_math = @import("native_math.zig");

const c = if (builtin.target.os.tag == .freestanding)
    struct {}
else
    @cImport({
        @cInclude("math.h");
    });

pub inline fn cos(value: anytype) @TypeOf(value) {
    const T = @TypeOf(value);
    return switch (T) {
        f32 => native_math.cosNative(value),
        f64 => if (builtin.target.os.tag != .freestanding)
            c.cos(value)
        else
            std.math.cos(value),
        comptime_float => std.math.cos(value),
        else => @compileError("runtime.math.cos only supports f32/f64/comptime_float"),
    };
}

pub inline fn sin(value: anytype) @TypeOf(value) {
    const T = @TypeOf(value);
    return switch (T) {
        f32 => native_math.sinNative(value),
        f64 => if (builtin.target.os.tag != .freestanding)
            c.sin(value)
        else
            std.math.sin(value),
        comptime_float => std.math.sin(value),
        else => @compileError("runtime.math.sin only supports f32/f64/comptime_float"),
    };
}

pub inline fn atan2(y: anytype, x: @TypeOf(y)) @TypeOf(y) {
    const T = @TypeOf(y);
    return switch (T) {
        f32 => native_math.atan2Native(y, x),
        f64 => if (builtin.target.os.tag != .freestanding)
            c.atan2(y, x)
        else
            std.math.atan2(y, x),
        comptime_float => std.math.atan2(y, x),
        else => @compileError("runtime.math.atan2 only supports f32/f64/comptime_float"),
    };
}
