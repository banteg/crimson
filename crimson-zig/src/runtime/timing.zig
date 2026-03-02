const std = @import("std");
const native_math = @import("native_math.zig");

const narrowF32 = native_math.roundF32;

pub fn ftolMsI32(dt_seconds: f32) i32 {
    const scaled_f32 = narrowF32(dt_seconds * 1000.0);
    if (!std.math.isFinite(scaled_f32)) return 0;
    if (scaled_f32 <= @as(f32, @floatFromInt(std.math.minInt(i32)))) return std.math.minInt(i32);
    if (scaled_f32 >= @as(f32, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(@trunc(scaled_f32));
}
