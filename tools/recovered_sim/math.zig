const std = @import("std");
const sine = @import("rt").sin;
const cosine = @import("rt").cos;
export fn portable_sin(x: f64) f64 {
    @setFloatMode(.strict);
    return sine.sin(x);
}
export fn portable_cos(x: f64) f64 {
    @setFloatMode(.strict);
    return cosine.cos(x);
}
export fn portable_atan2(y: f64, x: f64) f64 {
    @setFloatMode(.strict);
    return std.math.atan2(y, x);
}
export fn portable_pow(x: f64, y: f64) f64 {
    @setFloatMode(.strict);
    return std.math.pow(f64, x, y);
}
// Positive finite bases: CRT __CIpow / crt_two_to_tos under gameplay PC24.
// FYL2X and F2XM1 stay wide; FSUB and FADD round to a 24-bit mantissa.
export fn portable_crt_pow_pc24(base: f64, exponent: f64) f32 {
    @setFloatMode(.strict);
    const scaled_log = exponent * std.math.log2(base);
    var whole = @round(scaled_log);
    if (@abs(scaled_log - @trunc(scaled_log)) == 0.5 and @mod(whole, 2.0) != 0.0)
        whole -= std.math.sign(scaled_log);
    const fraction: f32 = @floatCast(scaled_log - whole);
    const mantissa: f32 = @floatCast(std.math.pow(f64, 2.0, @as(f64, fraction)) - 1.0 + 1.0);
    return std.math.ldexp(mantissa, @as(i32, @intFromFloat(whole)));
}
export fn portable_sinf(x: f32) f32 {
    return @floatCast(portable_sin(@floatCast(x)));
}
export fn portable_cosf(x: f32) f32 {
    return @floatCast(portable_cos(@floatCast(x)));
}
export fn portable_atan2f(y: f32, x: f32) f64 {
    return portable_atan2(@floatCast(y), @floatCast(x));
}
