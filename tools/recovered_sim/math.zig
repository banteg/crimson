const std = @import("std");
const sine = @import("rt").sin;
const cosine = @import("rt").cos;
export fn portable_sin(x: f64) f64 { @setFloatMode(.strict); return sine.sin(x); }
export fn portable_cos(x: f64) f64 { @setFloatMode(.strict); return cosine.cos(x); }
export fn portable_atan2(y: f64, x: f64) f64 { @setFloatMode(.strict); return std.math.atan2(y, x); }
export fn portable_pow(x: f64, y: f64) f64 { @setFloatMode(.strict); return std.math.pow(f64, x, y); }
export fn portable_sinf(x: f32) f32 { return @floatCast(portable_sin(@floatCast(x))); }
export fn portable_cosf(x: f32) f32 { return @floatCast(portable_cos(@floatCast(x))); }
export fn portable_atan2f(y: f32, x: f32) f64 { return portable_atan2(@floatCast(y), @floatCast(x)); }
