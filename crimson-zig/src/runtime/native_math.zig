const std = @import("std");

pub const native_pi: f32 = @bitCast(@as(u32, 0x40490FDB));
pub const native_half_pi: f32 = @bitCast(@as(u32, 0x3FC90FDB));
pub const native_quarter_pi: f32 = @bitCast(@as(u32, 0x3F490FDB));
pub const native_tau: f32 = @bitCast(@as(u32, 0x40C90FDB));
pub const native_turn_rate_scale: f32 = @bitCast(@as(u32, 0x3FAAAAAB));
pub const native_creature_spawn_elapsed_scale: f32 = @bitCast(@as(u32, 0x3727C5AD));
pub const native_float_epsilon: f32 = @bitCast(@as(u32, 0x34000000));
pub const native_float_min: f32 = @bitCast(@as(u32, 0x00800000));
pub const native_fire_muzzle_rotation: f32 = @bitCast(@as(u32, 0x3E1A8976));
pub const native_tau_over_512: f32 = @bitCast(@as(u32, 0x3C490FDB));

pub inline fn roundF32(value: anytype) f32 {
    return @floatCast(value);
}

pub inline fn pc24Add(lhs: anytype, rhs: anytype) f32 {
    return roundF32(@as(f64, @floatCast(lhs)) + @as(f64, @floatCast(rhs)));
}

pub inline fn pc24Sub(lhs: anytype, rhs: anytype) f32 {
    return roundF32(@as(f64, @floatCast(lhs)) - @as(f64, @floatCast(rhs)));
}

pub inline fn pc24Mul(lhs: anytype, rhs: anytype) f32 {
    return roundF32(@as(f64, @floatCast(lhs)) * @as(f64, @floatCast(rhs)));
}

pub inline fn pc24Div(lhs: anytype, rhs: anytype) f32 {
    return roundF32(@as(f64, @floatCast(lhs)) / @as(f64, @floatCast(rhs)));
}

pub inline fn pc24Sqrt(value: anytype) f32 {
    return roundF32(std.math.sqrt(@as(f64, @floatCast(value))));
}

pub inline fn pc24Hypot(x: anytype, y: anytype) f32 {
    return pc24Sqrt(pc24Add(pc24Mul(x, x), pc24Mul(y, y)));
}

pub inline fn floatNearEqual(lhs: f32, rhs: f32) bool {
    const difference = pc24Sub(lhs, rhs);
    return difference >= -native_float_epsilon and difference <= native_float_epsilon;
}

pub inline fn normalizeVec2Safe(x: f32, y: f32) [2]f32 {
    const magnitude_sq = pc24Add(pc24Mul(y, y), pc24Mul(x, x));
    if (floatNearEqual(magnitude_sq, 1.0)) return .{ x, y };
    if (!(magnitude_sq > native_float_min)) return .{ 0.0, 0.0 };

    const inv_magnitude = pc24Div(1.0, pc24Sqrt(magnitude_sq));
    return .{
        pc24Mul(inv_magnitude, x),
        pc24Mul(inv_magnitude, y),
    };
}

pub inline fn fireMuzzlePos(player_x: f32, player_y: f32, aim_heading: f32) [2]f32 {
    const radians = pc24Sub(pc24Sub(aim_heading, native_half_pi), native_fire_muzzle_rotation);
    return .{
        pc24Add(player_x, pc24Mul(@cos(@as(f64, radians)), @as(f32, 16.0))),
        pc24Add(player_y, pc24Mul(@sin(@as(f64, radians)), @as(f32, 16.0))),
    };
}

pub inline fn shotAngleFromJitterDraws(
    aim_x: f32,
    aim_y: f32,
    player_x: f32,
    player_y: f32,
    spread_heat: f32,
    dir_draw: u32,
    mag_draw: u32,
) f32 {
    const aim_dx = pc24Sub(aim_x, player_x);
    const aim_dy = pc24Sub(aim_y, player_y);
    const distance_sq = pc24Add(
        pc24Mul(aim_dx, aim_dx),
        pc24Mul(aim_dy, aim_dy),
    );
    const half_len = pc24Mul(std.math.sqrt(@as(f64, distance_sq)), @as(f32, 0.5));
    const offset = pc24Mul(
        pc24Mul(
            pc24Mul(half_len, spread_heat),
            @as(f32, @floatFromInt(mag_draw & 0x1ff)),
        ),
        @as(f32, 0.001953125),
    );
    const dir_angle = pc24Mul(
        @as(f32, @floatFromInt(dir_draw & 0x1ff)),
        native_tau_over_512,
    );
    const jitter_x = pc24Add(pc24Mul(@cos(@as(f64, dir_angle)), offset), aim_x);
    const jitter_y = pc24Add(pc24Mul(@sin(@as(f64, dir_angle)), offset), aim_y);
    return pc24Sub(
        fpatan(
            pc24Sub(player_y, jitter_y),
            pc24Sub(player_x, jitter_x),
        ),
        native_half_pi,
    );
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

pub inline fn fpatan(y: f32, x: f32) f64 {
    return std.math.atan2(@as(f64, @floatCast(y)), @as(f64, @floatCast(x)));
}

pub inline fn wrapAngle0Tau(value: f32) f32 {
    var angle = roundF32(value);
    // Keep iterative wrapping to match decompiled native behavior for finite values.
    // Non-finite inputs would otherwise never converge (e.g. +/-inf).
    if (!std.math.isFinite(angle)) return angle;
    while (angle < 0.0) {
        angle = roundF32(angle + native_tau);
    }
    while (native_tau < angle) {
        angle = roundF32(angle - native_tau);
    }
    return angle;
}

pub inline fn headingFromDeltaNative(dx: f32, dy: f32) f32 {
    // `fpatan` stays wide; the following PC=24 `fadd` chooses the signed-zero
    // side of the left-axis boundary before the f32 target-heading store.
    return pc24Add(fpatan(dy, dx), native_half_pi);
}

test "wrap angle 0..tau keeps native finite behavior" {
    const tol: f32 = 1e-6;

    try std.testing.expectApproxEqAbs(@as(f32, 0.25), wrapAngle0Tau(roundF32(native_tau + 0.25)), tol);
    try std.testing.expectApproxEqAbs(roundF32(native_tau - 0.25), wrapAngle0Tau(-0.25), tol);
    try std.testing.expectApproxEqAbs(native_tau, wrapAngle0Tau(native_tau), tol);
}

test "wrap angle 0..tau returns non-finite unchanged" {
    const pos_inf = std.math.inf(f32);
    const neg_inf = -std.math.inf(f32);
    const nan = std.math.nan(f32);

    try std.testing.expect(std.math.isPositiveInf(wrapAngle0Tau(pos_inf)));
    try std.testing.expect(std.math.isNegativeInf(wrapAngle0Tau(neg_inf)));
    try std.testing.expect(std.math.isNan(wrapAngle0Tau(nan)));
}

test "heading from delta keeps atan2+half_pi wide until final narrow" {
    const dx: f32 = 81.96824645996094;
    const dy: f32 = -21.1148681640625;
    const heading = headingFromDeltaNative(dx, dy);
    try std.testing.expectEqual(@as(u32, 0x3fa8ca7d), @as(u32, @bitCast(heading)));
}

test "heading from delta preserves fpatan signed-zero boundary" {
    try std.testing.expectEqual(@as(u32, 0x4096cbe4), @as(u32, @bitCast(headingFromDeltaNative(-1.0, 0.0))));
    try std.testing.expectEqual(@as(u32, 0xbfc90fda), @as(u32, @bitCast(headingFromDeltaNative(-1.0, -0.0))));
}

test "fpatan consumes pc24 rounded subtraction operands" {
    const dy = roundF32(@as(f32, 868.6661376953125) - @as(f32, 597.0));
    const dx = roundF32(@as(f32, 275.0183410644531) - @as(f32, 821.0));
    const atan = fpatan(dy, dx);
    const heading = roundF32(atan - @as(f64, native_half_pi));
    try std.testing.expectEqual(@as(u32, 0x3f8df6b7), @as(u32, @bitCast(heading)));
}

test "pc24 helpers round every arithmetic operation" {
    const radians = pc24Sub(@as(f32, -0.8641037344932556), native_half_pi);
    const cosine = std.math.cos(@as(f64, @floatCast(radians)));
    const step = pc24Mul(
        pc24Mul(
            pc24Mul(
                pc24Mul(cosine, @as(f32, 0.06000000238418579)),
                @as(f32, 20.0),
            ),
            @as(f32, 1.0),
        ),
        @as(f32, 3.0),
    );

    try std.testing.expectEqual(@as(f32, -2.737848997116089), step);

    const jitter = pc24Mul(@as(f32, 52.0), @as(f32, 0.002));
    const size_scale = pc24Mul(@as(f32, 45.0), @as(f32, 0.025));
    const turn = pc24Div(jitter, size_scale);
    try std.testing.expectEqual(@as(f32, 0.09244444966316223), turn);

    const distance_sq = pc24Add(pc24Mul(@as(f32, 58.63446044921875), @as(f32, 58.63446044921875)), pc24Mul(@as(f32, -209.81591796875), @as(f32, -209.81591796875)));
    const distance = pc24Sqrt(distance_sq);
    try std.testing.expectEqual(@as(f32, 217.8548126220703), distance);
}

test "float near equal uses inclusive native f32 epsilon" {
    try std.testing.expect(floatNearEqual(1.0, 1.0 + native_float_epsilon));
    try std.testing.expect(!floatNearEqual(1.0, 1.0 + 2.0 * native_float_epsilon));
    try std.testing.expect(!floatNearEqual(std.math.nan(f32), 1.0));
}

test "safe vec2 normalization preserves near-unit and rejects subnormal lengths" {
    try std.testing.expectEqual(
        [2]f32{ 1.0, @bitCast(@as(u32, 0x38d1b717)) },
        normalizeVec2Safe(1.0, 0.0001),
    );
    try std.testing.expectEqual([2]f32{ 0.0, 0.0 }, normalizeVec2Safe(1e-20, 0.0));
}

test "native fire muzzle combines heading rotations before trig" {
    try std.testing.expectEqual(
        [2]f32{ 152.47727966308594, 941.5100708007812 },
        fireMuzzlePos(137.84991455078125, 935.0262451171875, -4.14423131942749),
    );
}

test "native shot jitter preserves fpatan branch and pc24 rounding" {
    try std.testing.expectEqual(
        @as(f32, -4.71196985244751),
        shotAngleFromJitterDraws(200.0, 100.0, 100.0, 100.0, 0.2, 65, 3),
    );
}
