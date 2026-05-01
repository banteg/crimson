const std = @import("std");

const packed_input = @import("packed_input.zig");
const player_runtime = @import("../runtime/player.zig");

pub const fire_down_flag: u32 = 1 << 0;
pub const fire_pressed_flag: u32 = 1 << 1;
pub const reload_pressed_flag: u32 = 1 << 2;
pub const move_keys_present_flag: u32 = 1 << 3;
pub const move_forward_flag: u32 = 1 << 4;
pub const move_backward_flag: u32 = 1 << 5;
pub const turn_left_flag: u32 = 1 << 6;
pub const turn_right_flag: u32 = 1 << 7;
pub const move_mode_present_flag: u32 = 1 << 8;
pub const move_mode_shift: u5 = 9;
pub const move_mode_mask: u32 = 0x7;
pub const aim_scheme_present_flag: u32 = 1 << 12;
pub const aim_scheme_shift: u5 = 13;
pub const aim_scheme_mask: u32 = 0x7;

pub const InputFlags = struct {
    fire_down: bool,
    fire_pressed: bool,
    reload_pressed: bool,
    move_mode: ?i32 = null,
    aim_scheme: ?i32 = null,
    move_forward_pressed: ?bool = null,
    move_backward_pressed: ?bool = null,
    turn_left_pressed: ?bool = null,
    turn_right_pressed: ?bool = null,
};

pub fn packGameInput(input: player_runtime.GameInput) packed_input.PackedPlayerInput {
    return .{
        .move_x = input.move_x,
        .move_y = input.move_y,
        .aim_x = input.aim_x,
        .aim_y = input.aim_y,
        .flags = packGameInputFlags(input.flags),
    };
}

pub fn unpackGameInput(input: packed_input.PackedPlayerInput) player_runtime.GameInput {
    const flags = unpackGameInputFlags(input.flags);
    return .{
        .move_x = input.move_x,
        .move_y = input.move_y,
        .aim_x = input.aim_x,
        .aim_y = input.aim_y,
        .flags = .{
            .fire_down = flags.fire_down,
            .fire_pressed = flags.fire_pressed,
            .reload_pressed = flags.reload_pressed,
            .move_mode = flags.move_mode,
            .aim_scheme = flags.aim_scheme,
            .move_forward_pressed = flags.move_forward_pressed,
            .move_backward_pressed = flags.move_backward_pressed,
            .turn_left_pressed = flags.turn_left_pressed,
            .turn_right_pressed = flags.turn_right_pressed,
        },
    };
}

pub fn packGameInputFlags(flags: player_runtime.GameInputFlags) u32 {
    var out: u32 = 0;
    if (flags.fire_down) out |= fire_down_flag;
    if (flags.fire_pressed) out |= fire_pressed_flag;
    if (flags.reload_pressed) out |= reload_pressed_flag;

    if (flags.move_forward_pressed != null or
        flags.move_backward_pressed != null or
        flags.turn_left_pressed != null or
        flags.turn_right_pressed != null)
    {
        out |= move_keys_present_flag;
        if (flags.move_forward_pressed orelse false) out |= move_forward_flag;
        if (flags.move_backward_pressed orelse false) out |= move_backward_flag;
        if (flags.turn_left_pressed orelse false) out |= turn_left_flag;
        if (flags.turn_right_pressed orelse false) out |= turn_right_flag;
    }

    if (flags.move_mode) |move_mode| {
        out |= move_mode_present_flag;
        out |= encodeThreeBitValue(move_mode) << move_mode_shift;
    }
    if (flags.aim_scheme) |aim_scheme| {
        out |= aim_scheme_present_flag;
        const encoded: u32 = if (aim_scheme < 0)
            aim_scheme_mask
        else
            encodeThreeBitValue(aim_scheme);
        out |= encoded << aim_scheme_shift;
    }
    return out;
}

pub fn unpackGameInputFlags(flags: u32) InputFlags {
    var decoded: InputFlags = .{
        .fire_down = (flags & fire_down_flag) != 0,
        .fire_pressed = (flags & fire_pressed_flag) != 0,
        .reload_pressed = (flags & reload_pressed_flag) != 0,
    };

    if ((flags & move_keys_present_flag) != 0) {
        decoded.move_forward_pressed = (flags & move_forward_flag) != 0;
        decoded.move_backward_pressed = (flags & move_backward_flag) != 0;
        decoded.turn_left_pressed = (flags & turn_left_flag) != 0;
        decoded.turn_right_pressed = (flags & turn_right_flag) != 0;
    }
    if ((flags & move_mode_present_flag) != 0) {
        decoded.move_mode = @intCast((flags >> move_mode_shift) & move_mode_mask);
    }
    if ((flags & aim_scheme_present_flag) != 0) {
        const raw: i32 = @intCast((flags >> aim_scheme_shift) & aim_scheme_mask);
        decoded.aim_scheme = if (raw == @as(i32, @intCast(aim_scheme_mask))) -1 else raw;
    }
    return decoded;
}

fn encodeThreeBitValue(value: i32) u32 {
    return @intCast(std.math.clamp(value, @as(i32, 0), @as(i32, @intCast(move_mode_mask))));
}

test "lockstep input adapter packs replay-compatible flags" {
    const input: player_runtime.GameInput = .{
        .move_x = -0.25,
        .move_y = 0.75,
        .aim_x = 12.0,
        .aim_y = -9.0,
        .flags = .{
            .fire_down = true,
            .fire_pressed = false,
            .reload_pressed = true,
            .move_mode = 2,
            .aim_scheme = -1,
            .move_forward_pressed = true,
            .move_backward_pressed = false,
            .turn_left_pressed = false,
            .turn_right_pressed = true,
        },
    };

    const wire_input = packGameInput(input);
    try std.testing.expectEqual(@as(f32, -0.25), wire_input.move_x);
    try std.testing.expectEqual(@as(f32, 0.75), wire_input.move_y);
    try std.testing.expectEqual(@as(f32, 12.0), wire_input.aim_x);
    try std.testing.expectEqual(@as(f32, -9.0), wire_input.aim_y);

    const decoded_flags = unpackGameInputFlags(wire_input.flags);
    try std.testing.expect(decoded_flags.fire_down);
    try std.testing.expect(!decoded_flags.fire_pressed);
    try std.testing.expect(decoded_flags.reload_pressed);
    try std.testing.expectEqual(@as(?i32, 2), decoded_flags.move_mode);
    try std.testing.expectEqual(@as(?i32, -1), decoded_flags.aim_scheme);
    try std.testing.expectEqual(@as(?bool, true), decoded_flags.move_forward_pressed);
    try std.testing.expectEqual(@as(?bool, false), decoded_flags.move_backward_pressed);
    try std.testing.expectEqual(@as(?bool, false), decoded_flags.turn_left_pressed);
    try std.testing.expectEqual(@as(?bool, true), decoded_flags.turn_right_pressed);
}

test "lockstep input adapter roundtrips game input through packed shape" {
    const input: player_runtime.GameInput = .{
        .move_x = 1.0,
        .move_y = -1.0,
        .aim_x = 64.0,
        .aim_y = 128.0,
        .flags = .{
            .fire_down = false,
            .fire_pressed = true,
            .reload_pressed = false,
            .reload_down = true,
            .move_to_cursor_pressed = true,
            .move_mode = 4,
            .aim_scheme = 3,
            .move_forward_pressed = null,
            .move_backward_pressed = null,
            .turn_left_pressed = null,
            .turn_right_pressed = null,
        },
    };

    const roundtrip = unpackGameInput(packGameInput(input));
    try std.testing.expectEqual(input.move_x, roundtrip.move_x);
    try std.testing.expectEqual(input.move_y, roundtrip.move_y);
    try std.testing.expectEqual(input.aim_x, roundtrip.aim_x);
    try std.testing.expectEqual(input.aim_y, roundtrip.aim_y);
    try std.testing.expectEqual(input.flags.fire_down, roundtrip.flags.fire_down);
    try std.testing.expectEqual(input.flags.fire_pressed, roundtrip.flags.fire_pressed);
    try std.testing.expectEqual(input.flags.reload_pressed, roundtrip.flags.reload_pressed);
    try std.testing.expect(!roundtrip.flags.reload_down);
    try std.testing.expect(!roundtrip.flags.move_to_cursor_pressed);
    try std.testing.expectEqual(input.flags.move_mode, roundtrip.flags.move_mode);
    try std.testing.expectEqual(input.flags.aim_scheme, roundtrip.flags.aim_scheme);
}
