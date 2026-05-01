const std = @import("std");

const live_runner = @import("../runtime/live_runner.zig");
const lockstep_input_adapter = @import("lockstep_input_adapter.zig");
const lockstep_protocol = @import("lockstep_protocol.zig");
const packed_input = @import("packed_input.zig");
const state_mod = @import("../runtime/state.zig");

pub const BridgeError = error{
    TooManyPlayers,
};

pub const StepCanonicalFrameError = BridgeError || live_runner.LiveRunnerError;

pub fn frameInputFromPacked(inputs: []const packed_input.PackedPlayerInput) BridgeError!live_runner.FrameInput {
    if (inputs.len > state_mod.max_players) return error.TooManyPlayers;

    var frame_input: live_runner.FrameInput = .{};
    frame_input.player_count = inputs.len;
    for (inputs, 0..) |input, idx| {
        frame_input.players[idx] = lockstep_input_adapter.unpackGameInput(input);
    }
    return frame_input;
}

pub fn frameInputFromTickFrame(frame: lockstep_protocol.TickFrame) BridgeError!live_runner.FrameInput {
    return frameInputFromPacked(frame.frame_inputs);
}

pub fn stepCanonicalFrame(
    runner: *live_runner.LiveRunner,
    frame: lockstep_protocol.TickFrame,
) StepCanonicalFrameError!live_runner.FrameUpdate {
    return runner.stepFrame(
        runner.session.dt_nominal,
        try frameInputFromTickFrame(frame),
    );
}

test "lockstep live bridge maps canonical packed inputs to frame input" {
    const wire_inputs = [_]packed_input.PackedPlayerInput{
        .{
            .move_x = 1.0,
            .move_y = 0.0,
            .aim_x = 700.0,
            .aim_y = 512.0,
            .flags = lockstep_input_adapter.fire_down_flag |
                lockstep_input_adapter.fire_pressed_flag |
                lockstep_input_adapter.move_mode_present_flag |
                (@as(u32, 3) << lockstep_input_adapter.move_mode_shift),
        },
        .{
            .move_x = 0.0,
            .move_y = -1.0,
            .aim_x = 512.0,
            .aim_y = 256.0,
            .flags = lockstep_input_adapter.reload_pressed_flag,
        },
    };

    const input = try frameInputFromPacked(&wire_inputs);
    try std.testing.expectEqual(@as(usize, 2), input.player_count);
    try std.testing.expectEqual(@as(f32, 1.0), input.players[0].move_x);
    try std.testing.expectEqual(@as(f32, -1.0), input.players[1].move_y);
    try std.testing.expect(input.players[0].flags.fire_down);
    try std.testing.expect(input.players[0].flags.fire_pressed);
    try std.testing.expectEqual(@as(?i32, 3), input.players[0].flags.move_mode);
    try std.testing.expect(input.players[1].flags.reload_pressed);
}

test "lockstep live bridge advances live runner from canonical frame" {
    var runner = try live_runner.LiveRunner.init(.{
        .player_count = 2,
    });
    const before_p0 = runner.session.players()[0].pos;
    const before_p1 = runner.session.players()[1].pos;

    const wire_inputs = [_]packed_input.PackedPlayerInput{
        .{
            .move_x = 1.0,
            .move_y = 0.0,
            .aim_x = 700.0,
            .aim_y = 512.0,
            .flags = lockstep_input_adapter.move_mode_present_flag |
                (@as(u32, 3) << lockstep_input_adapter.move_mode_shift),
        },
        .{
            .move_x = 0.0,
            .move_y = 1.0,
            .aim_x = 512.0,
            .aim_y = 700.0,
            .flags = lockstep_input_adapter.move_mode_present_flag |
                (@as(u32, 3) << lockstep_input_adapter.move_mode_shift),
        },
    };
    const frame: lockstep_protocol.TickFrame = .{
        .tick_index = 0,
        .frame_inputs = &wire_inputs,
    };

    const update = try stepCanonicalFrame(&runner, frame);
    const after_p0 = runner.session.players()[0].pos;
    const after_p1 = runner.session.players()[1].pos;

    try std.testing.expectEqual(@as(usize, 1), update.ticks_advanced);
    try std.testing.expectEqual(@as(usize, 1), runner.session.tick_index);
    try std.testing.expect(after_p0.x != before_p0.x or after_p0.y != before_p0.y);
    try std.testing.expect(after_p1.x != before_p1.x or after_p1.y != before_p1.y);
}

test "lockstep live bridge rejects oversized canonical frames" {
    const wire_inputs = [_]packed_input.PackedPlayerInput{.{}} ** (state_mod.max_players + 1);
    try std.testing.expectError(error.TooManyPlayers, frameInputFromPacked(&wire_inputs));
}
