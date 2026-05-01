const std = @import("std");

const game_cfg = @import("../formats/game_cfg.zig");
const live_runner = @import("../runtime/live_runner.zig");
const lockstep_input_adapter = @import("lockstep_input_adapter.zig");
const lockstep_live_bridge = @import("lockstep_live_bridge.zig");
const relay_protocol = @import("relay_protocol.zig");
const rollback_runtime = @import("rollback_runtime.zig");
const rollback_session = @import("rollback_session.zig");
const room_code = @import("room_code.zig");
const state_mod = @import("../runtime/state.zig");

pub const BridgeError = lockstep_live_bridge.BridgeError;
pub const StepFrameError = BridgeError || live_runner.LiveRunnerError;

pub const MatchConfig = rollback_session.MatchConfig;

pub fn matchConfigFromRoomStart(start: relay_protocol.RoomStart) MatchConfig {
    return .{
        .seed = start.seed,
        .mode_id = start.mode_id,
        .player_count = start.player_count,
        .quest_level = start.quest_level,
        .preserve_bugs = start.preserve_bugs,
        .tick_rate = start.tick_rate,
        .input_delay_ticks = start.input_delay_ticks,
        .status = start.status,
    };
}

pub fn liveConfigFromMatchConfig(config: MatchConfig) BridgeError!live_runner.LiveModeConfig {
    return lockstep_live_bridge.liveConfigFromSettings(.{
        .mode_id = config.mode_id,
        .player_count = config.player_count,
        .quest_level = config.quest_level,
        .preserve_bugs = config.preserve_bugs,
        .tick_rate = config.tick_rate,
        .input_delay_ticks = config.input_delay_ticks,
        .netcode_mode = relay_protocol.NetcodeMode.lockstep,
    }, .{
        .seed = config.seed,
        .status = config.status,
    });
}

pub fn liveConfigFromRoomStart(start: relay_protocol.RoomStart) BridgeError!live_runner.LiveModeConfig {
    return liveConfigFromMatchConfig(matchConfigFromRoomStart(start));
}

pub fn frameInputFromTickFrame(frame: rollback_runtime.TickFrame) BridgeError!live_runner.FrameInput {
    if (frame.player_count > state_mod.max_players) return error.TooManyPlayers;
    return lockstep_live_bridge.frameInputFromPacked(frame.frame_inputs[0..frame.player_count]);
}

pub fn stepFrame(
    runner: *live_runner.LiveRunner,
    frame: rollback_runtime.TickFrame,
) StepFrameError!live_runner.FrameUpdate {
    return runner.stepFrame(
        runner.session.dt_nominal,
        try frameInputFromTickFrame(frame),
    );
}

test "rollback live bridge maps room start to live runner config" {
    var status = std.mem.zeroes(game_cfg.Status);
    status.quest_unlock_index = 4;
    const start: relay_protocol.RoomStart = .{
        .room_code = try room_code.parseRoomCode("ABCD"),
        .seed = 1234,
        .mode_id = 2,
        .player_count = 2,
        .tick_rate = 30,
        .status = status,
    };

    const config = try liveConfigFromRoomStart(start);
    try std.testing.expectEqual(@as(u32, 1234), config.seed);
    try std.testing.expectEqual(@as(i32, 2), config.player_count);
    try std.testing.expectEqual(@as(i32, 30), config.tick_rate);
    try std.testing.expectEqual(@as(i32, 4), config.status_quest_unlock_index);
}

test "rollback live bridge converts tick frames to live input" {
    const frame: rollback_runtime.TickFrame = .{
        .tick_index = 9,
        .player_count = 2,
        .frame_inputs = .{
            .{ .flags = lockstep_input_adapter.fire_pressed_flag },
            .{ .flags = lockstep_input_adapter.reload_pressed_flag },
            .{},
            .{},
        },
    };

    const input = try frameInputFromTickFrame(frame);
    try std.testing.expectEqual(@as(usize, 2), input.player_count);
    try std.testing.expect(input.players[0].flags.fire_pressed);
    try std.testing.expect(input.players[1].flags.reload_pressed);
}
