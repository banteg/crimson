const std = @import("std");

const game_cfg = @import("../formats/game_cfg.zig");
const game_ids = @import("../game_ids.zig");
const live_runner = @import("../runtime/live_runner.zig");
const lockstep_input_adapter = @import("lockstep_input_adapter.zig");
const lockstep_protocol = @import("lockstep_protocol.zig");
const packed_input = @import("packed_input.zig");
const quest_level = @import("../quest_level.zig");
const session_settings = @import("session_settings.zig");
const state_mod = @import("../runtime/state.zig");

pub const BridgeError = error{
    InvalidGameMode,
    TooManyPlayers,
};

pub const StepCanonicalFrameError = BridgeError || live_runner.LiveRunnerError;

pub const LiveConfigOptions = struct {
    seed: i32 = 1,
    status: ?game_cfg.Status = null,
};

pub const MatchStartLiveConfigOptions = struct {
    tick_rate: i32 = lockstep_protocol.tick_rate,
    input_delay_ticks: i32 = lockstep_protocol.input_delay_ticks,
};

pub fn liveConfigFromSettings(
    settings: session_settings.LockstepSessionSettings,
    options: LiveConfigOptions,
) BridgeError!live_runner.LiveModeConfig {
    const game_mode = std.enums.fromInt(game_ids.GameModeId, settings.mode_id) orelse
        return error.InvalidGameMode;

    var config: live_runner.LiveModeConfig = .{
        .seed = @bitCast(options.seed),
        .game_mode = game_mode,
        .player_count = settings.player_count,
        .tick_rate = settings.tick_rate,
        .preserve_bugs = settings.preserve_bugs,
    };
    if (settings.quest_level) |level| {
        config.quest_level_key = level.levelKey();
    }
    if (options.status) |status| {
        config.status_quest_unlock_index = @intCast(status.quest_unlock_index);
        config.status_quest_unlock_index_full = @intCast(status.quest_unlock_index_full);
        config.status_weapon_usage_counts = statusWeaponUsageCounts(status);
    }
    return config;
}

pub fn liveConfigFromMatchStart(
    start: lockstep_protocol.MatchStart,
    options: MatchStartLiveConfigOptions,
) BridgeError!live_runner.LiveModeConfig {
    const settings = session_settings.fromMatchStart(start, .{
        .tick_rate = options.tick_rate,
        .input_delay_ticks = options.input_delay_ticks,
    });
    return liveConfigFromSettings(settings, .{
        .seed = start.seed,
        .status = start.status,
    });
}

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

fn statusWeaponUsageCounts(status: game_cfg.Status) [state_mod.weapon_count_size]u32 {
    var counts: [state_mod.weapon_count_size]u32 = [_]u32{0} ** state_mod.weapon_count_size;
    for (0..@min(counts.len, status.weapon_usage_counts.len)) |idx| {
        counts[idx] = status.weapon_usage_counts[idx];
    }
    return counts;
}

test "lockstep live bridge maps match start to live runner config" {
    var status = std.mem.zeroes(game_cfg.Status);
    status.quest_unlock_index = 6;
    status.quest_unlock_index_full = 12;
    status.weapon_usage_counts[@intFromEnum(game_ids.WeaponId.pistol)] = 9;

    const start: lockstep_protocol.MatchStart = .{
        .mode_id = @intFromEnum(game_ids.GameModeId.quests),
        .player_count = 2,
        .seed = 12345,
        .quest_level = try quest_level.QuestLevel.parse("2.5"),
        .preserve_bugs = true,
        .status = status,
    };

    const config = try liveConfigFromMatchStart(start, .{
        .tick_rate = 30,
        .input_delay_ticks = 3,
    });
    try std.testing.expectEqual(@as(u32, 12345), config.seed);
    try std.testing.expectEqual(game_ids.GameModeId.quests, config.game_mode);
    try std.testing.expectEqual(@as(i32, 2), config.player_count);
    try std.testing.expectEqual(@as(i32, 205), config.quest_level_key);
    try std.testing.expectEqual(@as(i32, 30), config.tick_rate);
    try std.testing.expect(config.preserve_bugs);
    try std.testing.expectEqual(@as(i32, 6), config.status_quest_unlock_index);
    try std.testing.expectEqual(@as(i32, 12), config.status_quest_unlock_index_full);
    try std.testing.expectEqual(@as(u32, 9), config.status_weapon_usage_counts[@intFromEnum(game_ids.WeaponId.pistol)]);
}

test "lockstep live bridge rejects unknown match start mode" {
    try std.testing.expectError(error.InvalidGameMode, liveConfigFromMatchStart(.{
        .mode_id = 99,
    }, .{}));
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
