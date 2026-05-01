const std = @import("std");

const game_cfg = @import("../formats/game_cfg.zig");
const live_runner = @import("../runtime/live_runner.zig");
const lockstep_input_adapter = @import("lockstep_input_adapter.zig");
const lockstep_live_bridge = @import("lockstep_live_bridge.zig");
const relay_protocol = @import("relay_protocol.zig");
const rollback_runtime = @import("rollback_runtime.zig");
const rollback_resync_v5 = @import("rollback_resync_v5.zig");
const rollback_session = @import("rollback_session.zig");
const room_code = @import("room_code.zig");
const runtime_session = @import("../runtime/session.zig");
const spawn_mod = @import("../runtime/spawn.zig");
const state_mod = @import("../runtime/state.zig");

pub const BridgeError = lockstep_live_bridge.BridgeError;
pub const StepFrameError = BridgeError || live_runner.LiveRunnerError;
pub const SnapshotBridgeError = rollback_resync_v5.RollbackResyncV5Error ||
    runtime_session.DeterministicSessionError ||
    error{
        SnapshotModeMismatch,
        SnapshotTickMismatch,
        UnsupportedSnapshotMode,
    };

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

pub fn modeSnapshotFromRunner(
    runner: *const live_runner.LiveRunner,
    tick_index: i32,
) SnapshotBridgeError!?rollback_resync_v5.ModeStateSnapshotV2 {
    const session = &runner.session;
    return switch (session.game_mode) {
        .survival => .{ .survival = .{
            .tick_index = @max(0, tick_index),
            .runtime_state = .{
                .elapsed_ms = session.elapsed_ms_sim,
                .stage = session.spawn_stage,
                .spawn_cooldown_ms = session.spawn_cooldown,
                .perk_pending_count = session.state.perk_selection.pending_count,
            },
        } },
        .rush => .{ .rush = .{
            .tick_index = @max(0, tick_index),
            .runtime_state = .{
                .elapsed_ms = @floatFromInt(session.elapsed_ms_sim_rush),
                .spawn_cooldown_ms = session.spawn_cooldown,
                .kill_count = session.creatures.kill_count,
            },
        } },
        .quests => .{ .quests = .{
            .tick_index = @max(0, tick_index),
            .runtime_state = .{
                .elapsed_ms = session.elapsed_ms_sim,
                .spawn_entries = session.quest_spawn_entries,
                .spawn_timeline_ms = session.quest_spawn_timeline_ms,
                .no_creatures_timer_ms = session.quest_no_creatures_timer_ms,
                .completion_transition_ms = session.quest_completion_transition_ms,
                .perk_pending_count = session.state.perk_selection.pending_count,
            },
        } },
        .typo, .tutorial => null,
    };
}

pub fn encodeRunnerModeSnapshot(
    allocator: std.mem.Allocator,
    runner: *const live_runner.LiveRunner,
    tick_index: i32,
) SnapshotBridgeError!?[]u8 {
    const snapshot = try modeSnapshotFromRunner(runner, tick_index) orelse return null;
    const encoded = try rollback_resync_v5.encodeModeSnapshot(allocator, snapshot);
    return encoded;
}

pub fn applyModeSnapshotToRunner(
    runner: *live_runner.LiveRunner,
    snapshot: rollback_resync_v5.ModeStateSnapshotV2,
) SnapshotBridgeError!void {
    const snapshot_tick = snapshot.tickIndex();
    if (snapshot_tick < 0) return error.SnapshotTickMismatch;
    const session_tick: usize = @intCast(snapshot_tick + 1);

    switch (snapshot) {
        .survival => |survival| {
            if (runner.session.game_mode != .survival) return error.SnapshotModeMismatch;
            const runtime = survival.runtime_state;
            runner.session.tick_index = session_tick;
            runner.session.elapsed_ms_sim = runtime.elapsed_ms;
            runner.session.spawn_stage = runtime.stage;
            runner.session.spawn_cooldown = runtime.spawn_cooldown_ms;
        },
        .rush => |rush| {
            if (runner.session.game_mode != .rush) return error.SnapshotModeMismatch;
            const runtime = rush.runtime_state;
            runner.session.tick_index = session_tick;
            runner.session.elapsed_ms_sim = runtime.elapsed_ms;
            runner.session.elapsed_ms_sim_rush = @intFromFloat(runtime.elapsed_ms);
            runner.session.spawn_cooldown = runtime.spawn_cooldown_ms;
            runner.session.creatures.kill_count = runtime.kill_count;
        },
        .quests => |quests| {
            if (runner.session.game_mode != .quests) return error.SnapshotModeMismatch;
            const runtime = quests.runtime_state;
            runner.session.tick_index = session_tick;
            runner.session.elapsed_ms_sim = runtime.elapsed_ms;
            try runner.session.setQuestSpawnEntries(runtime.spawn_entries);
            runner.session.quest_spawn_timeline_ms = runtime.spawn_timeline_ms;
            runner.session.quest_no_creatures_timer_ms = runtime.no_creatures_timer_ms;
            runner.session.quest_completion_transition_ms = runtime.completion_transition_ms;
            runner.session.quest_completed = false;
            runner.session.quest_play_hit_sfx = false;
            runner.session.quest_play_completion_music = false;
        },
    }
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

test "rollback live bridge captures and applies survival mode snapshot" {
    var runner = try live_runner.LiveRunner.init(.{ .game_mode = .survival });
    runner.session.tick_index = 11;
    runner.session.elapsed_ms_sim = 123.0;
    runner.session.spawn_stage = 3;
    runner.session.spawn_cooldown = 45.0;

    const snapshot = (try modeSnapshotFromRunner(&runner, 10)).?;
    var restored = try live_runner.LiveRunner.init(.{ .game_mode = .survival });
    try applyModeSnapshotToRunner(&restored, snapshot);

    try std.testing.expectEqual(@as(usize, 11), restored.session.tick_index);
    try std.testing.expectApproxEqAbs(@as(f32, 123.0), restored.session.elapsed_ms_sim, 0.001);
    try std.testing.expectEqual(@as(i32, 3), restored.session.spawn_stage);
    try std.testing.expectApproxEqAbs(@as(f32, 45.0), restored.session.spawn_cooldown, 0.001);
}

test "rollback live bridge applies quest snapshot with owned spawn table copy" {
    var runner = try live_runner.LiveRunner.init(.{
        .game_mode = .quests,
        .quest_level_key = 205,
    });
    const entries = [_]spawn_mod.QuestSpawnEntry{
        .{
            .pos = .{ .x = 10.0, .y = 20.0 },
            .heading = 0.0,
            .spawn_id = .alien_random_06,
            .trigger_ms = 2000,
            .count = 2,
        },
    };
    const snapshot: rollback_resync_v5.ModeStateSnapshotV2 = .{ .quests = .{
        .tick_index = 4,
        .runtime_state = .{
            .elapsed_ms = 321.0,
            .spawn_entries = entries[0..],
            .spawn_timeline_ms = 222.0,
            .no_creatures_timer_ms = 111.0,
            .completion_transition_ms = 999.0,
            .perk_pending_count = 7,
        },
    } };

    try applyModeSnapshotToRunner(&runner, snapshot);

    try std.testing.expectEqual(@as(usize, 5), runner.session.tick_index);
    try std.testing.expectEqual(@as(usize, 1), runner.session.quest_spawn_entries.len);
    try std.testing.expectEqual(spawn_mod.SpawnId.alien_random_06, runner.session.quest_spawn_entries[0].spawn_id);
    try std.testing.expectApproxEqAbs(@as(f32, 321.0), runner.session.elapsed_ms_sim, 0.001);
    try std.testing.expectApproxEqAbs(@as(f32, 222.0), runner.session.quest_spawn_timeline_ms, 0.001);
    try std.testing.expect(!runner.session.quest_completed);
}
