//! Replay playback: step a session through a replay's ticks, enforce the
//! run-end and command rules, and derive the `RunResult`
//! (`SessionPlaybackDriver` and `build_run_result` on the Python side).
const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");

const replay_codec = @import("../replay_codec.zig");
const quest_results = @import("../quest_results.zig");
const perks = @import("perks.zig");
const player_runtime = @import("player.zig");
const projectiles_mod = @import("projectiles.zig");
const spawn_mod = @import("spawn.zig");
const state_mod = @import("state.zig");
const survival_progression = @import("survival_progression.zig");
const weapons_runtime = @import("weapons.zig");
const math = @import("math.zig");
const replay_commands = @import("replay/commands.zig");
const replay_diagnostic_trace = @import("replay/diagnostic_trace.zig");
const replay_movement = @import("movement.zig");
const runtime_session = @import("session.zig");
const session_builders = @import("session_builders.zig");
const replay_step = @import("replay/step.zig");

const narrowF32 = native_math.roundF32;
const PerkId = perks.PerkId;
const RunResult = replay_codec.RunResult;
const native_half_pi: f32 = native_math.native_half_pi;

pub const ReplayRunnerError = error{
    OutOfMemory,
    // Run spec (`DeterministicSessionError`).
    InvalidPlayerCount,
    InvalidWorldSize,
    InvalidTickRate,
    UnsupportedGameMode,
    InvalidQuestSpawnTable,
    // Tick simulation (`replay_step.StepError`).
    InvalidSpawnTemplate,
    NoPendingPerk,
    EveryPlayerDead,
    ChoiceNotOffered,
    MissingRngCallerTag,
    RunEndedEarly,
};

/// Where a run failed; `write` renders the error for users.
pub const RunFailure = struct {
    tick_index: usize = 0,
    tick_count: usize = 0,
    command: ?replay_codec.Command = null,
    outcome: replay_codec.RunOutcome = .incomplete,

    pub fn write(self: RunFailure, writer: *std.Io.Writer, err: ReplayRunnerError) std.Io.Writer.Error!void {
        switch (err) {
            error.NoPendingPerk, error.EveryPlayerDead, error.ChoiceNotOffered => {
                try writer.print("tick {d}: ", .{self.tick_index});
                try replay_commands.writeError(writer, @errorCast(err), self.command.?);
            },
            error.RunEndedEarly => try writer.print(
                "run ended ({s}) at tick {d} but the replay has {d} ticks",
                .{ @tagName(self.outcome), self.tick_index, self.tick_count },
            ),
            error.InvalidQuestSpawnTable => try writer.writeAll("quest replay resolves to an invalid quest spawn table"),
            error.InvalidSpawnTemplate => try writer.print("tick {d}: native replay run hit an invalid creature spawn template", .{self.tick_index}),
            error.MissingRngCallerTag => try writer.print("tick {d}: native replay trace hit an untagged gameplay RNG draw", .{self.tick_index}),
            error.OutOfMemory => try writer.writeAll("native replay run ran out of memory"),
            error.InvalidPlayerCount, error.InvalidWorldSize, error.InvalidTickRate, error.UnsupportedGameMode => {
                try writer.print("native replay run rejected the run spec: {s}", .{@errorName(err)});
            },
        }
    }
};

pub const ReplayRunResult = struct {
    ticks_simulated: usize,
    /// Every recorded tick was simulated, so `result` is comparable with the recorded one.
    complete: bool,
    result: RunResult,
};

pub const ReplayTickTrace = replay_diagnostic_trace.ReplayTickTrace;
pub fn deinitReplayTickTraceRows(
    allocator: std.mem.Allocator,
    rows: []ReplayTickTrace,
) void {
    replay_diagnostic_trace.deinitReplayTickTraceSlice(allocator, rows);
}

pub const ReplayRunOptions = struct {
    /// Simulate only this prefix; a prefix never verifies a result.
    max_ticks: ?usize = null,
    quest_spawn_entries: ?[]const spawn_mod.QuestSpawnEntry = null,
    quest_start_weapon_id: ?i32 = null,
    trace_rng: bool = true,
    trace_timing: bool = true,
    failure: ?*RunFailure = null,
};

/// A session stepping through a replay's recorded ticks.
pub const Playback = struct {
    replay: replay_codec.Replay,
    session: runtime_session.DeterministicSession,
    tick_limit: usize,
    next_tick: usize = 0,
    failure: RunFailure,

    pub fn init(replay: replay_codec.Replay, options: ReplayRunOptions) ReplayRunnerError!Playback {
        const tick_count = replay.tickCount();
        return .{
            .replay = replay,
            .session = try session_builders.buildReplaySession(replay.run, .{
                .quest_spawn_entries = options.quest_spawn_entries,
                .quest_start_weapon_id = options.quest_start_weapon_id,
            }),
            .tick_limit = if (options.max_ticks) |max_ticks| @min(max_ticks, tick_count) else tick_count,
            .failure = .{ .tick_count = tick_count },
        };
    }

    pub fn done(self: *const Playback) bool {
        return self.next_tick >= self.tick_limit;
    }

    /// Whether every recorded tick is simulated (no `max_ticks` prefix).
    pub fn complete(self: *const Playback) bool {
        return self.tick_limit == self.replay.tickCount();
    }

    /// Simulate the next tick. A run that ends before the replay's last tick
    /// is an error.
    pub fn step(self: *Playback, options: replay_step.StepOptions) ReplayRunnerError!replay_step.StepResult {
        const tick_index = self.next_tick;
        self.failure.tick_index = tick_index;
        // The session may have moved since the last tick.
        self.session.rebindInternalPointers();

        var inputs_storage: [state_mod.max_players]player_runtime.GameInput = undefined;
        const inputs = self.replay.tickInputs(tick_index);
        for (inputs, inputs_storage[0..inputs.len]) |input, *mapped| mapped.* = mapReplayInputToGameInput(input);
        const commands = self.replay.tickCommands(tick_index);
        var step_options = options;
        var failed_command: usize = 0;
        step_options.failed_command_index = &failed_command;
        const step_result = replay_step.stepTick(
            &self.session,
            tick_index,
            inputs_storage[0..inputs.len],
            commands,
            replay_codec.tick_dt,
            step_options,
        ) catch |err| {
            if (failed_command < commands.len) self.failure.command = commands[failed_command];
            return err;
        };
        self.next_tick += 1;

        if (self.session.terminalOutcome()) |outcome| {
            if (self.next_tick < self.replay.tickCount()) {
                self.failure.outcome = outcome;
                return error.RunEndedEarly;
            }
        }
        return step_result;
    }

    /// Result after the simulated ticks; a prefix only reports a terminal outcome it reached.
    pub fn result(self: *const Playback) RunResult {
        const outcome = if (self.complete())
            self.session.endOutcome()
        else
            self.session.terminalOutcome() orelse .incomplete;
        return buildRunResult(&self.session, outcome);
    }
};

/// The authoritative end-of-run state, derived like live play derives it.
pub fn buildRunResult(
    session: *const runtime_session.DeterministicSession,
    outcome: replay_codec.RunOutcome,
) RunResult {
    const state = &session.state;
    const players = session.playersConst();
    const elapsed_ms: replay_codec.Int = @intFromFloat(session.runElapsedMs());

    var result: RunResult = .{
        .outcome = outcome,
        .elapsed_ms = elapsed_ms,
        .kills = session.creatures.kill_count,
        .rng_state = state.rng.state,
        .pending_perks = state.perk_selection.pending_count,
        .quest_final_ms = null,
        .player_count = players.len,
    };
    var health_values: [state_mod.max_players]f32 = undefined;
    for (players, result.players_buffer[0..players.len], 0..) |player, *player_result, index| {
        var shots_fired: i32 = undefined;
        var shots_hit: i32 = undefined;
        if (session.game_mode == .typo) {
            shots_fired = state.typo.typing.submit_count;
            shots_hit = state.typo.typing.match_count;
        } else {
            // Piercing shots can hit several creatures; the high-score record
            // clamps hits to shots fired.
            shots_fired = @max(0, state.shots_fired[index]);
            shots_hit = @max(0, @min(state.shots_hit[index], shots_fired));
        }
        player_result.* = .{
            .experience = player.experience,
            .health = player.health,
            .shots_fired = shots_fired,
            .shots_hit = shots_hit,
            .most_used_weapon_id = survival_progression.mostUsedWeaponIdForPlayer(state.*, index, player.weapon.weapon_id),
        };
        health_values[index] = player.health;
    }
    if (outcome == .quest_completed) {
        result.quest_final_ms = quest_results.computeQuestFinalTime(
            @intCast(elapsed_ms),
            health_values[0..players.len],
            state.perk_selection.pending_count,
        ).final_time_ms;
    }
    return result;
}

pub fn runReplay(replay: replay_codec.Replay) ReplayRunnerError!ReplayRunResult {
    return runReplayWithOptions(replay, .{});
}

pub fn runReplayWithOptions(
    replay: replay_codec.Replay,
    options: ReplayRunOptions,
) ReplayRunnerError!ReplayRunResult {
    return runReplayWithTrace(std.heap.page_allocator, replay, null, options);
}

/// Run a replay, appending one trace row per simulated tick to `trace_out`.
/// On error the rows up to the failing tick stay in `trace_out`.
pub fn runReplayWithTrace(
    trace_allocator: std.mem.Allocator,
    replay: replay_codec.Replay,
    trace_out: ?*std.ArrayList(ReplayTickTrace),
    options: ReplayRunOptions,
) ReplayRunnerError!ReplayRunResult {
    var playback = Playback.init(replay, options) catch |err| {
        if (options.failure) |failure| failure.* = .{ .tick_count = replay.tickCount() };
        return err;
    };
    errdefer if (options.failure) |failure| {
        failure.* = playback.failure;
    };

    while (!playback.done()) {
        var step_options: replay_step.StepOptions = .{};
        var trace_collector: TickTraceCollector = undefined;
        var trace_collector_active = false;
        var rng_trace_active = false;
        const rng = &playback.session.state.rng;
        defer if (trace_collector_active) trace_collector.deinit();
        defer if (rng_trace_active) rng.setTraceSink(null, null, false);
        if (trace_out != null and (options.trace_rng or options.trace_timing)) {
            trace_collector = TickTraceCollector.init(trace_allocator);
            trace_collector_active = true;

            if (options.trace_rng) {
                rng.setTraceSink(&trace_collector, TickTraceCollector.onRngDraw, true);
                rng_trace_active = true;
            }
            if (options.trace_timing) {
                step_options.timing_trace_ctx = &trace_collector;
                step_options.timing_trace_sink = TickTraceCollector.onTimingSample;
            }
        }

        const tick_index = playback.next_tick;
        const step_result = playback.step(step_options) catch |err| switch (err) {
            // The run-end check follows a completed tick, which still belongs in the trace.
            error.RunEndedEarly => {
                if (trace_out) |trace| try appendTickTrace(trace_allocator, trace, &playback, tick_index, null, &trace_collector, trace_collector_active);
                return err;
            },
            else => return err,
        };
        if (rng_trace_active and rng.consumeMissingTraceCaller()) {
            return error.MissingRngCallerTag;
        }
        if (trace_out) |trace| {
            try appendTickTrace(trace_allocator, trace, &playback, tick_index, &step_result, &trace_collector, trace_collector_active);
        }
    }

    return .{
        .ticks_simulated = playback.tick_limit,
        .complete = playback.complete(),
        .result = playback.result(),
    };
}

fn appendTickTrace(
    allocator: std.mem.Allocator,
    trace: *std.ArrayList(ReplayTickTrace),
    playback: *const Playback,
    tick_index: usize,
    step_result: ?*const replay_step.StepResult,
    collector: *TickTraceCollector,
    collector_active: bool,
) ReplayRunnerError!void {
    const context = &playback.session;
    const players = context.playersConst();
    const rng_rows = if (collector_active) try collector.takeRngRows() else &.{};
    errdefer if (rng_rows.len > 0) allocator.free(rng_rows);
    const timing_samples = if (collector_active) try collector.takeTimingSamples() else &.{};
    errdefer if (timing_samples.len > 0) allocator.free(timing_samples);
    const rng_state = context.state.rng.state;
    var row = try replay_diagnostic_trace.buildReplayTickTraceWithEntities(
        allocator,
        tick_index,
        @as(f32, @floatCast(context.runElapsedMs())),
        &context.state,
        players[0],
        players,
        &context.creatures,
        &context.projectiles,
        &context.secondary_projectiles,
        &context.bonuses,
        if (step_result) |r| r.rng_after_perk_effects else rng_state,
        if (step_result) |r| r.rng_after_creatures else rng_state,
        if (step_result) |r| r.rng_after_projectiles else rng_state,
        if (step_result) |r| r.rng_after_secondary_projectiles else rng_state,
        if (step_result) |r| r.rng_after_particles else rng_state,
        if (step_result) |r| r.rng_after_player_update else rng_state,
        if (step_result) |r| r.rng_after_stage_spawns else rng_state,
        if (step_result) |r| r.rng_after_wave_spawns else rng_state,
        if (step_result) |r| r.rng_after_spawns else rng_state,
        if (step_result) |r| r.rng_after_bonus_update else rng_state,
        rng_rows,
        timing_samples,
    );
    if (step_result) |r| {
        row.event_hit_count = r.projectile_tick_stats.hit_count;
        row.event_pickup_count = @intCast(r.bonus_pickups.len);
        row.sfx_events = r.sfx_events;
    }
    try trace.append(allocator, row);
}

pub fn mapReplayInputToGameInput(input: replay_codec.PlayerInput) player_runtime.GameInput {
    const flags = replay_codec.unpackInputFlags(input.flags);
    return .{
        .move_x = input.move_x,
        .move_y = input.move_y,
        .aim_x = input.aim_x,
        .aim_y = input.aim_y,
        .flags = .{
            .fire_down = flags.fire_down,
            .fire_pressed = flags.fire_pressed,
            .reload_pressed = flags.reload_pressed,
            .reload_down = flags.reload_down,
            .fire_bullets_key_down = flags.fire_bullets_key_down,
            .move_mode = flags.move_mode,
            .aim_scheme = flags.aim_scheme,
            .move_forward_pressed = flags.move_forward_pressed,
            .move_backward_pressed = flags.move_backward_pressed,
            .turn_left_pressed = flags.turn_left_pressed,
            .turn_right_pressed = flags.turn_right_pressed,
        },
    };
}

/// A small valid survival replay carrying the result its ticks simulate to,
/// for tests and embedders that need real replay bytes.
pub fn buildSmokeTestReplayPayload(allocator: std.mem.Allocator) ![]u8 {
    var replay = testReplay(.{ .game_mode = .survival, .seed = 1 }, &aimed_inputs, &.{}, zero_command_ends[0..2]);
    replay.result = (try runReplay(replay)).result;
    return replay_codec.encodePayload(allocator, replay);
}

pub fn buildSmokeTestReplayFile(allocator: std.mem.Allocator) ![]u8 {
    const payload = try buildSmokeTestReplayPayload(allocator);
    defer allocator.free(payload);
    return replay_codec.wrapZstdFilePayload(allocator, payload);
}

const aimed_inputs = [_]replay_codec.PlayerInput{.{ .aim_x = 512.0, .aim_y = 512.0 }} ** 256;
const zero_command_ends = [_]u32{0} ** 256;

/// A replay over `inputs` (tick-major) whose recorded result is a placeholder.
fn testReplay(
    run: replay_codec.RunSpec,
    inputs: []const replay_codec.PlayerInput,
    commands: []const replay_codec.Command,
    command_ends: []const u32,
) replay_codec.Replay {
    return .{
        .game_version = "0.10.0",
        .run = run,
        .result = .{
            .outcome = .incomplete,
            .elapsed_ms = 0,
            .kills = 0,
            .rng_state = 0,
            .pending_perks = 0,
            .quest_final_ms = null,
            .player_count = 0,
        },
        .inputs = inputs[0 .. command_ends.len * run.player_count],
        .commands = commands,
        .command_ends = command_ends,
    };
}

const TickTraceCollector = struct {
    allocator: std.mem.Allocator,
    failed: bool = false,
    rng_rows: std.ArrayList(replay_diagnostic_trace.ReplayTickRngDraw) = .empty,
    timing_samples: std.ArrayList(replay_diagnostic_trace.ReplayTickTimingSample) = .empty,

    fn init(allocator: std.mem.Allocator) TickTraceCollector {
        return .{
            .allocator = allocator,
        };
    }

    fn deinit(self: *TickTraceCollector) void {
        self.rng_rows.deinit(self.allocator);
        self.timing_samples.deinit(self.allocator);
        self.* = undefined;
    }

    fn takeRngRows(self: *TickTraceCollector) error{OutOfMemory}![]const replay_diagnostic_trace.ReplayTickRngDraw {
        if (self.failed) return error.OutOfMemory;
        if (self.rng_rows.items.len == 0) return &.{};
        return self.rng_rows.toOwnedSlice(self.allocator);
    }

    fn takeTimingSamples(self: *TickTraceCollector) error{OutOfMemory}![]const replay_diagnostic_trace.ReplayTickTimingSample {
        if (self.failed) return error.OutOfMemory;
        if (self.timing_samples.items.len == 0) return &.{};
        return self.timing_samples.toOwnedSlice(self.allocator);
    }

    fn onRngDraw(ctx: ?*anyopaque, draw: spawn_mod.Crand.TraceDraw) void {
        var self: *TickTraceCollector = @ptrCast(@alignCast(ctx orelse return));
        if (self.failed) return;

        self.rng_rows.append(self.allocator, .{
            .tick_call_index = std.math.cast(i32, self.rng_rows.items.len + 1) orelse {
                self.failed = true;
                return;
            },
            .value_15 = @intCast(draw.value_15),
            .state_before_u32 = draw.state_before,
            .state_after_u32 = draw.state_after,
            .caller = if (draw.caller) |caller| @intFromEnum(caller) else null,
        }) catch {
            self.failed = true;
        };
    }

    fn onTimingSample(ctx: ?*anyopaque, sample: replay_diagnostic_trace.ReplayTickTimingSample) void {
        var self: *TickTraceCollector = @ptrCast(@alignCast(ctx orelse return));
        if (self.failed) return;

        self.timing_samples.append(self.allocator, sample) catch {
            self.failed = true;
        };
    }
};

fn f32Bits(value: f32) u32 {
    return @bitCast(value);
}

const testing = std.testing;

/// Step every tick of `replay` and return the finished playback.
fn playThrough(replay: replay_codec.Replay, options: ReplayRunOptions) ReplayRunnerError!Playback {
    var playback = try Playback.init(replay, options);
    while (!playback.done()) _ = try playback.step(.{});
    return playback;
}

fn withFlags(comptime count: usize, flags: [count]u32) [count]replay_codec.PlayerInput {
    var inputs: [count]replay_codec.PlayerInput = undefined;
    for (&inputs, flags) |*input, value| input.* = .{ .aim_x = 512.0, .aim_y = 512.0, .flags = value };
    return inputs;
}

fn expectFailure(replay: replay_codec.Replay, options: ReplayRunOptions, expected_err: ReplayRunnerError, expected: []const u8) !void {
    var failure: RunFailure = .{};
    var failing_options = options;
    failing_options.failure = &failure;
    const err = if (runReplayWithOptions(replay, failing_options)) |_| return error.TestExpectedError else |err| err;
    try testing.expectEqual(expected_err, err);
    var buffer: [160]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try failure.write(&writer, err);
    try testing.expectEqualStrings(expected, writer.buffered());
}

test "survival run derives a deterministic incomplete result" {
    const replay = testReplay(.{ .game_mode = .survival, .seed = 0xBEEF }, &aimed_inputs, &.{}, zero_command_ends[0..3]);
    const first = try runReplay(replay);
    const second = try runReplay(replay);
    try testing.expectEqual(first.result.rng_state, second.result.rng_state);
    try testing.expectEqual(@as(usize, 3), first.ticks_simulated);
    try testing.expect(first.complete);
    const result = first.result;
    try testing.expectEqual(replay_codec.RunOutcome.incomplete, result.outcome);
    try testing.expectEqual(@as(replay_codec.Int, 48), result.elapsed_ms);
    try testing.expectEqual(@as(?replay_codec.Int, null), result.quest_final_ms);
    try testing.expectEqual(@as(usize, 1), result.players().len);
    try testing.expectEqual(@as(f32, 100.0), result.players()[0].health);
    try testing.expectEqual(game_ids.WeaponId.pistol, result.players()[0].most_used_weapon_id);
}

test "shots are reported per player and hits clamp to shots fired" {
    const run: replay_codec.RunSpec = .{ .game_mode = .survival, .seed = 1, .player_count = 2 };
    var playback = try playThrough(testReplay(run, &aimed_inputs, &.{}, zero_command_ends[0..1]), .{});
    playback.session.state.shots_fired[0] = 2;
    playback.session.state.shots_hit[0] = 5;
    playback.session.state.shots_fired[1] = -3;
    playback.session.state.shots_hit[1] = -1;
    const result = playback.result();
    try testing.expectEqual(@as(replay_codec.Int, 2), result.players()[0].shots_fired);
    try testing.expectEqual(@as(replay_codec.Int, 2), result.players()[0].shots_hit);
    try testing.expectEqual(@as(replay_codec.Int, 0), result.players()[1].shots_fired);
    try testing.expectEqual(@as(replay_codec.Int, 0), result.players()[1].shots_hit);
}

test "a prefix reports incomplete unless it reached a terminal outcome" {
    const replay = testReplay(.{ .game_mode = .survival, .seed = 1 }, &aimed_inputs, &.{}, zero_command_ends[0..3]);
    const prefix = try runReplayWithOptions(replay, .{ .max_ticks = 2 });
    try testing.expect(!prefix.complete);
    try testing.expectEqual(@as(usize, 2), prefix.ticks_simulated);
    try testing.expectEqual(@as(replay_codec.Int, 32), prefix.result.elapsed_ms);
    const beyond = try runReplayWithOptions(replay, .{ .max_ticks = 9 });
    try testing.expect(beyond.complete);
}

test "a run that ends before the last tick is rejected" {
    const replay = testReplay(.{ .game_mode = .rush, .seed = 1 }, &aimed_inputs, &.{}, zero_command_ends[0..2]);
    var playback = try Playback.init(replay, .{});
    playback.session.players()[0].health = 0.0;
    try testing.expectError(error.RunEndedEarly, playback.step(.{}));
    var buffer: [160]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try playback.failure.write(&writer, error.RunEndedEarly);
    try testing.expectEqualStrings("run ended (death) at tick 0 but the replay has 2 ticks", writer.buffered());

    var last_tick = try Playback.init(testReplay(replay.run, &aimed_inputs, &.{}, zero_command_ends[0..1]), .{});
    last_tick.session.players()[0].health = 0.0;
    _ = try last_tick.step(.{});
    try testing.expectEqual(replay_codec.RunOutcome.death, last_tick.result().outcome);
}

test "quest completion ends the run and scores the final time" {
    const run: replay_codec.RunSpec = .{ .game_mode = .quests, .seed = 101, .quest_level = .{ .major = 1, .minor = 1 } };
    const options: ReplayRunOptions = .{ .quest_spawn_entries = &.{} };
    var probe = try Playback.init(testReplay(run, &aimed_inputs, &.{}, &zero_command_ends), options);
    while (true) _ = probe.step(.{}) catch |err| switch (err) {
        error.RunEndedEarly => break,
        else => return err,
    };
    const ticks = probe.next_tick;

    const completed = try runReplayWithOptions(testReplay(run, &aimed_inputs, &.{}, zero_command_ends[0..ticks]), options);
    const result = completed.result;
    try testing.expectEqual(replay_codec.RunOutcome.quest_completed, result.outcome);
    const expected = quest_results.computeQuestFinalTime(@intCast(result.elapsed_ms), &.{100.0}, 0).final_time_ms;
    try testing.expectEqual(@as(?replay_codec.Int, expected), result.quest_final_ms);

    var message: [96]u8 = undefined;
    try expectFailure(
        testReplay(run, &aimed_inputs, &.{}, zero_command_ends[0 .. ticks + 1]),
        options,
        error.RunEndedEarly,
        try std.fmt.bufPrint(&message, "run ended (quest_completed) at tick {d} but the replay has {d} ticks", .{ ticks - 1, ticks + 1 }),
    );
}

test "perk commands the live UI cannot issue are rejected" {
    const pick = [_]replay_codec.Command{.{ .perk_pick = .{ .player_index = 0, .choice_index = 0 } }};
    try expectFailure(
        testReplay(.{ .game_mode = .survival, .seed = 1 }, &aimed_inputs, &pick, &.{1}),
        .{},
        error.NoPendingPerk,
        "tick 0: perk_pick without a pending perk",
    );
    const open = [_]replay_codec.Command{.{ .perk_menu_open = .{ .player_index = 0 } }};
    try expectFailure(
        testReplay(.{ .game_mode = .rush, .seed = 1 }, &aimed_inputs, &open, &.{ 0, 1 }),
        .{},
        error.NoPendingPerk,
        "tick 1: perk_menu_open without a pending perk",
    );
}

test "typo run reports submitted words as shots fired" {
    const commands = [_]replay_codec.Command{
        .{ .typo_char = .{ .player_index = 0, .ch = "r" } },
        .{ .typo_char = .{ .player_index = 0, .ch = "e" } },
        .{ .typo_char = .{ .player_index = 0, .ch = "l" } },
        .{ .typo_char = .{ .player_index = 0, .ch = "o" } },
        .{ .typo_char = .{ .player_index = 0, .ch = "a" } },
        .{ .typo_char = .{ .player_index = 0, .ch = "d" } },
        .{ .typo_submit = .{ .player_index = 0 } },
    };
    const run = try runReplay(testReplay(.{ .game_mode = .typo, .seed = 1 }, &aimed_inputs, &commands, &.{ 1, 2, 3, 4, 5, 6, 7 }));
    const player = run.result.players()[0];
    try testing.expectEqual(@as(replay_codec.Int, 1), player.shots_fired);
    try testing.expectEqual(@as(replay_codec.Int, 0), player.shots_hit);
    try testing.expectEqual(game_ids.WeaponId.shotgun, player.most_used_weapon_id);
}

test "typo run spawns creatures after creature update phase" {
    // The expected state matches the Python simulation of the same replay.
    const commands = [_]replay_codec.Command{.{ .typo_char = .{ .player_index = 0, .ch = "r" } }};
    const inputs = [_]replay_codec.PlayerInput{.{}};
    const playback = try playThrough(testReplay(.{ .game_mode = .typo, .seed = 0xBEEF }, &inputs, &commands, &.{1}), .{});
    try testing.expect(playback.session.creatures.activeCount() > 0);
    try testing.expectEqual(@as(u32, 436623559), playback.session.state.rng.state);
}

test "typo input fire and reload flags have no effect" {
    const idle = [_]replay_codec.PlayerInput{.{ .aim_x = 512.0, .aim_y = 512.0 }} ** 3;
    const firing = withFlags(3, .{replay_codec.fire_down_flag | replay_codec.fire_pressed_flag | replay_codec.reload_pressed_flag} ** 3);
    const run: replay_codec.RunSpec = .{ .game_mode = .typo, .seed = 7 };
    const baseline = try runReplay(testReplay(run, &idle, &.{}, zero_command_ends[0..3]));
    const pressed = try runReplay(testReplay(run, &firing, &.{}, zero_command_ends[0..3]));
    try testing.expectEqual(baseline.result.rng_state, pressed.result.rng_state);
}

test "rush run enforces the assault rifle and advances spawns in integer milliseconds" {
    const playback = try playThrough(testReplay(.{ .game_mode = .rush, .seed = 0xBEEF }, &([_]replay_codec.PlayerInput{.{}} ** 16), &.{}, zero_command_ends[0..16]), .{});
    try testing.expectEqual(game_ids.WeaponId.assault_rifle, playback.session.playersConst()[0].weapon.weapon_id);
    try testing.expectEqual(@as(usize, 4), playback.session.creatures.activeCount());
    try testing.expectEqual(@as(u32, 2055104443), playback.session.state.rng.state);
}

test "survival and rush runs support player counts 1 through 4" {
    for ([_]game_ids.GameModeId{ .survival, .rush }) |game_mode| {
        for (1..replay_codec.max_players + 1) |player_count| {
            var inputs = aimed_inputs;
            inputs[2 * player_count - 1].flags = replay_codec.fire_down_flag;
            const run = try runReplay(testReplay(
                .{ .game_mode = game_mode, .seed = 0x1234, .player_count = @intCast(player_count) },
                &inputs,
                &.{},
                zero_command_ends[0..2],
            ));
            try testing.expectEqual(player_count, run.result.players().len);
        }
    }
}

test "quest run resolves the native spawn table and start weapon from the run spec" {
    for ([_]struct { level: replay_codec.QuestLevel, weapon: game_ids.WeaponId }{
        .{ .level = .{ .major = 1, .minor = 1 }, .weapon = .pistol },
        .{ .level = .{ .major = 2, .minor = 5 }, .weapon = .gauss_gun },
        .{ .level = .{ .major = 3, .minor = 9 }, .weapon = .gauss_gun },
    }) |case| {
        for (1..replay_codec.max_players + 1) |player_count| {
            const run: replay_codec.RunSpec = .{ .game_mode = .quests, .seed = 205, .quest_level = case.level, .player_count = @intCast(player_count) };
            var playback = try playThrough(testReplay(run, &aimed_inputs, &.{}, zero_command_ends[0..1]), .{});
            try testing.expectEqual(case.weapon, playback.session.playersConst()[0].weapon.weapon_id);
            try testing.expect(playback.session.questSpawnEntries().len > 0);
        }
    }
}

test "quest run rejects an oversized spawn override table" {
    const oversized = try testing.allocator.alloc(spawn_mod.QuestSpawnEntry, runtime_session.max_sim_quest_spawn_entries + 1);
    defer testing.allocator.free(oversized);
    const run: replay_codec.RunSpec = .{ .game_mode = .quests, .seed = 101, .quest_level = .{ .major = 1, .minor = 1 } };
    try testing.expectError(
        error.InvalidQuestSpawnTable,
        runReplayWithOptions(testReplay(run, &aimed_inputs, &.{}, zero_command_ends[0..1]), .{ .quest_spawn_entries = oversized }),
    );
}

test "trace records authoritative rng rows and timing samples" {
    const inputs = [_]replay_codec.PlayerInput{.{ .aim_x = 700.0, .aim_y = 512.0, .flags = replay_codec.fire_down_flag | replay_codec.fire_pressed_flag }};
    const replay = testReplay(.{ .game_mode = .survival, .seed = 0x1234 }, &inputs, &.{}, zero_command_ends[0..1]);

    var trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer trace.deinit(testing.allocator);
    defer deinitReplayTickTraceRows(testing.allocator, trace.items);
    _ = try runReplayWithTrace(testing.allocator, replay, &trace, .{});

    try testing.expectEqual(@as(usize, 1), trace.items.len);
    const row = trace.items[0];
    try testing.expectEqual(@as(usize, 1), row.timing_samples.len);
    try testing.expectEqualStrings("gpur_enter", row.timing_samples[0].phase);
    try testing.expectEqual(replay_codec.tick_dt, row.timing_samples[0].frame_dt_f32.?);
    try testing.expectEqual(@as(i32, 16), row.timing_samples[0].frame_dt_ms_i32.?);
    try testing.expectEqualStrings("gameplay_update_and_render", row.timing_samples[0].mode_fn.?);

    try testing.expect(row.rng_rows.len > 0);
    try testing.expectEqual(@as(i32, 1), row.rng_rows[0].tick_call_index);
    for (row.rng_rows[1..], 1..) |draw, idx| {
        try testing.expectEqual(@as(i32, @intCast(idx + 1)), draw.tick_call_index);
        try testing.expectEqual(row.rng_rows[idx - 1].state_after_u32, draw.state_before_u32);
    }
    try testing.expectEqual(row.rng.rng_state, row.rng_rows[row.rng_rows.len - 1].state_after_u32);

    var untraced: std.ArrayList(ReplayTickTrace) = .empty;
    defer untraced.deinit(testing.allocator);
    defer deinitReplayTickTraceRows(testing.allocator, untraced.items);
    _ = try runReplayWithTrace(testing.allocator, replay, &untraced, .{ .trace_rng = false, .trace_timing = false });
    try testing.expectEqual(@as(usize, 0), untraced.items[0].rng_rows.len);
    try testing.expectEqual(@as(usize, 0), untraced.items[0].timing_samples.len);
    try testing.expectEqual(row.rng.rng_state, untraced.items[0].rng.rng_state);
}

test "smoke replay verifies against its own recorded result" {
    const file = try buildSmokeTestReplayFile(testing.allocator);
    defer testing.allocator.free(file);
    var diagnostic: replay_codec.Diagnostic = .{};
    const replay = try replay_codec.loadReplay(testing.allocator, file, &diagnostic);
    defer replay.deinit(testing.allocator);
    const run = try runReplay(replay);
    try testing.expectEqualDeep(replay.result.players(), run.result.players());
    try testing.expectEqual(replay.result.rng_state, run.result.rng_state);
}

test "replay input adapter preserves packed flag decode semantics" {
    const packed_flags: u32 =
        replay_codec.fire_down_flag |
        replay_codec.reload_pressed_flag |
        replay_codec.reload_down_flag |
        replay_codec.fire_bullets_key_down_flag |
        replay_codec.move_keys_present_flag |
        replay_codec.move_forward_flag |
        replay_codec.turn_right_flag |
        replay_codec.move_mode_present_flag |
        (@as(u32, 5) << replay_codec.move_mode_shift) |
        replay_codec.aim_scheme_present_flag |
        (replay_codec.aim_scheme_mask << replay_codec.aim_scheme_shift);

    const replay_input: replay_codec.PlayerInput = .{
        .move_x = 1.5,
        .move_y = -0.25,
        .aim_x = 777.0,
        .aim_y = 333.0,
        .flags = packed_flags,
    };
    const mapped = mapReplayInputToGameInput(replay_input);
    const expected_flags = replay_codec.unpackInputFlags(packed_flags);

    try testing.expectEqual(replay_input.move_x, mapped.move_x);
    try testing.expectEqual(replay_input.move_y, mapped.move_y);
    try testing.expectEqual(replay_input.aim_x, mapped.aim_x);
    try testing.expectEqual(replay_input.aim_y, mapped.aim_y);
    try testing.expectEqual(expected_flags.fire_down, mapped.flags.fire_down);
    try testing.expectEqual(expected_flags.fire_pressed, mapped.flags.fire_pressed);
    try testing.expectEqual(expected_flags.reload_pressed, mapped.flags.reload_pressed);
    try testing.expectEqual(expected_flags.reload_down, mapped.flags.reload_down);
    try testing.expectEqual(expected_flags.fire_bullets_key_down, mapped.flags.fire_bullets_key_down);
    try testing.expectEqual(expected_flags.move_mode, mapped.flags.move_mode);
    try testing.expectEqual(expected_flags.aim_scheme, mapped.flags.aim_scheme);
    try testing.expectEqual(expected_flags.move_forward_pressed, mapped.flags.move_forward_pressed);
    try testing.expectEqual(expected_flags.move_backward_pressed, mapped.flags.move_backward_pressed);
    try testing.expectEqual(expected_flags.turn_left_pressed, mapped.flags.turn_left_pressed);
    try testing.expectEqual(expected_flags.turn_right_pressed, mapped.flags.turn_right_pressed);
}

test "fire cough projectile uses pre-move player position for muzzle origin" {
    var state = state_mod.GameplayState.init(1);
    var projectiles: projectiles_mod.ProjectilePool = .{};
    var player: state_mod.PlayerState = .{
        .index = 0,
        .pos = .{ .x = 100.0, .y = 100.0 },
        .aim = .{ .x = 200.0, .y = 100.0 },
        .aim_heading = 0.0,
        .fire_cough_timer = 1.95,
    };
    player.perk_counts.set(PerkId.fire_caugh, 1);

    const before_pos = player.pos;
    weapons_runtime.applyPlayerPerkTicks(
        &state,
        &player,
        &projectiles,
        0.1,
    );

    const move_input: player_runtime.GameInput = .{
        .move_x = 1.0,
        .move_y = 0.0,
        .aim_x = 200.0,
        .aim_y = 100.0,
        .flags = .{
            .fire_down = false,
            .fire_pressed = false,
            .reload_pressed = false,
        },
    };
    replay_movement.updatePlayerFromGameInput(&player, move_input, &state, null, 0.1);
    replay_movement.finalizePlayerPostUpdate(&player, 1024.0);

    try std.testing.expect(player.pos.x > before_pos.x);

    const proj = projectiles.entries[0];
    try std.testing.expect(proj.active);
    try std.testing.expectEqual(@intFromEnum(game_ids.ProjectileTypeId.fire_bullets), proj.type_id);

    const muzzle_dir = blk: {
        const dir: state_mod.Vec2 = .{
            .x = math.cos(-native_half_pi),
            .y = math.sin(-native_half_pi),
        };
        const cos_theta = math.cos(-0.150915);
        const sin_theta = math.sin(-0.150915);
        break :blk state_mod.Vec2{
            .x = dir.x * cos_theta - dir.y * sin_theta,
            .y = dir.x * sin_theta + dir.y * cos_theta,
        };
    };
    const expected_pos = state_mod.Vec2.add(before_pos, muzzle_dir.mul(16.0));
    try std.testing.expectApproxEqAbs(expected_pos.x, proj.pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(expected_pos.y, proj.pos.y, 1e-6);
}

