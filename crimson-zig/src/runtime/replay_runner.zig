const std = @import("std");
const game_ids = @import("../game_ids.zig");
const native_math = @import("native_math.zig");
const rng_callers = @import("../rng_caller_static.zig");

const replay_codec = @import("../replay_codec.zig");
const runtime_bootstrap = @import("bootstrap.zig");
const bonuses_mod = @import("bonuses.zig");
const creature_lifecycle = @import("lifecycle.zig").CreatureLifecycle;
const creatures_mod = @import("creatures.zig");
const perks = @import("perks.zig");
const player_runtime = @import("player.zig");
const projectiles_mod = @import("projectiles.zig");
const secondary_projectiles_mod = @import("secondary_projectiles.zig");
const spawn_mod = @import("spawn.zig");
const state_mod = @import("state.zig");
const survival_progression = @import("survival_progression.zig");
const weapons_runtime = @import("weapons.zig");
const math = @import("math.zig");
const replay_diagnostic_trace = @import("replay/diagnostic_trace.zig");
const replay_events = @import("replay/events.zig");
const replay_movement = @import("movement.zig");
const runtime_session = @import("session.zig");
const session_builders = @import("session_builders.zig");
const replay_step = @import("replay/step.zig");

const narrowF32 = native_math.roundF32;
const PerkId = perks.PerkId;
const GameModeId = game_ids.GameModeId;
const native_half_pi: f32 = native_math.native_half_pi;
const native_pi: f32 = native_math.native_pi;
const native_tau: f32 = native_math.native_tau;
const relative_move_heading_none: f32 = -1.0;
const relative_move_heading_forward: f32 = 0.0;
const relative_move_heading_forward_right: f32 = 0.7853981852531433;
const relative_move_heading_right: f32 = native_half_pi;
const relative_move_heading_backward_right: f32 = 2.356194496154785;
const relative_move_heading_backward: f32 = native_pi;
const relative_move_heading_backward_left: f32 = 3.9269909858703613;
const relative_move_heading_left: f32 = narrowF32(native_tau - native_half_pi);
const relative_move_heading_forward_left: f32 = 5.4977874755859375;
const relative_move_turn_align_scale: f32 = 7.957746982574463;
const movement_control_relative: i32 = 1;
const movement_control_static: i32 = 2;
const movement_control_dual_action_pad: i32 = 3;
const movement_control_computer: i32 = 5;
const aim_scheme_mouse: i32 = 0;
const aim_scheme_computer: i32 = 5;
const TickEventPhase = enum {
    pre_step,
    post_state_transition,
    post_spawn_hook,
    post_menu_open,
};
// Native capture state-transition rows that target state 12 trigger a full run-state reset.
const capture_state_reset_target: i32 = 12;
// Native creature_update_all writes `link_index = -700 - (rand & 0x3ff)` when AI7
// timer mode rolls from active to cooldown. Capture rows can carry that result
// directly, so replay backfills the skipped RNG draw for this range.
const ai7_link_timer_rollover_min: i32 = -1723;
const ai7_link_timer_rollover_max: i32 = -700;

pub const ReplayRunnerError = error{
    OutOfMemory,
    InvalidHeaderValue,
    InvalidCaptureEnumValue,
    UnsupportedGameMode,
    UnsupportedPlayerCount,
    UnsupportedInputQuantization,
    UnsupportedEventOrdering,
    UnsupportedEventKind,
    UnsupportedEventPlayerIndex,
    MissingRngCallerTag,
    InvalidSpawnTemplate,
    InvalidQuestSpawnTable,
};

fn parseCaptureCreatureAiMode(value: i32) ReplayRunnerError!spawn_mod.CreatureAiMode {
    const mode: spawn_mod.CreatureAiMode = @enumFromInt(value);
    return switch (mode) {
        .orbit_player,
        .orbit_player_tight,
        .chase_player,
        .follow_link,
        .link_guard,
        .follow_link_tethered,
        .orbit_link,
        .hold_timer,
        .orbit_player_wide,
        => mode,
        else => error.InvalidCaptureEnumValue,
    };
}

fn isAi7LinkTimerRolloverValue(link_index: i32) bool {
    return link_index >= ai7_link_timer_rollover_min and
        link_index <= ai7_link_timer_rollover_max;
}

pub const ReplayRunResult = struct {
    ticks: usize,
    elapsed_ms_nominal: i64,
    elapsed_ms_sim: i64,
    perk_menu_open_count: usize,
    perk_pick_count: usize,
    fire_pressed_count: usize,
    reload_pressed_count: usize,
    stage_spawn_count: usize,
    wave_spawn_count: usize,
    wave_spawn_rng_state: u32,
    player_level: i32,
    player_experience: i32,
    player_weapon_id: i32,
    most_used_weapon_id: i32,
    shots_fired: i32,
    shots_hit: i32,
    creature_kill_count: i32,
    creature_active_count: usize,
    perk_pending_count: i32,
    survival_reward_handout_enabled: bool,
    survival_reward_fire_seen: bool,
    survival_reward_damage_seen: bool,
    spawn_stage: i32,
    spawn_cooldown_ms: f32,
    quest_completion_transition_ms: f32,
    quest_completed: bool,
    quest_play_hit_sfx: bool,
    quest_play_completion_music: bool,
};

pub const ReplayTickTrace = replay_diagnostic_trace.ReplayTickTrace;
pub fn deinitReplayTickTraceRows(
    allocator: std.mem.Allocator,
    rows: []ReplayTickTrace,
) void {
    replay_diagnostic_trace.deinitReplayTickTraceSlice(allocator, rows);
}

pub const ReplayRunOptions = struct {
    strict_events: bool = true,
    max_ticks: ?usize = null,
    quest_spawn_entries: ?[]const spawn_mod.QuestSpawnEntry = null,
    quest_start_weapon_id: ?i32 = null,
    trace_rng: bool = true,
    trace_timing: bool = true,
};

pub fn runReplay(
    replay: replay_codec.Replay,
) ReplayRunnerError!ReplayRunResult {
    return runReplayWithOptions(replay, .{});
}

pub fn runReplayWithOptions(
    replay: replay_codec.Replay,
    options: ReplayRunOptions,
) ReplayRunnerError!ReplayRunResult {
    return runReplayWithTrace(
        std.heap.page_allocator,
        replay,
        null,
        options,
    );
}

/// Apply an ordered per-tick replay operation phase. The caller owns trace
/// placement: preludes run before the sink is enabled, while postludes run
/// after simulation with the tick sink still active.
pub fn applyReplayOperations(
    context: *runtime_session.DeterministicSession,
    ops: []const replay_codec.ReplayPreludeOp,
    dt_tick: f32,
) ReplayRunnerError!void {
    var menu_open_seen = false;
    const perk_event_dt = survival_progression.timeScaleReflexBoostBonus(
        context.state.bonuses.reflex_boost,
        context.state.time_scale_active,
        dt_tick,
    );

    for (ops) |op| {
        switch (op) {
            .game_frame_rng_advance => |advance| {
                var frame_index: u32 = 0;
                while (frame_index < advance.frames) : (frame_index += 1) {
                    _ = context.state.rng.randTagged(rng_callers.game_frame_update_discarded);
                }
            },
            .perk_menu_open, .perk_pick => {
                const event: replay_codec.ReplayEvent = switch (op) {
                    .perk_menu_open => |open| .{ .perk_menu_open = .{
                        .tick_index = open.tick_index,
                        .player_index = open.player_index,
                    } },
                    .perk_pick => |pick| .{ .perk_pick = .{
                        .tick_index = pick.tick_index,
                        .player_index = pick.player_index,
                        .choice_index = pick.choice_index,
                    } },
                    .game_frame_rng_advance => unreachable,
                };
                const outcome = try replay_events.applyReplayEvent(
                    event,
                    &context.state,
                    context.players(),
                    &context.creatures,
                    perk_event_dt,
                    &context.quest_spawn_timeline_ms,
                    &context.quest_no_creatures_timer_ms,
                    &context.quest_completion_transition_ms,
                    .{
                        .game_mode = context.game_mode,
                        .player_count = context.player_count,
                        .quest_unlock_index = context.quest_unlock_index,
                        .strict_events = context.strict_events,
                        .menu_open_seen_this_tick = menu_open_seen,
                    },
                );
                menu_open_seen = menu_open_seen or outcome.menu_open_seen_this_tick;
                context.perk_menu_open_count += outcome.perk_menu_open_count_delta;
                context.perk_pick_count += outcome.perk_pick_count_delta;
            },
        }
    }
}

pub fn applyReplayPostlude(
    context: *runtime_session.DeterministicSession,
    ops: []const replay_codec.ReplayPostludeOp,
    dt_tick: f32,
) ReplayRunnerError!void {
    const perk_event_dt = survival_progression.timeScaleReflexBoostBonus(
        context.state.bonuses.reflex_boost,
        context.state.time_scale_active,
        dt_tick,
    );
    for (ops) |open| {
        const outcome = try replay_events.applyReplayEvent(
            .{ .perk_menu_open = .{
                .tick_index = open.tick_index,
                .player_index = open.player_index,
            } },
            &context.state,
            context.players(),
            &context.creatures,
            perk_event_dt,
            &context.quest_spawn_timeline_ms,
            &context.quest_no_creatures_timer_ms,
            &context.quest_completion_transition_ms,
            .{
                .game_mode = context.game_mode,
                .player_count = context.player_count,
                .quest_unlock_index = context.quest_unlock_index,
                .strict_events = context.strict_events,
                .menu_open_seen_this_tick = false,
            },
        );
        context.perk_menu_open_count += outcome.perk_menu_open_count_delta;
    }
}

pub fn runReplayWithTrace(
    trace_allocator: std.mem.Allocator,
    replay: replay_codec.Replay,
    trace_out: ?*std.ArrayList(ReplayTickTrace),
    options: ReplayRunOptions,
) ReplayRunnerError!ReplayRunResult {
    const header = replay.header;
    const game_mode = std.enums.fromInt(GameModeId, header.game_mode_id) orelse {
        return error.UnsupportedGameMode;
    };
    if (header.player_count <= 0 or header.player_count > state_mod.max_players) {
        return error.UnsupportedPlayerCount;
    }
    if (!std.mem.eql(u8, header.input_quantization, "f32")) {
        return error.UnsupportedInputQuantization;
    }
    const max_world_size_i32_f32: f32 = @floatFromInt(std.math.maxInt(i32));
    if (!std.math.isFinite(header.world_size) or header.world_size <= 0.0 or header.world_size > max_world_size_i32_f32) {
        return error.InvalidHeaderValue;
    }
    if (replay.dt.len != replay.tickCount()) {
        return error.InvalidHeaderValue;
    }

    const prelude = replay.prelude;
    const postlude = replay.postlude;
    const events = replay.events;
    var context = session_builders.buildReplaySession(
        game_mode,
        header,
        events,
        .{
            .strict_events = options.strict_events,
            .quest_spawn_entries = options.quest_spawn_entries,
            .quest_start_weapon_id = options.quest_start_weapon_id,
        },
    ) catch |err| switch (err) {
        error.InvalidPlayerCount => return error.UnsupportedPlayerCount,
        error.InvalidWorldSize => return error.InvalidHeaderValue,
        error.InvalidTickRate => return error.InvalidHeaderValue,
        error.UnsupportedGameMode => return error.UnsupportedGameMode,
        error.InvalidQuestSpawnTable => return error.InvalidQuestSpawnTable,
    };

    const ticks_to_simulate: usize = if (options.max_ticks) |max_ticks|
        @min(max_ticks, replay.tickCount())
    else
        replay.tickCount();
    const full_replay_simulated = ticks_to_simulate == replay.tickCount();

    var prelude_index: usize = 0;
    var postlude_index: usize = 0;
    for (0..ticks_to_simulate) |tick_index| {
        if (prelude_index < prelude.len and prelude[prelude_index].tickIndex() < tick_index) {
            return error.UnsupportedEventOrdering;
        }
        if (postlude_index < postlude.len and postlude[postlude_index].tickIndex() < tick_index) {
            return error.UnsupportedEventOrdering;
        }
        if (context.event_index < events.len and events[context.event_index].tickIndex() < tick_index) {
            return error.UnsupportedEventOrdering;
        }

        const dt_tick = replay.dt[tick_index];
        const tick_prelude_start = prelude_index;
        while (prelude_index < prelude.len and prelude[prelude_index].tickIndex() == tick_index) : (prelude_index += 1) {}
        try applyReplayOperations(&context, prelude[tick_prelude_start..prelude_index], dt_tick);
        const tick_postlude_start = postlude_index;
        while (postlude_index < postlude.len and postlude[postlude_index].tickIndex() == tick_index) : (postlude_index += 1) {}
        const tick_event_start = context.event_index;
        var tick_event_end = tick_event_start;
        while (tick_event_end < events.len and events[tick_event_end].tickIndex() == tick_index) : (tick_event_end += 1) {}
        var tick_inputs_storage: [state_mod.max_players]player_runtime.GameInput = undefined;
        const replay_tick_inputs = replay.inputs[tick_index];
        const tick_input_len = @min(replay_tick_inputs.len, tick_inputs_storage.len);
        for (replay_tick_inputs[0..tick_input_len], 0..) |input, idx| {
            tick_inputs_storage[idx] = mapReplayInputToGameInput(input);
        }

        var step_options: replay_step.StepOptions = .{};
        var trace_collector: TickTraceCollector = undefined;
        var trace_collector_active = false;
        var rng_trace_active = false;
        defer if (trace_collector_active) trace_collector.deinit();
        defer if (rng_trace_active) context.state.rng.setTraceSink(null, null, false);
        if (trace_out != null and (options.trace_rng or options.trace_timing)) {
            trace_collector = TickTraceCollector.init(trace_allocator);
            trace_collector_active = true;

            if (options.trace_rng) {
                context.state.rng.setTraceSink(&trace_collector, TickTraceCollector.onRngDraw, true);
                rng_trace_active = true;
            }

            if (options.trace_timing) {
                step_options.timing_trace_ctx = &trace_collector;
                step_options.timing_trace_sink = TickTraceCollector.onTimingSample;
            }
        }

        const step_result = try replay_step.stepTick(
            &context,
            tick_index,
            tick_inputs_storage[0..tick_input_len],
            events[tick_event_start..tick_event_end],
            dt_tick,
            step_options,
        );
        try applyReplayPostlude(&context, postlude[tick_postlude_start..postlude_index], dt_tick);
        if (rng_trace_active and context.state.rng.consumeMissingTraceCaller()) {
            return error.MissingRngCallerTag;
        }

        if (trace_out) |trace| {
            const trace_elapsed_ms = switch (game_mode) {
                .quests => context.quest_spawn_timeline_ms,
                .rush => @as(f32, @floatFromInt(context.elapsed_ms_sim_rush)),
                else => context.elapsed_ms_sim,
            };
            const players = context.playersConst();
            const player0 = players[0];
            const rng_rows = if (trace_collector_active)
                try trace_collector.takeRngRows()
            else
                &.{};
            errdefer if (rng_rows.len > 0) trace_allocator.free(rng_rows);
            const timing_samples = if (trace_collector_active)
                try trace_collector.takeTimingSamples()
            else
                &.{};
            errdefer if (timing_samples.len > 0) trace_allocator.free(timing_samples);
            var row = try buildTickTrace(
                trace_allocator,
                tick_index,
                narrowF32(trace_elapsed_ms),
                &context.state,
                player0,
                players,
                &context.creatures,
                &context.projectiles,
                &context.secondary_projectiles,
                &context.bonuses,
                step_result.rng_after_perk_effects,
                step_result.rng_after_creatures,
                step_result.rng_after_projectiles,
                step_result.rng_after_secondary_projectiles,
                step_result.rng_after_particles,
                step_result.rng_after_player_update,
                step_result.rng_after_stage_spawns,
                step_result.rng_after_wave_spawns,
                step_result.rng_after_spawns,
                step_result.rng_after_bonus_update,
                rng_rows,
                timing_samples,
            );
            row.event_hit_count = step_result.projectile_tick_stats.hit_count;
            row.event_pickup_count = @intCast(step_result.bonus_pickups.len);
            row.sfx_events = step_result.sfx_events;
            try trace.append(trace_allocator, row);
        }
    }

    if (full_replay_simulated) {
        if (prelude_index != prelude.len) return error.UnsupportedEventOrdering;
        if (postlude_index != postlude.len) return error.UnsupportedEventOrdering;
        const terminal_tick = replay.tickCount();
        if (context.event_index < events.len and events[context.event_index].tickIndex() < terminal_tick) {
            return error.UnsupportedEventOrdering;
        }
        var terminal_menu_open_seen = false;
        while (context.event_index < events.len and events[context.event_index].tickIndex() == terminal_tick) : (context.event_index += 1) {
            const dt_tick = if (replay.dt.len > 0)
                replay.dt[replay.dt.len - 1]
            else
                context.dt_nominal;
            const outcome = try replay_events.applyReplayEvent(
                events[context.event_index],
                &context.state,
                context.players(),
                &context.creatures,
                narrowF32(dt_tick),
                &context.quest_spawn_timeline_ms,
                &context.quest_no_creatures_timer_ms,
                &context.quest_completion_transition_ms,
                .{
                    .game_mode = context.game_mode,
                    .player_count = context.player_count,
                    .quest_unlock_index = context.quest_unlock_index,
                    .strict_events = context.strict_events,
                    .menu_open_seen_this_tick = terminal_menu_open_seen,
                },
            );
            terminal_menu_open_seen = terminal_menu_open_seen or outcome.menu_open_seen_this_tick;
            context.perk_menu_open_count += outcome.perk_menu_open_count_delta;
            context.perk_pick_count += outcome.perk_pick_count_delta;
            if (outcome.signal == .request_capture_state_reset) {
                context.pending_capture_state_reset = true;
            }
        }
        if (context.event_index != events.len) return error.UnsupportedEventOrdering;
    }

    const tick_rate_f32: f32 = @floatFromInt(header.tick_rate);
    const ticks_f32: f32 = @floatFromInt(ticks_to_simulate);
    const elapsed_ms_nominal: i64 = @intFromFloat(@round(ticks_f32 * (1000.0 / tick_rate_f32)));
    const elapsed_ms_sim_i64: i64 = switch (game_mode) {
        .quests => @intFromFloat(context.quest_spawn_timeline_ms),
        .rush => context.elapsed_ms_sim_rush,
        else => @intFromFloat(context.elapsed_ms_sim),
    };

    const players = context.playersConst();
    const player0 = players[0];
    const shots: state_mod.PlayerShots = if (game_mode == .typo)
        .{
            .fired = context.state.typo.typing.submit_count,
            .hit = context.state.typo.typing.match_count,
        }
    else
        survival_progression.player0Shots(context.state);
    const most_used_weapon_id = survival_progression.mostUsedWeaponIdForPlayer(
        context.state,
        0,
        player0.weapon.weapon_id,
    );

    return .{
        .ticks = ticks_to_simulate,
        .elapsed_ms_nominal = elapsed_ms_nominal,
        .elapsed_ms_sim = elapsed_ms_sim_i64,
        .perk_menu_open_count = context.perk_menu_open_count,
        .perk_pick_count = context.perk_pick_count,
        .fire_pressed_count = context.fire_pressed_count,
        .reload_pressed_count = context.reload_pressed_count,
        .stage_spawn_count = context.stage_spawn_count,
        .wave_spawn_count = context.wave_spawn_count,
        .wave_spawn_rng_state = context.state.rng.state,
        .player_level = player0.level,
        .player_experience = player0.experience,
        .player_weapon_id = @intFromEnum(player0.weapon.weapon_id),
        .most_used_weapon_id = @intFromEnum(most_used_weapon_id),
        .shots_fired = shots.fired,
        .shots_hit = shots.hit,
        .creature_kill_count = context.creatures.kill_count,
        .creature_active_count = context.creatures.activeCount(),
        .perk_pending_count = context.state.perk_selection.pending_count,
        .survival_reward_handout_enabled = context.state.survival_reward_handout_enabled,
        .survival_reward_fire_seen = context.state.survival_reward_fire_seen,
        .survival_reward_damage_seen = context.state.survival_reward_damage_seen,
        .spawn_stage = context.spawn_stage,
        .spawn_cooldown_ms = context.spawn_cooldown,
        .quest_completion_transition_ms = @floatCast(context.quest_completion_transition_ms),
        .quest_completed = context.quest_completed,
        .quest_play_hit_sfx = context.quest_play_hit_sfx,
        .quest_play_completion_music = context.quest_play_completion_music,
    };
}

fn buildTickTrace(
    allocator: std.mem.Allocator,
    tick_index: usize,
    elapsed_ms_sim: f32,
    state: *const state_mod.GameplayState,
    player: state_mod.PlayerState,
    players: []const state_mod.PlayerState,
    creatures: *const creatures_mod.CreaturePool,
    projectiles: *const projectiles_mod.ProjectilePool,
    secondary_projectiles: *const secondary_projectiles_mod.SecondaryProjectilePool,
    bonuses: *const bonuses_mod.BonusPool,
    rng_after_perk_effects: u32,
    rng_after_creatures: u32,
    rng_after_projectiles: u32,
    rng_after_secondary_projectiles: u32,
    rng_after_particles: u32,
    rng_after_player_update: u32,
    rng_after_stage_spawns: u32,
    rng_after_wave_spawns: u32,
    rng_after_spawns: u32,
    rng_after_bonus_update: u32,
    rng_rows: []const replay_diagnostic_trace.ReplayTickRngDraw,
    timing_samples: []const replay_diagnostic_trace.ReplayTickTimingSample,
) !ReplayTickTrace {
    return replay_diagnostic_trace.buildReplayTickTraceWithEntities(
        allocator,
        tick_index,
        elapsed_ms_sim,
        state,
        player,
        players,
        creatures,
        projectiles,
        secondary_projectiles,
        bonuses,
        rng_after_perk_effects,
        rng_after_creatures,
        rng_after_projectiles,
        rng_after_secondary_projectiles,
        rng_after_particles,
        rng_after_player_update,
        rng_after_stage_spawns,
        rng_after_wave_spawns,
        rng_after_spawns,
        rng_after_bonus_update,
        rng_rows,
        timing_samples,
    );
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

pub fn mapReplayInputToGameInput(input: replay_codec.ReplayPlayerInput) player_runtime.GameInput {
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
            .move_mode = flags.move_mode,
            .aim_scheme = flags.aim_scheme,
            .move_forward_pressed = flags.move_forward_pressed,
            .move_backward_pressed = flags.move_backward_pressed,
            .turn_left_pressed = flags.turn_left_pressed,
            .turn_right_pressed = flags.turn_right_pressed,
        },
    };
}

test "replay input adapter preserves packed flag decode semantics" {
    const packed_flags: u32 =
        replay_codec.fire_down_flag |
        replay_codec.reload_pressed_flag |
        replay_codec.reload_down_flag |
        replay_codec.move_keys_present_flag |
        replay_codec.move_forward_flag |
        replay_codec.turn_right_flag |
        replay_codec.move_mode_present_flag |
        (@as(u32, 5) << replay_codec.move_mode_shift) |
        replay_codec.aim_scheme_present_flag |
        (replay_codec.aim_scheme_mask << replay_codec.aim_scheme_shift);

    const replay_input: replay_codec.ReplayPlayerInput = .{
        .move_x = 1.5,
        .move_y = -0.25,
        .aim_x = 777.0,
        .aim_y = 333.0,
        .flags = packed_flags,
    };
    const mapped = mapReplayInputToGameInput(replay_input);
    const expected_flags = replay_codec.unpackInputFlags(packed_flags);

    try std.testing.expectApproxEqAbs(replay_input.move_x, mapped.move_x, 1e-9);
    try std.testing.expectApproxEqAbs(replay_input.move_y, mapped.move_y, 1e-9);
    try std.testing.expectApproxEqAbs(replay_input.aim_x, mapped.aim_x, 1e-9);
    try std.testing.expectApproxEqAbs(replay_input.aim_y, mapped.aim_y, 1e-9);
    try std.testing.expectEqual(expected_flags.fire_down, mapped.flags.fire_down);
    try std.testing.expectEqual(expected_flags.fire_pressed, mapped.flags.fire_pressed);
    try std.testing.expectEqual(expected_flags.reload_pressed, mapped.flags.reload_pressed);
    try std.testing.expectEqual(expected_flags.reload_down, mapped.flags.reload_down);
    try std.testing.expectEqual(expected_flags.move_mode, mapped.flags.move_mode);
    try std.testing.expectEqual(expected_flags.aim_scheme, mapped.flags.aim_scheme);
    try std.testing.expectEqual(expected_flags.move_forward_pressed, mapped.flags.move_forward_pressed);
    try std.testing.expectEqual(expected_flags.move_backward_pressed, mapped.flags.move_backward_pressed);
    try std.testing.expectEqual(expected_flags.turn_left_pressed, mapped.flags.turn_left_pressed);
    try std.testing.expectEqual(expected_flags.turn_right_pressed, mapped.flags.turn_right_pressed);
}

fn quantizeQ6(value: f32) i32 {
    const scaled = @round(value * 1_000_000.0);
    if (scaled <= @as(f32, @floatFromInt(std.math.minInt(i32)))) return std.math.minInt(i32);
    if (scaled >= @as(f32, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(scaled);
}

fn bonusTimerMs(seconds: f32) i32 {
    if (!(seconds > 0.0)) return 0;
    const ms = @round(seconds * 1000.0);
    if (ms <= 0.0) return 0;
    if (ms >= @as(f32, @floatFromInt(std.math.maxInt(i32)))) return std.math.maxInt(i32);
    return @intFromFloat(ms);
}

fn hashMix(seed: u64, value: u64) u64 {
    var h = seed ^ value;
    h *%= 1099511628211;
    return h;
}

fn applyCaptureCreatureSpawnEvent(
    state: *state_mod.GameplayState,
    creatures: *creatures_mod.CreaturePool,
    event: replay_codec.CaptureCreatureSpawnEvent,
) ReplayRunnerError!void {
    var spawned_indices = [_]bool{false} ** creatures_mod.max_creatures;
    var active_before = [_]bool{false} ** creatures_mod.max_creatures;
    for (creatures.entries, 0..) |entry, idx| {
        active_before[idx] = entry.active;
    }

    for (event.spawns[0..event.spawn_count]) |spawn_row| {
        creatures.spawnTemplateCall(
            .{
                .template_id = spawn_row.template_id,
                .pos = .{
                    .x = spawn_row.pos_x,
                    .y = spawn_row.pos_y,
                },
                .heading = spawn_row.heading,
            },
            &state.rng,
        ) catch |err| switch (err) {
            error.InvalidSpawnTemplate => return error.InvalidSpawnTemplate,
        };
        for (creatures.entries, 0..) |entry, idx| {
            if (!active_before[idx] and entry.active) {
                spawned_indices[idx] = true;
            }
            active_before[idx] = entry.active;
        }
    }

    for (event.added_head[0..event.added_head_count]) |row| {
        if (row.index < 0 or row.index >= creatures.entries.len) continue;
        const idx: usize = @intCast(row.index);
        const entry = &creatures.entries[idx];
        if (!entry.active) continue;

        const ai_mode = if (row.has_ai_mode) try parseCaptureCreatureAiMode(row.ai_mode) else null;

        const flags_i32 = if (row.has_flags) row.flags else @as(i32, @intCast(entry.flags));
        const needs_ai7_rollover_rng_backfill = spawned_indices[idx] and
            row.has_link_index and
            isAi7LinkTimerRolloverValue(row.link_index) and
            (flags_i32 & @as(i32, @intCast(spawn_mod.CreatureFlags.ai7_link_timer))) != 0;
        if (needs_ai7_rollover_rng_backfill) {
            _ = state.rng.randTagged(rng_callers.creature_update_all_ai7_link_timer_reset);
        }

        if (row.has_pos) {
            entry.pos = .{
                .x = row.pos_x,
                .y = row.pos_y,
            };
        }
        if (row.has_heading) entry.heading = row.heading;
        if (row.has_target_heading) entry.target_heading = row.target_heading;
        if (ai_mode) |mode| entry.ai_mode = mode;
        if (row.has_link_index) entry.link_index = row.link_index;
        if (row.has_hp) entry.hp = row.hp;
        if (row.has_lifecycle_stage) entry.lifecycle_stage = row.lifecycle_stage;
        if (row.has_orbit_angle) entry.orbit_angle = row.orbit_angle;
        if (row.has_orbit_radius) entry.orbit_radius = row.orbit_radius;
        if (row.has_flags) entry.flags = @intCast(@max(0, flags_i32));
        if (row.has_type_id) entry.type_id = row.type_id;
    }
}

test "survival run accepts preserve bugs replay headers" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .game_version = "0.6.9",
        .preserve_bugs = true,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@as(i64, 17), result.elapsed_ms_nominal);
    try std.testing.expectEqual(@as(i64, 16), result.elapsed_ms_sim);
}

test "survival run tracks event and input counters" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{
            replay_codec.fire_pressed_flag,
            replay_codec.reload_pressed_flag,
        },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(usize, 2), result.ticks);
    try std.testing.expectEqual(@as(i64, 33), result.elapsed_ms_nominal);
    try std.testing.expectEqual(@as(i64, 32), result.elapsed_ms_sim);
    try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
    try std.testing.expectEqual(@as(usize, 0), result.perk_pick_count);
    try std.testing.expectEqual(@as(usize, 1), result.fire_pressed_count);
    try std.testing.expectEqual(@as(usize, 1), result.reload_pressed_count);
    try std.testing.expectEqual(@as(usize, 0), result.stage_spawn_count);
    try std.testing.expectEqual(@as(usize, 1), result.wave_spawn_count);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.pistol), result.player_weapon_id);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.pistol), result.most_used_weapon_id);
    try std.testing.expectEqual(@as(i32, 0), result.shots_fired);
    try std.testing.expectEqual(@as(i32, 0), result.shots_hit);
    try std.testing.expectEqual(@as(i32, 1), result.player_level);
    try std.testing.expectEqual(@as(i32, 0), result.perk_pending_count);
    try std.testing.expect(!result.survival_reward_fire_seen);
}

test "quest run advances elapsed time with integer simulation milliseconds" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .tick_rate = 60,
        .quest_level = "1.1",
        .inputs = &.{ 0, 0, 0 },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(usize, 3), result.ticks);
    try std.testing.expectEqual(@as(i64, 50), result.elapsed_ms_nominal);
    try std.testing.expectEqual(@as(i64, 48), result.elapsed_ms_sim);
}

test "survival run rejects unsupported event player index" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag},
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 1 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.UnsupportedEventPlayerIndex,
        runReplay(replay),
    );
}

test "survival run accepts multiplayer event player indices" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplayMulti(allocator, .{
        .tick_rate = 60,
        .player_count = 2,
        .inputs = &.{
            &.{ replay_codec.fire_pressed_flag, replay_codec.reload_pressed_flag },
        },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 1 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
    try std.testing.expectEqual(@as(usize, 1), result.fire_pressed_count);
    try std.testing.expectEqual(@as(usize, 1), result.reload_pressed_count);
}

test "survival run rejects multiplayer event player index out of bounds" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplayMulti(allocator, .{
        .tick_rate = 60,
        .player_count = 2,
        .inputs = &.{
            &.{ 0, 0 },
        },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 2 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.UnsupportedEventPlayerIndex,
        runReplay(replay),
    );
}

test "survival run treats stale perk pick as strict no-op" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag},
        .events = &.{
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@as(usize, 0), result.perk_pick_count);
    try std.testing.expectEqual(@as(i32, 0), result.perk_pending_count);
}

test "survival run can skip invalid perk pick event in non-strict mode" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag},
        .events = &.{
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayWithOptions(replay, .{
        .strict_events = false,
    });
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@as(usize, 0), result.perk_pick_count);
    try std.testing.expectEqual(@as(i32, 0), result.perk_pending_count);
}

test "survival run treats same-tick stale perk pick after menu open as strict no-op" {
    const allocator = std.testing.allocator;

    const menu_only = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 0 } },
        },
    });
    defer menu_only.deinit(allocator);

    const with_stale_pick = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 0 } },
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 1 } },
        },
    });
    defer with_stale_pick.deinit(allocator);

    const menu_result = try runReplay(menu_only);
    const stale_result = try runReplay(with_stale_pick);

    try std.testing.expectEqual(menu_result.wave_spawn_rng_state, stale_result.wave_spawn_rng_state);
    try std.testing.expectEqual(menu_result.perk_pending_count, stale_result.perk_pending_count);
    try std.testing.expectEqual(@as(usize, 0), stale_result.perk_pick_count);
}

test "survival run defers menu-open processing in original capture replays" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            menu_before_pick: bool,
        ) !ReplayRunResult {
            var bootstrap: replay_codec.CaptureBootstrapEvent = .{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.perk_pending_count = 1;
            bootstrap.perk_choices_dirty = true;

            const menu_event: replay_codec.ReplayEvent = .{
                .perk_menu_open = .{
                    .tick_index = 0,
                    .player_index = 0,
                },
            };
            const pick_event: replay_codec.ReplayEvent = .{
                .perk_pick = .{
                    .tick_index = 0,
                    .player_index = 0,
                    .choice_index = 0,
                },
            };

            const replay = try buildTestReplay(allocator_inner, .{
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{0},
                .events = if (menu_before_pick)
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                        menu_event,
                        pick_event,
                    }
                else
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                        pick_event,
                        menu_event,
                    },
            });
            defer replay.deinit(allocator_inner);
            return runReplay(replay);
        }
    }.runCase;

    const menu_first = try run(allocator, true);
    const pick_first = try run(allocator, false);

    try std.testing.expectEqual(menu_first.wave_spawn_rng_state, pick_first.wave_spawn_rng_state);
    try std.testing.expectEqual(menu_first.perk_pick_count, pick_first.perk_pick_count);
    try std.testing.expectEqual(menu_first.perk_menu_open_count, pick_first.perk_menu_open_count);
    try std.testing.expectEqual(menu_first.perk_pending_count, pick_first.perk_pending_count);
}

test "survival run tracks weapon runtime counters" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{
            replay_codec.fire_down_flag,
            replay_codec.fire_down_flag,
        },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(i32, 1), result.shots_fired);
    try std.testing.expectEqual(@as(i32, 0), result.shots_hit);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.pistol), result.most_used_weapon_id);
}

test "typo run reports submit count as shots fired" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.typo),
        .tick_rate = 60,
        .inputs = &.{ 0, 0, 0, 0, 0, 0, 0 },
        .events = &.{
            .{ .typo_char = .{ .tick_index = 0, .player_index = 0, .ch = 'r' } },
            .{ .typo_char = .{ .tick_index = 1, .player_index = 0, .ch = 'e' } },
            .{ .typo_char = .{ .tick_index = 2, .player_index = 0, .ch = 'l' } },
            .{ .typo_char = .{ .tick_index = 3, .player_index = 0, .ch = 'o' } },
            .{ .typo_char = .{ .tick_index = 4, .player_index = 0, .ch = 'a' } },
            .{ .typo_char = .{ .tick_index = 5, .player_index = 0, .ch = 'd' } },
            .{ .typo_submit = .{ .tick_index = 6, .player_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(i32, 1), result.shots_fired);
    try std.testing.expectEqual(@as(i32, 0), result.shots_hit);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.shotgun), result.most_used_weapon_id);
}

test "typo run spawns creatures after creature update phase" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.typo),
        .seed = 0xBEEF,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .typo_char = .{ .tick_index = 0, .player_index = 0, .ch = 'r' } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expect(result.creature_active_count > 0);
    try std.testing.expectEqual(@as(u32, 4267440421), result.wave_spawn_rng_state);
}

test "survival run consumes replay dt rows for elapsed_ms" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    replay.dt[0] = 0.5;
    const result = try runReplayWithOptions(replay, .{});
    try std.testing.expectEqual(@as(i64, 500), result.elapsed_ms_sim);
}

test "survival run ordered rng-burn preludes shift rng deterministically" {
    const allocator = std.testing.allocator;

    const baseline_replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{},
    });
    defer baseline_replay.deinit(allocator);
    const burns = [_]replay_codec.ReplayPreludeOp{
        .{ .game_frame_rng_advance = .{ .tick_index = 0, .frames = 1 } },
        .{ .game_frame_rng_advance = .{ .tick_index = 1, .frames = 1 } },
        .{ .game_frame_rng_advance = .{ .tick_index = 2, .frames = 1 } },
    };
    const shifted_replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{ 0, 0, 0 },
        .prelude = &burns,
        .events = &.{},
    });
    defer shifted_replay.deinit(allocator);

    const baseline = try runReplay(baseline_replay);
    const shifted = try runReplay(shifted_replay);
    const shifted_again = try runReplay(shifted_replay);

    try std.testing.expectEqual(@as(usize, 3), baseline.ticks);
    try std.testing.expectEqual(shifted.wave_spawn_rng_state, shifted_again.wave_spawn_rng_state);
    try std.testing.expect(shifted.wave_spawn_rng_state != baseline.wave_spawn_rng_state);
}

test "postlude menu RNG follows simulation in the canonical tick trace" {
    const allocator = std.testing.allocator;

    const baseline_replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{0},
        .events = &.{},
    });
    defer baseline_replay.deinit(allocator);
    const postlude_ops = [_]replay_codec.ReplayPostludeOp{
        .{ .tick_index = 0, .player_index = 0 },
    };
    const postlude_replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{0},
        .postlude = &postlude_ops,
        .events = &.{},
    });
    defer postlude_replay.deinit(allocator);

    var baseline_trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer {
        deinitReplayTickTraceRows(allocator, baseline_trace.items);
        baseline_trace.deinit(allocator);
    }
    _ = try runReplayWithTrace(allocator, baseline_replay, &baseline_trace, .{});

    var postlude_trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer {
        deinitReplayTickTraceRows(allocator, postlude_trace.items);
        postlude_trace.deinit(allocator);
    }
    const result = try runReplayWithTrace(allocator, postlude_replay, &postlude_trace, .{});

    try std.testing.expectEqual(@as(usize, 1), baseline_trace.items.len);
    try std.testing.expectEqual(@as(usize, 1), postlude_trace.items.len);
    const baseline_rng = baseline_trace.items[0].rng_rows;
    const postlude_rng = postlude_trace.items[0].rng_rows;
    try std.testing.expect(postlude_rng.len > baseline_rng.len);
    for (baseline_rng, postlude_rng[0..baseline_rng.len]) |expected, actual| {
        try std.testing.expectEqual(expected.state_before_u32, actual.state_before_u32);
        try std.testing.expectEqual(expected.state_after_u32, actual.state_after_u32);
        try std.testing.expectEqual(expected.value_15, actual.value_15);
        try std.testing.expectEqual(expected.caller, actual.caller);
    }
    try std.testing.expect(!postlude_trace.items[0].gameplay_state.perk_selection.choices_dirty);
    try std.testing.expectEqual(@as(usize, replay_codec.perk_choice_slot_count), postlude_trace.items[0].gameplay_state.perk_selection.choice_count);
    try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
}

test "survival run applies capture bootstrap payload state" {
    const allocator = std.testing.allocator;

    var bootstrap: replay_codec.CaptureBootstrapEvent = .{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 9,
        .pos_x = 600.0,
        .pos_y = 600.0,
        .health = 75.0,
        .ammo = 4.0,
        .experience = 321,
        .level = 5,
    };
    bootstrap.perk_pending_count = 2;
    bootstrap.double_experience_ms = 1500;

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@as(i32, 321), result.player_experience);
    try std.testing.expectEqual(@as(i32, 5), result.player_level);
    try std.testing.expectEqual(@as(i32, 2), result.perk_pending_count);
}

test "survival run applies terminal tick events" {
    const allocator = std.testing.allocator;

    const with_terminal_event = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 3, .player_index = 0 } },
        },
    });
    defer with_terminal_event.deinit(allocator);

    const without_terminal_event = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{},
    });
    defer without_terminal_event.deinit(allocator);

    const with_result = try runReplay(with_terminal_event);
    const without_result = try runReplay(without_terminal_event);
    try std.testing.expect(with_result.wave_spawn_rng_state != without_result.wave_spawn_rng_state);
}

test "survival run max ticks skips terminal tick events beyond clamp" {
    const allocator = std.testing.allocator;

    const with_terminal_event = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 3, .player_index = 0 } },
        },
    });
    defer with_terminal_event.deinit(allocator);

    const without_terminal_event = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{},
    });
    defer without_terminal_event.deinit(allocator);

    const with_result = try runReplayWithOptions(with_terminal_event, .{
        .max_ticks = 2,
    });
    const without_result = try runReplayWithOptions(without_terminal_event, .{
        .max_ticks = 2,
    });
    try std.testing.expectEqual(@as(usize, 2), with_result.ticks);
    try std.testing.expectEqual(without_result.wave_spawn_rng_state, with_result.wave_spawn_rng_state);
}

test "survival run bootstrap player shot cooldown blocks first-tick fire" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            include_shot_cooldown: bool,
        ) !struct { shots_fired: i32, ammo_bits: u32, fire_seen: bool } {
            var bootstrap: replay_codec.CaptureBootstrapEvent = .{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.players[0] = .{
                .weapon_id = 1,
                .ammo = 12.0,
                .reload_active = false,
                .reload_timer = 0.0,
                .reload_timer_max = 1.0,
                .spread_heat = 0.0,
            };
            if (include_shot_cooldown) {
                bootstrap.players[0].shot_cooldown = 0.5;
            }

            var replay = try buildTestReplay(allocator_inner, .{
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{replay_codec.fire_down_flag},
                .events = &.{
                    .{ .capture_bootstrap = bootstrap },
                },
            });
            defer replay.deinit(allocator_inner);
            replay.inputs[0][0].aim_x = 700.0;
            replay.inputs[0][0].aim_y = 512.0;

            var trace: std.ArrayList(ReplayTickTrace) = .empty;
            defer trace.deinit(allocator_inner);
            defer deinitReplayTickTraceRows(allocator_inner, trace.items);
            const result = try runReplayWithTrace(
                allocator_inner,
                replay,
                &trace,
                .{},
            );
            try std.testing.expectEqual(@as(usize, 1), trace.items.len);
            return .{
                .shots_fired = result.shots_fired,
                .ammo_bits = f32Bits(trace.items[0].player_state.weapon.ammo),
                .fire_seen = result.survival_reward_fire_seen,
            };
        }
    }.runCase;

    const without_cooldown = try run(allocator, false);
    const with_cooldown = try run(allocator, true);
    try std.testing.expect(without_cooldown.shots_fired > with_cooldown.shots_fired);
    try std.testing.expectEqual(@as(i32, 0), with_cooldown.shots_fired);
    try std.testing.expect(without_cooldown.ammo_bits < with_cooldown.ammo_bits);
    try std.testing.expectEqual(f32Bits(12.0), with_cooldown.ammo_bits);
    try std.testing.expect(without_cooldown.fire_seen);
    try std.testing.expect(!with_cooldown.fire_seen);
}

test "survival run bootstrap perk counts enable alternate weapon swap" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            include_perk_counts: bool,
        ) !i32 {
            var bootstrap: replay_codec.CaptureBootstrapEvent = .{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.players[0] = .{
                .weapon_id = 11,
                .ammo = 0.0,
                .reload_active = false,
                .reload_timer = 0.0,
                .reload_timer_max = 1.0,
                .alt_weapon_id = 1,
                .alt_clip_size = 12,
                .alt_ammo = 12.0,
                .alt_reload_active = false,
                .alt_reload_timer = 0.0,
                .alt_reload_timer_max = 1.2,
                .alt_shot_cooldown = 0.0,
            };
            if (include_perk_counts) {
                bootstrap.player_perk_counts[0].pair_count = 1;
                bootstrap.player_perk_counts[0].pairs[0] = .{
                    .perk_id = @intFromEnum(PerkId.alternate_weapon),
                    .count = 1,
                };
            }

            const replay = try buildTestReplay(allocator_inner, .{
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{replay_codec.reload_pressed_flag},
                .events = &.{
                    .{ .capture_bootstrap = bootstrap },
                },
            });
            defer replay.deinit(allocator_inner);

            const result = try runReplay(replay);
            return result.player_weapon_id;
        }
    }.runCase;

    const without_counts = try run(allocator, false);
    const with_counts = try run(allocator, true);
    try std.testing.expectEqual(@as(i32, 11), without_counts);
    try std.testing.expectEqual(@as(i32, 1), with_counts);
}

test "survival run bootstrap rejects invalid perk id in perk counts" {
    const allocator = std.testing.allocator;

    var bootstrap: replay_codec.CaptureBootstrapEvent = .{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.player_perk_counts[0].pair_count = 1;
    bootstrap.player_perk_counts[0].pairs[0] = .{
        .perk_id = 999,
        .count = 1,
    };

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.InvalidCaptureEnumValue,
        runReplay(replay),
    );
}

test "survival run bootstrap rejects invalid perk id in choices" {
    const allocator = std.testing.allocator;

    var bootstrap: replay_codec.CaptureBootstrapEvent = .{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.perk_choice_count = 1;
    bootstrap.perk_choices[0] = 999;

    const replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .seed = 0x1234,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(
        error.InvalidCaptureEnumValue,
        runReplay(replay),
    );
}

test "capture perk pending event sets pending without shifting rng in survival and quest modes" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            game_mode_id: GameModeId,
            apply_pending_event: bool,
        ) !struct { rng_state: u32, pending: i32 } {
            var bootstrap: replay_codec.CaptureBootstrapEvent = .{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.perk_pending_count = 2;
            const pending_event: replay_codec.ReplayEvent = .{
                .capture_perk_pending = .{
                    .tick_index = 0,
                    .perk_pending = 0,
                },
            };
            const replay = try buildTestReplay(allocator_inner, .{
                .game_mode_id = @intFromEnum(game_mode_id),
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{0},
                .events = if (apply_pending_event)
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                        pending_event,
                    }
                else
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                    },
            });
            defer replay.deinit(allocator_inner);

            const result = try runReplayWithOptions(replay, .{
                .quest_spawn_entries = if (game_mode_id == .quests) &.{} else null,
            });
            return .{
                .rng_state = result.wave_spawn_rng_state,
                .pending = result.perk_pending_count,
            };
        }
    }.runCase;

    for ([_]GameModeId{ .survival, .quests }) |mode| {
        const baseline = try run(allocator, mode, false);
        const with_pending = try run(allocator, mode, true);
        try std.testing.expectEqual(baseline.rng_state, with_pending.rng_state);
        try std.testing.expectEqual(@as(i32, 0), with_pending.pending);
    }
}

test "capture perk apply outside-before keeps rng anchored and consumes pending-after" {
    const allocator = std.testing.allocator;

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            include_perk_apply: bool,
        ) !ReplayRunResult {
            var bootstrap: replay_codec.CaptureBootstrapEvent = .{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.perk_pending_count = 1;
            bootstrap.players[0] = .{
                .weapon_id = @intFromEnum(game_ids.WeaponId.assault_rifle),
                .ammo = 6.0,
            };

            const apply_event: replay_codec.ReplayEvent = .{
                .capture_perk_apply = .{
                    .tick_index = 0,
                    .perk_id = @intFromEnum(PerkId.random_weapon),
                    .outside_before = true,
                    .pending_before = 1,
                    .pending_after = 4,
                },
            };

            const replay = try buildTestReplay(allocator_inner, .{
                .game_mode_id = @intFromEnum(GameModeId.survival),
                .tick_rate = 60,
                .seed = 0x1234,
                .inputs = &.{0},
                .events = if (include_perk_apply)
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                        apply_event,
                    }
                else
                    &.{
                        .{ .capture_bootstrap = bootstrap },
                    },
            });
            defer replay.deinit(allocator_inner);
            return runReplay(replay);
        }
    }.runCase;

    const baseline = try run(allocator, false);
    const applied = try run(allocator, true);

    try std.testing.expectEqual(baseline.wave_spawn_rng_state, applied.wave_spawn_rng_state);
    try std.testing.expectEqual(@as(i32, 3), applied.perk_pending_count);
}

test "rush run is deterministic and enforces assault rifle loadout" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result0 = try runReplay(replay);
    const result1 = try runReplay(replay);
    try std.testing.expectEqual(result0.wave_spawn_rng_state, result1.wave_spawn_rng_state);
    try std.testing.expectEqual(@as(usize, 10), result0.ticks);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result0.player_weapon_id);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result0.most_used_weapon_id);
}

test "rush run consumes replay dt rows for elapsed_ms" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    replay.dt[0] = 0.5;
    const result = try runReplayWithOptions(replay, .{});
    try std.testing.expectEqual(@as(i64, 500), result.elapsed_ms_sim);
}

test "rush run spawn cadence uses raw frame dt, not sim dt" {
    const allocator = std.testing.allocator;

    const inputs = [_]u32{0} ** 15;
    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = inputs[0..],
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    // Native rush cooldown arithmetic uses integer milliseconds; at 60 Hz nominal
    // dt this yields a second batch on tick 15 (0-indexed tick 14), so 4 total
    // creatures in 15 ticks.
    try std.testing.expectEqual(@as(usize, 4), result.wave_spawn_count);
}

test "rush run ordered rng-burn preludes shift rng deterministically" {
    const allocator = std.testing.allocator;

    const baseline_replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{ 0, 0, 0 },
        .events = &.{},
    });
    defer baseline_replay.deinit(allocator);
    const burns = [_]replay_codec.ReplayPreludeOp{
        .{ .game_frame_rng_advance = .{ .tick_index = 0, .frames = 1 } },
        .{ .game_frame_rng_advance = .{ .tick_index = 1, .frames = 1 } },
        .{ .game_frame_rng_advance = .{ .tick_index = 2, .frames = 1 } },
    };
    const shifted_replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{ 0, 0, 0 },
        .prelude = &burns,
        .events = &.{},
    });
    defer shifted_replay.deinit(allocator);

    const baseline = try runReplay(baseline_replay);
    const shifted = try runReplay(shifted_replay);
    const shifted_again = try runReplay(shifted_replay);

    try std.testing.expectEqual(@as(usize, 3), baseline.ticks);
    try std.testing.expectEqual(shifted.wave_spawn_rng_state, shifted_again.wave_spawn_rng_state);
    try std.testing.expect(shifted.wave_spawn_rng_state != baseline.wave_spawn_rng_state);
}

test "rush run rejects replay events" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 0 } },
        },
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(error.UnsupportedEventKind, runReplay(replay));
}

test "rush run accepts capture bootstrap events" {
    const allocator = std.testing.allocator;

    var bootstrap: replay_codec.CaptureBootstrapEvent = .{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 17,
        .pos_x = 256.0,
        .pos_y = 256.0,
        .health = 100.0,
        .ammo = 6.0,
        .experience = 123,
        .level = 2,
    };

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 42,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(usize, 1), result.ticks);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.player_weapon_id);
    try std.testing.expectEqual(@as(i32, 123), result.player_experience);
}

test "survival trace records authoritative rng rows and timing samples" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag | replay_codec.fire_pressed_flag},
        .events = &.{},
    });
    defer replay.deinit(allocator);
    replay.inputs[0][0].aim_x = 700.0;
    replay.inputs[0][0].aim_y = 512.0;

    var trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer trace.deinit(allocator);
    defer deinitReplayTickTraceRows(allocator, trace.items);
    _ = try runReplayWithTrace(
        allocator,
        replay,
        &trace,
        .{},
    );

    try std.testing.expectEqual(@as(usize, 1), trace.items.len);
    const row = trace.items[0];
    try std.testing.expectEqual(@as(usize, 1), row.timing_samples.len);
    try std.testing.expectEqualStrings("gpur_enter", row.timing_samples[0].phase);
    try std.testing.expectApproxEqAbs(@as(f32, 1.0 / 60.0), row.timing_samples[0].frame_dt_f32.?, 1e-6);
    try std.testing.expectEqual(@as(i32, 16), row.timing_samples[0].frame_dt_ms_i32.?);
    try std.testing.expectEqualStrings("gameplay_update_and_render", row.timing_samples[0].mode_fn.?);

    try std.testing.expect(row.rng_rows.len > 0);
    try std.testing.expectEqual(@as(i32, 1), row.rng_rows[0].tick_call_index);
    for (row.rng_rows[1..], 1..) |draw, idx| {
        try std.testing.expectEqual(@as(i32, @intCast(idx + 1)), draw.tick_call_index);
        try std.testing.expectEqual(row.rng_rows[idx - 1].state_after_u32, draw.state_before_u32);
    }
    try std.testing.expectEqual(row.rng.rng_state, row.rng_rows[row.rng_rows.len - 1].state_after_u32);
}

test "survival trace can omit rng rows and timing samples" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{replay_codec.fire_down_flag | replay_codec.fire_pressed_flag},
        .events = &.{},
    });
    defer replay.deinit(allocator);
    replay.inputs[0][0].aim_x = 700.0;
    replay.inputs[0][0].aim_y = 512.0;

    var trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer trace.deinit(allocator);
    defer deinitReplayTickTraceRows(allocator, trace.items);
    _ = try runReplayWithTrace(
        allocator,
        replay,
        &trace,
        .{
            .trace_rng = false,
            .trace_timing = false,
        },
    );

    try std.testing.expectEqual(@as(usize, 1), trace.items.len);
    try std.testing.expectEqual(@as(usize, 0), trace.items[0].rng_rows.len);
    try std.testing.expectEqual(@as(usize, 0), trace.items[0].timing_samples.len);
    try std.testing.expect(trace.items[0].rng.rng_state != 0);
}

test "rush run original capture bootstrap keeps packed move vector behavior" {
    const allocator = std.testing.allocator;

    var bootstrap: replay_codec.CaptureBootstrapEvent = .{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = @intFromEnum(game_ids.WeaponId.assault_rifle),
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 100.0,
        .ammo = 50.0,
    };
    bootstrap.digital_move_enabled_by_player[0] = true;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);
    replay.inputs[0][0].move_x = 1.0;
    replay.inputs[0][0].move_y = 0.0;
    replay.inputs[0][0].aim_x = 600.0;
    replay.inputs[0][0].aim_y = 512.0;

    var trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer trace.deinit(allocator);
    defer deinitReplayTickTraceRows(allocator, trace.items);
    _ = try runReplayWithTrace(
        allocator,
        replay,
        &trace,
        .{},
    );
    try std.testing.expectEqual(@as(usize, 1), trace.items.len);
    try std.testing.expect(f32Bits(trace.items[0].player_state.pos.x) > f32Bits(512.0));
}

test "rush run supports multiplayer replays" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplayMulti(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .player_count = 2,
        .inputs = &.{
            &.{ 0, 0 },
            &.{ replay_codec.fire_down_flag, 0 },
            &.{ 0, replay_codec.reload_pressed_flag },
        },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(usize, 3), result.ticks);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.player_weapon_id);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.most_used_weapon_id);
}

test "rush run advances spawn cooldown with integer frame milliseconds" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0xBEEF,
        .tick_rate = 60,
        .inputs = &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(usize, 16), result.ticks);
    try std.testing.expectEqual(@as(usize, 4), result.creature_active_count);
    try std.testing.expectEqual(@as(u32, 2055104443), result.wave_spawn_rng_state);
}

test "rush run disables progression updates even above level threshold" {
    const allocator = std.testing.allocator;

    var bootstrap: replay_codec.CaptureBootstrapEvent = .{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = @intFromEnum(game_ids.WeaponId.assault_rifle),
        .experience = 2060,
        .level = 1,
        .ammo = 50.0,
        .health = 100.0,
    };

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.rush),
        .seed = 0x1234,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplay(replay);
    try std.testing.expectEqual(@as(i32, 2060), result.player_experience);
    try std.testing.expectEqual(@as(i32, 1), result.player_level);
    try std.testing.expectEqual(@as(i32, 0), result.perk_pending_count);
}

test "survival run supports player counts 1 through 4" {
    const allocator = std.testing.allocator;

    var player_count: i32 = 1;
    while (player_count <= 4) : (player_count += 1) {
        const players_len: usize = @intCast(player_count);
        const fire_player: usize = players_len - 1;

        const row0_storage = [_]u32{0} ** state_mod.max_players;
        var row1_storage = [_]u32{0} ** state_mod.max_players;
        row1_storage[fire_player] = replay_codec.fire_down_flag;

        const rows = [_][]const u32{
            row0_storage[0..players_len],
            row1_storage[0..players_len],
        };

        const replay = try buildTestReplayMulti(allocator, .{
            .game_mode_id = @intFromEnum(GameModeId.survival),
            .seed = 0x1234,
            .tick_rate = 60,
            .player_count = player_count,
            .inputs = rows[0..],
            .events = &.{
                .{ .perk_menu_open = .{
                    .tick_index = 1,
                    .player_index = @intCast(player_count - 1),
                } },
            },
        });
        defer replay.deinit(allocator);

        const result = try runReplay(replay);
        try std.testing.expectEqual(@as(usize, 2), result.ticks);
        try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
    }
}

test "rush run supports player counts 1 through 4" {
    const allocator = std.testing.allocator;

    var player_count: i32 = 1;
    while (player_count <= 4) : (player_count += 1) {
        const players_len: usize = @intCast(player_count);

        const row0_storage = [_]u32{0} ** state_mod.max_players;
        const row1_storage = [_]u32{replay_codec.fire_down_flag} ** state_mod.max_players;
        const rows = [_][]const u32{
            row0_storage[0..players_len],
            row1_storage[0..players_len],
        };

        const replay = try buildTestReplayMulti(allocator, .{
            .game_mode_id = @intFromEnum(GameModeId.rush),
            .seed = 0x1234,
            .tick_rate = 60,
            .player_count = player_count,
            .inputs = rows[0..],
            .events = &.{},
        });
        defer replay.deinit(allocator);

        const result = try runReplay(replay);
        try std.testing.expectEqual(@as(usize, 2), result.ticks);
        try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.player_weapon_id);
        try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.assault_rifle), result.most_used_weapon_id);
    }
}

test "quest run is deterministic with explicit spawn entries" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const quest_entries = [_]spawn_mod.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = spawn_mod.SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 5000,
            .count = 1,
        },
    };
    const result0 = try runReplayWithOptions(replay, .{
        .quest_spawn_entries = quest_entries[0..],
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
    });
    const result1 = try runReplayWithOptions(replay, .{
        .quest_spawn_entries = quest_entries[0..],
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
    });
    try std.testing.expectEqual(result0.wave_spawn_rng_state, result1.wave_spawn_rng_state);
    try std.testing.expectEqual(@as(usize, 10), result0.ticks);
}

test "quest run timeline uses frame dt even when reflex boost is active" {
    const allocator = std.testing.allocator;

    var bootstrap: replay_codec.CaptureBootstrapEvent = .{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 100.0,
        .ammo = 11.0,
    };
    bootstrap.reflex_boost_ms = 500;

    const quest_entries = [_]spawn_mod.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = spawn_mod.SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 100_000,
            .count = 1,
        },
    };

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{
            .{ .capture_bootstrap = bootstrap },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayWithOptions(replay, .{
        .quest_spawn_entries = quest_entries[0..],
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.pistol),
    });
    try std.testing.expectEqual(@as(i64, 16), result.elapsed_ms_sim);
}

test "quest run advances spawn timeline and fires entries" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const quest_entries = [_]spawn_mod.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = spawn_mod.SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 200,
            .count = 1,
        },
    };
    replay.dt[0] = 0.5;
    const result = try runReplayWithOptions(replay, .{
        .quest_spawn_entries = quest_entries[0..],
    });
    try std.testing.expectEqual(@as(i64, 500), result.elapsed_ms_sim);
    try std.testing.expect(result.wave_spawn_count > 0);
    try std.testing.expect(result.creature_active_count > 0);
}

test "quest run supports multiplayer replays with explicit start weapon" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplayMulti(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .player_count = 2,
        .inputs = &.{
            &.{ 0, 0 },
            &.{ replay_codec.fire_pressed_flag, replay_codec.reload_pressed_flag },
        },
        .events = &.{
            .{ .perk_menu_open = .{ .tick_index = 1, .player_index = 1 } },
        },
    });
    defer replay.deinit(allocator);

    const result = try runReplayWithOptions(replay, .{
        .quest_start_weapon_id = @intFromEnum(game_ids.WeaponId.ion_cannon),
    });
    try std.testing.expectEqual(@as(usize, 2), result.ticks);
    try std.testing.expectEqual(@intFromEnum(game_ids.WeaponId.ion_cannon), result.player_weapon_id);
    try std.testing.expectEqual(@as(usize, 1), result.perk_menu_open_count);
}

test "quest run resolves native quest preset and start weapon from replay header" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 205,
        .tick_rate = 60,
        .quest_level = "2.5",
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    replay.dt[0] = 3.0;
    const result = try runReplayWithOptions(replay, .{});
    try std.testing.expectEqual(@as(i32, 6), result.player_weapon_id);
    try std.testing.expect(result.wave_spawn_count > 0);
}

test "quest run supports dynamic quest seed variants when no spawn entries are provided" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 999,
        .tick_rate = 60,
        .quest_level = "2.5",
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    replay.dt[0] = 3.0;
    const result = try runReplayWithOptions(replay, .{});
    try std.testing.expectEqual(@as(i32, 6), result.player_weapon_id);
    try std.testing.expect(result.wave_spawn_count > 0);
}

test "quest run rejects unknown quest level when no spawn entries are provided" {
    const allocator = std.testing.allocator;

    const replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 999,
        .tick_rate = 60,
        .quest_level = "9.9",
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    try std.testing.expectError(error.InvalidQuestSpawnTable, runReplay(replay));
}

test "quest run supports player counts 1 through 4 across static and dynamic levels" {
    const allocator = std.testing.allocator;
    const level_cases = [_]struct {
        quest_level: []const u8,
        seed: u32,
        expected_start_weapon: i32,
    }{
        .{ .quest_level = "1.1", .seed = 101, .expected_start_weapon = @intFromEnum(game_ids.WeaponId.pistol) },
        .{ .quest_level = "2.5", .seed = 205, .expected_start_weapon = 6 },
        .{ .quest_level = "3.3", .seed = 205, .expected_start_weapon = @intFromEnum(game_ids.WeaponId.pistol) },
        .{ .quest_level = "3.9", .seed = 999, .expected_start_weapon = 6 },
    };

    for (level_cases) |case| {
        var player_count: i32 = 1;
        while (player_count <= 4) : (player_count += 1) {
            const players_len: usize = @intCast(player_count);
            const row_storage = [_]u32{0} ** state_mod.max_players;
            const rows = [_][]const u32{row_storage[0..players_len]};

            var replay = try buildTestReplayMulti(allocator, .{
                .game_mode_id = @intFromEnum(GameModeId.quests),
                .seed = case.seed,
                .tick_rate = 60,
                .player_count = player_count,
                .quest_level = case.quest_level,
                .inputs = rows[0..],
                .events = &.{},
            });
            defer replay.deinit(allocator);

            replay.dt[0] = 3.0;
            const result = try runReplayWithOptions(replay, .{});
            try std.testing.expectEqual(@as(usize, 1), result.ticks);
            try std.testing.expectEqual(case.expected_start_weapon, result.player_weapon_id);
            try std.testing.expect(result.wave_spawn_count > 0);
        }
    }
}

test "quest run applies capture bootstrap quest session timers" {
    const allocator = std.testing.allocator;

    const inputs = [_]u32{0} ** 20;
    var replay_baseline = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = inputs[0..],
        .events = &.{},
    });
    defer replay_baseline.deinit(allocator);

    const quest_entries = [_]spawn_mod.QuestSpawnEntry{
        .{
            .pos = .{ .x = 512.0, .y = 512.0 },
            .heading = 0.0,
            .spawn_id = spawn_mod.SpawnId.formation_ring_alien_8_12,
            .trigger_ms = 5000,
            .count = 1,
        },
    };

    for (replay_baseline.dt, 0..) |*entry, idx| {
        _ = idx;
        entry.* = 0.1;
    }

    var baseline_trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer baseline_trace.deinit(allocator);
    defer deinitReplayTickTraceRows(allocator, baseline_trace.items);
    _ = try runReplayWithTrace(
        allocator,
        replay_baseline,
        &baseline_trace,
        .{
            .quest_spawn_entries = quest_entries[0..],
        },
    );
    try std.testing.expectEqual(@as(usize, 20), baseline_trace.items.len);
    try std.testing.expectEqual(@as(usize, 0), baseline_trace.items[19].summary.creature_count);

    var bootstrap: replay_codec.CaptureBootstrapEvent = .{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 1,
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 100.0,
        .ammo = 11.0,
        .experience = 0,
        .level = 1,
    };
    bootstrap.quest_session = .{
        .spawn_timeline_ms = 1701.0,
        .no_creatures_timer_ms = 3100.0,
        .completion_transition_ms = -1.0,
    };
    const events = [_]replay_codec.ReplayEvent{
        .{ .capture_bootstrap = bootstrap },
    };
    var replay_bootstrapped = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = inputs[0..],
        .events = events[0..],
    });
    defer replay_bootstrapped.deinit(allocator);
    for (replay_bootstrapped.dt, 0..) |*entry, idx| {
        _ = idx;
        entry.* = 0.1;
    }

    var bootstrapped_trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer bootstrapped_trace.deinit(allocator);
    defer deinitReplayTickTraceRows(allocator, bootstrapped_trace.items);
    _ = try runReplayWithTrace(
        allocator,
        replay_bootstrapped,
        &bootstrapped_trace,
        .{
            .quest_spawn_entries = quest_entries[0..],
        },
    );
    try std.testing.expectEqual(@as(usize, 20), bootstrapped_trace.items.len);
    try std.testing.expect(bootstrapped_trace.items[19].summary.creature_count > 0);
}

test "quest run disables runtime spawn slot ticks when capture spawns are authoritative" {
    const allocator = std.testing.allocator;

    const inputs = [_]u32{0} ** 40;
    var bootstrap: replay_codec.CaptureBootstrapEvent = .{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 1,
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 100.0,
        .ammo = 11.0,
        .experience = 0,
        .level = 1,
    };
    bootstrap.quest_session = .{
        .spawn_timeline_ms = 0.0,
        .no_creatures_timer_ms = 0.0,
        .completion_transition_ms = -1.0,
    };

    var capture_spawn: replay_codec.CaptureCreatureSpawnEvent = .{
        .tick_index = 0,
    };
    capture_spawn.spawn_count = 1;
    capture_spawn.spawns[0] = .{
        .template_id = 0x0A,
        .pos_x = 900.0,
        .pos_y = 900.0,
        .heading = 0.0,
    };
    const events = [_]replay_codec.ReplayEvent{
        .{ .capture_bootstrap = bootstrap },
        .{ .capture_creature_spawn = capture_spawn },
    };

    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = inputs[0..],
        .events = events[0..],
    });
    defer replay.deinit(allocator);
    for (replay.dt, 0..) |*entry, idx| {
        _ = idx;
        entry.* = 0.1;
    }

    const empty_entries: [0]spawn_mod.QuestSpawnEntry = .{};
    var trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer trace.deinit(allocator);
    defer deinitReplayTickTraceRows(allocator, trace.items);
    _ = try runReplayWithTrace(
        allocator,
        replay,
        &trace,
        .{
            .quest_spawn_entries = empty_entries[0..],
        },
    );
    try std.testing.expectEqual(@as(usize, 40), trace.items.len);
    try std.testing.expectEqual(@as(usize, 1), trace.items[39].summary.creature_count);
}

test "capture creature spawn event applies added head overrides" {
    var state = state_mod.GameplayState.init(1);
    var creatures: creatures_mod.CreaturePool = .{};
    creatures.reset();

    var event: replay_codec.CaptureCreatureSpawnEvent = .{
        .tick_index = 0,
    };
    event.spawn_count = 1;
    event.spawns[0] = .{
        .template_id = 0x18,
        .pos_x = -256.0,
        .pos_y = 256.0,
        .heading = -4.083981990814209,
    };
    event.added_head_count = 1;
    event.added_head[0] = .{
        .index = 1,
        .has_heading = true,
        .heading = 1.1278764009475708,
        .has_target_heading = true,
        .target_heading = 0.621416449546814,
        .has_ai_mode = true,
        .ai_mode = @intFromEnum(spawn_mod.CreatureAiMode.follow_link),
        .has_link_index = true,
        .link_index = 0,
        .has_hp = true,
        .hp = 123.5,
        .has_lifecycle_stage = true,
        .lifecycle_stage = 9.5,
        .has_orbit_angle = true,
        .orbit_angle = 0.25,
        .has_orbit_radius = true,
        .orbit_radius = 0.75,
        .has_flags = true,
        .flags = 17,
        .has_type_id = true,
        .type_id = 7,
        .has_pos = true,
        .pos_x = 12.25,
        .pos_y = 34.5,
    };

    try applyCaptureCreatureSpawnEvent(&state, &creatures, event);
    const creature = creatures.entries[1];
    try std.testing.expect(creature.active);
    try std.testing.expectApproxEqAbs(@as(f32, 1.1278764009475708), creature.heading, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.621416449546814), creature.target_heading, 1e-6);
    try std.testing.expectEqual(spawn_mod.CreatureAiMode.follow_link, creature.ai_mode);
    try std.testing.expectEqual(@as(i32, 0), creature.link_index);
    try std.testing.expectApproxEqAbs(@as(f32, 123.5), creature.hp, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 9.5), creature.lifecycle_stage, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.25), creature.orbit_angle, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.75), creature.orbit_radius, 1e-6);
    try std.testing.expectEqual(@as(u32, 17), creature.flags);
    try std.testing.expectEqual(@as(i32, 7), creature.type_id);
    try std.testing.expectApproxEqAbs(@as(f32, 12.25), creature.pos.x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 34.5), creature.pos.y, 1e-6);
}

test "capture creature spawn event applies added head rows without spawn rows" {
    var state = state_mod.GameplayState.init(1);
    var creatures: creatures_mod.CreaturePool = .{};
    creatures.reset();

    var seed_event: replay_codec.CaptureCreatureSpawnEvent = .{
        .tick_index = 0,
    };
    seed_event.spawn_count = 1;
    seed_event.spawns[0] = .{
        .template_id = 0x24,
        .pos_x = 256.0,
        .pos_y = 256.0,
        .heading = 0.0,
    };
    try applyCaptureCreatureSpawnEvent(&state, &creatures, seed_event);

    var update_event: replay_codec.CaptureCreatureSpawnEvent = .{
        .tick_index = 0,
    };
    update_event.added_head_count = 1;
    update_event.added_head[0] = .{
        .index = 0,
        .has_heading = true,
        .heading = 0.28999999165534973,
        .has_target_heading = true,
        .target_heading = 0.521416425704956,
        .has_ai_mode = true,
        .ai_mode = @intFromEnum(spawn_mod.CreatureAiMode.orbit_player),
        .has_link_index = true,
        .link_index = 1,
        .has_orbit_radius = true,
        .orbit_radius = 1.25,
        .has_flags = true,
        .flags = 5,
    };
    try applyCaptureCreatureSpawnEvent(&state, &creatures, update_event);

    const creature = creatures.entries[0];
    try std.testing.expect(creature.active);
    try std.testing.expectApproxEqAbs(@as(f32, 0.28999999165534973), creature.heading, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 0.521416425704956), creature.target_heading, 1e-6);
    try std.testing.expectEqual(spawn_mod.CreatureAiMode.orbit_player, creature.ai_mode);
    try std.testing.expectEqual(@as(i32, 1), creature.link_index);
    try std.testing.expectApproxEqAbs(@as(f32, 1.25), creature.orbit_radius, 1e-6);
    try std.testing.expectEqual(@as(u32, 5), creature.flags);
}

test "capture creature spawn event hard fails on invalid ai mode enum" {
    var state = state_mod.GameplayState.init(1);
    var creatures: creatures_mod.CreaturePool = .{};
    creatures.reset();

    var seed_event: replay_codec.CaptureCreatureSpawnEvent = .{
        .tick_index = 0,
    };
    seed_event.spawn_count = 1;
    seed_event.spawns[0] = .{
        .template_id = 0x24,
        .pos_x = 256.0,
        .pos_y = 256.0,
        .heading = 0.0,
    };
    try applyCaptureCreatureSpawnEvent(&state, &creatures, seed_event);

    var invalid_event: replay_codec.CaptureCreatureSpawnEvent = .{
        .tick_index = 1,
    };
    invalid_event.added_head_count = 1;
    invalid_event.added_head[0] = .{
        .index = 0,
        .has_ai_mode = true,
        .ai_mode = 999,
        .has_heading = true,
        .heading = 1.5,
    };

    const heading_before = creatures.entries[0].heading;
    try std.testing.expectError(
        error.InvalidCaptureEnumValue,
        applyCaptureCreatureSpawnEvent(&state, &creatures, invalid_event),
    );
    try std.testing.expectApproxEqAbs(heading_before, creatures.entries[0].heading, 1e-6);
}

test "quest run resets run state on capture transition to terminal state" {
    const allocator = std.testing.allocator;

    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{ 0, replay_codec.fire_down_flag },
        .events = &.{},
    });
    defer replay.deinit(allocator);

    var bootstrap: replay_codec.CaptureBootstrapEvent = .{
        .tick_index = 0,
    };
    bootstrap.player_count = 1;
    bootstrap.players[0] = .{
        .weapon_id = 17,
        .pos_x = 512.0,
        .pos_y = 512.0,
        .health = 0.0,
        .ammo = 6.0,
        .experience = 11581,
        .level = 4,
    };
    bootstrap.reflex_boost_ms = 1769;
    bootstrap.player_perk_counts[0].pair_count = 1;
    bootstrap.player_perk_counts[0].pairs[0] = .{
        .perk_id = @intFromEnum(PerkId.fire_caugh),
        .count = 1,
    };

    var transition: replay_codec.CaptureStateTransitionEvent = .{
        .tick_index = 0,
    };
    transition.transition_count = 1;
    transition.transitions[0] = .{
        .target_state = capture_state_reset_target,
        .has_before_state = true,
        .before_state = 9,
        .has_after_state = true,
        .after_state = capture_state_reset_target,
    };

    replay.events = blk: {
        const events = try allocator.alloc(replay_codec.ReplayEvent, 2);
        events[0] = .{ .capture_bootstrap = bootstrap };
        events[1] = .{ .capture_state_transition = transition };
        allocator.free(replay.events);
        break :blk events;
    };

    var trace: std.ArrayList(ReplayTickTrace) = .empty;
    defer trace.deinit(allocator);
    defer deinitReplayTickTraceRows(allocator, trace.items);
    const result = try runReplayWithTrace(
        allocator,
        replay,
        &trace,
        .{
            .quest_spawn_entries = &.{},
        },
    );

    try std.testing.expectEqual(@as(i32, 1), result.player_weapon_id);
    try std.testing.expectEqual(@as(i32, 0), result.player_experience);
    try std.testing.expectEqual(@as(i32, 1), result.player_level);
    try std.testing.expectEqual(@as(usize, 0), result.creature_active_count);
    try std.testing.expectEqual(@as(usize, 2), trace.items.len);
    try std.testing.expectApproxEqAbs(
        @as(f32, 0.0),
        trace.items[1].gameplay_state.bonuses.reflex_boost,
        @as(f32, 1e-6),
    );
    try std.testing.expectEqual(
        @as(i32, 0),
        trace.items[1].player_state.perk_counts.get(PerkId.fire_caugh),
    );
}

test "resolve quest level key ignores seed fallback outside i32 range" {
    const allocator = std.testing.allocator;
    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = std.math.maxInt(u32),
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    try std.testing.expect(runtime_bootstrap.resolveQuestLevelKey(replay.header) == null);
}

test "quest run rejects oversized quest spawn override table" {
    const allocator = std.testing.allocator;
    var replay = try buildTestReplay(allocator, .{
        .game_mode_id = @intFromEnum(GameModeId.quests),
        .seed = 101,
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    const oversized = try allocator.alloc(
        spawn_mod.QuestSpawnEntry,
        runtime_session.max_sim_quest_spawn_entries + 1,
    );
    defer allocator.free(oversized);
    for (oversized) |*entry| {
        entry.* = .{
            .pos = .{ .x = 0.0, .y = 0.0 },
            .heading = 0.0,
            .spawn_id = .zombie_boss_spawner_00,
            .trigger_ms = 0,
            .count = 0,
        };
    }

    try std.testing.expectError(
        error.InvalidQuestSpawnTable,
        runReplayWithOptions(replay, .{
            .quest_spawn_entries = oversized,
        }),
    );
}

test "survival run rejects world_size outside i32 range" {
    const allocator = std.testing.allocator;
    var replay = try buildTestReplay(allocator, .{
        .tick_rate = 60,
        .inputs = &.{0},
        .events = &.{},
    });
    defer replay.deinit(allocator);

    replay.header.world_size = 3_000_000_000.0;
    try std.testing.expectError(error.InvalidHeaderValue, runReplay(replay));
}

test "quest run disables world dt perk steps for original capture replays" {
    const allocator = std.testing.allocator;

    const bootstrap_event: replay_codec.ReplayEvent = .{
        .capture_bootstrap = blk: {
            var bootstrap = replay_codec.CaptureBootstrapEvent{
                .tick_index = 0,
            };
            bootstrap.player_count = 1;
            bootstrap.players[0] = .{
                .weapon_id = 1,
                .pos_x = 512.0,
                .pos_y = 512.0,
                .health = 100.0,
                .ammo = 11.0,
                .experience = 0,
                .level = 1,
            };
            break :blk bootstrap;
        },
    };
    const reflex_apply_event: replay_codec.ReplayEvent = .{
        .capture_perk_apply = .{
            .tick_index = 0,
            .perk_id = @intFromEnum(PerkId.reflex_boosted),
            .outside_before = true,
        },
    };

    const run = struct {
        fn runCase(
            allocator_inner: std.mem.Allocator,
            bootstrap: replay_codec.ReplayEvent,
            reflex_apply: replay_codec.ReplayEvent,
            include_reflex_boosted: bool,
            dt_tick: f32,
        ) !struct { x_bits: u32, y_bits: u32 } {
            const events = [_]replay_codec.ReplayEvent{ bootstrap, reflex_apply };
            var replay = try buildTestReplay(allocator_inner, .{
                .game_mode_id = @intFromEnum(GameModeId.quests),
                .seed = 101,
                .tick_rate = 60,
                .inputs = &.{0},
                .events = if (include_reflex_boosted) events[0..2] else events[0..1],
            });
            defer replay.deinit(allocator_inner);

            replay.inputs[0][0].move_x = 1.0;
            replay.inputs[0][0].move_y = 0.0;
            replay.inputs[0][0].aim_x = 700.0;
            replay.inputs[0][0].aim_y = 512.0;
            replay.dt[0] = dt_tick;

            var trace: std.ArrayList(ReplayTickTrace) = .empty;
            defer trace.deinit(allocator_inner);
            defer deinitReplayTickTraceRows(allocator_inner, trace.items);
            _ = try runReplayWithTrace(
                allocator_inner,
                replay,
                &trace,
                .{
                    .quest_spawn_entries = &.{},
                },
            );
            try std.testing.expectEqual(@as(usize, 1), trace.items.len);
            return .{
                .x_bits = f32Bits(trace.items[0].player_state.pos.x),
                .y_bits = f32Bits(trace.items[0].player_state.pos.y),
            };
        }
    }.runCase;

    const no_override_without_perk = try run(
        allocator,
        bootstrap_event,
        reflex_apply_event,
        false,
        1.0 / 60.0,
    );
    const no_override_with_perk = try run(
        allocator,
        bootstrap_event,
        reflex_apply_event,
        true,
        1.0 / 60.0,
    );
    try std.testing.expectEqual(no_override_without_perk.x_bits, no_override_with_perk.x_bits);
    try std.testing.expectEqual(no_override_without_perk.y_bits, no_override_with_perk.y_bits);

    const override_without_perk = try run(
        allocator,
        bootstrap_event,
        reflex_apply_event,
        false,
        0.1,
    );
    const override_with_perk = try run(
        allocator,
        bootstrap_event,
        reflex_apply_event,
        true,
        0.1,
    );
    try std.testing.expectEqual(override_without_perk.x_bits, override_with_perk.x_bits);
    try std.testing.expectEqual(override_without_perk.y_bits, override_with_perk.y_bits);
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

const TestReplayConfig = struct {
    game_mode_id: i32 = @intFromEnum(GameModeId.survival),
    seed: u32 = 1,
    tick_rate: i32,
    game_version: []const u8 = "0.9.0",
    preserve_bugs: bool = false,
    quest_level: []const u8 = "",
    inputs: []const u32,
    prelude: []const replay_codec.ReplayPreludeOp = &.{},
    postlude: []const replay_codec.ReplayPostludeOp = &.{},
    events: []const replay_codec.ReplayEvent,
};

const TestReplayMultiConfig = struct {
    game_mode_id: i32 = @intFromEnum(GameModeId.survival),
    seed: u32 = 1,
    tick_rate: i32,
    player_count: i32,
    game_version: []const u8 = "0.9.0",
    preserve_bugs: bool = false,
    quest_level: []const u8 = "",
    inputs: []const []const u32,
    prelude: []const replay_codec.ReplayPreludeOp = &.{},
    postlude: []const replay_codec.ReplayPostludeOp = &.{},
    events: []const replay_codec.ReplayEvent,
};

fn buildTestReplay(
    allocator: std.mem.Allocator,
    cfg: TestReplayConfig,
) !replay_codec.Replay {
    const ticks = try allocator.alloc(replay_codec.ReplayTickInputs, cfg.inputs.len);
    errdefer allocator.free(ticks);

    for (cfg.inputs, 0..) |flags, tick_index| {
        const input_tick = try allocator.alloc(replay_codec.ReplayPlayerInput, 1);
        input_tick[0] = .{
            .move_x = 0.0,
            .move_y = 0.0,
            .aim_x = 0.0,
            .aim_y = 0.0,
            .flags = flags,
        };
        ticks[tick_index] = input_tick;
    }

    const prelude = if (cfg.prelude.len > 0)
        try allocator.dupe(replay_codec.ReplayPreludeOp, cfg.prelude)
    else
        &.{};
    errdefer if (prelude.len > 0) allocator.free(prelude);
    const postlude = if (cfg.postlude.len > 0)
        try allocator.dupe(replay_codec.ReplayPostludeOp, cfg.postlude)
    else
        &.{};
    errdefer if (postlude.len > 0) allocator.free(postlude);
    const events = try allocator.alloc(replay_codec.ReplayEvent, cfg.events.len);
    for (cfg.events, 0..) |event, idx| {
        events[idx] = event;
    }
    const dt = try allocator.alloc(f32, cfg.inputs.len);
    const nominal_dt: f32 = if (cfg.tick_rate > 0)
        @as(f32, 1.0 / @as(f32, @floatFromInt(cfg.tick_rate)))
    else
        0.0;
    for (dt, 0..) |*entry, idx| {
        _ = idx;
        entry.* = nominal_dt;
    }

    return .{
        .header = .{
            .game_mode_id = cfg.game_mode_id,
            .seed = cfg.seed,
            .replay_format_version = replay_codec.replay_format_version,
            .quest_level = try allocator.dupe(u8, cfg.quest_level),
            .game_version = try allocator.dupe(u8, cfg.game_version),
            .tick_rate = cfg.tick_rate,
            .quest_fail_retry_count = 0,
            .hardcore = false,
            .preserve_bugs = cfg.preserve_bugs,
            .detail_preset = 5,
            .violence_disabled = 0,
            .world_size = 1024.0,
            .player_count = 1,
            .status = .{
                .quest_unlock_index = 0,
                .quest_unlock_index_full = 0,
                .weapon_usage_counts = [_]u32{0} ** replay_codec.weapon_usage_count,
            },
            .input_quantization = try allocator.dupe(u8, "f32"),
        },
        .inputs = ticks,
        .dt = dt,
        .prelude = prelude,
        .postlude = postlude,
        .events = events,
    };
}

fn buildTestReplayMulti(
    allocator: std.mem.Allocator,
    cfg: TestReplayMultiConfig,
) !replay_codec.Replay {
    const ticks = try allocator.alloc(replay_codec.ReplayTickInputs, cfg.inputs.len);
    errdefer allocator.free(ticks);
    const players_len: usize = @intCast(cfg.player_count);

    for (cfg.inputs, 0..) |tick_flags, tick_index| {
        std.debug.assert(tick_flags.len == players_len);
        const input_tick = try allocator.alloc(replay_codec.ReplayPlayerInput, players_len);
        for (tick_flags, 0..) |flags, player_index| {
            input_tick[player_index] = .{
                .move_x = 0.0,
                .move_y = 0.0,
                .aim_x = 0.0,
                .aim_y = 0.0,
                .flags = flags,
            };
        }
        ticks[tick_index] = input_tick;
    }

    const prelude = if (cfg.prelude.len > 0)
        try allocator.dupe(replay_codec.ReplayPreludeOp, cfg.prelude)
    else
        &.{};
    errdefer if (prelude.len > 0) allocator.free(prelude);
    const postlude = if (cfg.postlude.len > 0)
        try allocator.dupe(replay_codec.ReplayPostludeOp, cfg.postlude)
    else
        &.{};
    errdefer if (postlude.len > 0) allocator.free(postlude);
    const events = try allocator.alloc(replay_codec.ReplayEvent, cfg.events.len);
    for (cfg.events, 0..) |event, idx| {
        events[idx] = event;
    }
    const dt = try allocator.alloc(f32, cfg.inputs.len);
    const nominal_dt: f32 = if (cfg.tick_rate > 0)
        @as(f32, 1.0 / @as(f32, @floatFromInt(cfg.tick_rate)))
    else
        0.0;
    for (dt, 0..) |*entry, idx| {
        _ = idx;
        entry.* = nominal_dt;
    }

    return .{
        .header = .{
            .game_mode_id = cfg.game_mode_id,
            .seed = cfg.seed,
            .replay_format_version = replay_codec.replay_format_version,
            .quest_level = try allocator.dupe(u8, cfg.quest_level),
            .game_version = try allocator.dupe(u8, cfg.game_version),
            .tick_rate = cfg.tick_rate,
            .quest_fail_retry_count = 0,
            .hardcore = false,
            .preserve_bugs = cfg.preserve_bugs,
            .detail_preset = 5,
            .violence_disabled = 0,
            .world_size = 1024.0,
            .player_count = cfg.player_count,
            .status = .{
                .quest_unlock_index = 0,
                .quest_unlock_index_full = 0,
                .weapon_usage_counts = [_]u32{0} ** replay_codec.weapon_usage_count,
            },
            .input_quantization = try allocator.dupe(u8, "f32"),
        },
        .inputs = ticks,
        .dt = dt,
        .prelude = prelude,
        .postlude = postlude,
        .events = events,
    };
}
