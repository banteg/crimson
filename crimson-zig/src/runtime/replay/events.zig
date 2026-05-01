const std = @import("std");
const game_ids = @import("../../game_ids.zig");
const replay_codec = @import("../../replay_codec.zig");

const capture_state = @import("capture_state.zig");
const creatures_mod = @import("../creatures.zig");
const perks = @import("../perks.zig");
const spawn_mod = @import("../spawn.zig");
const state_mod = @import("../state.zig");
const typo_runtime = @import("../../typo/runtime.zig");

const GameModeId = game_ids.GameModeId;
const PerkId = perks.PerkId;

pub const TickEventPhase = enum {
    pre_step,
    post_state_transition,
    post_spawn_hook,
    post_menu_open,
};

pub const EventError = error{
    InvalidCaptureEnumValue,
    UnsupportedEventKind,
    UnsupportedEventPlayerIndex,
    InvalidSpawnTemplate,
};

pub const EventOutcomeSignal = enum {
    none,
    request_capture_state_reset,
};

pub const EventOutcome = struct {
    signal: EventOutcomeSignal = .none,
    menu_open_seen_this_tick: bool = false,
    perk_menu_open_count_delta: usize = 0,
    perk_pick_count_delta: usize = 0,
};

pub const ApplyEventOptions = struct {
    game_mode: GameModeId,
    player_count: i32,
    quest_unlock_index: i32,
    strict_events: bool,
    menu_open_seen_this_tick: bool = false,
};

pub fn classifyTickEvent(
    event: replay_codec.ReplayEvent,
    defer_menu_open: bool,
) TickEventPhase {
    if (!defer_menu_open) return .pre_step;
    return switch (event) {
        .perk_menu_open => .post_menu_open,
        .capture_creature_spawn => .post_spawn_hook,
        .capture_state_transition => .post_state_transition,
        else => .pre_step,
    };
}

pub fn applyReplayEvent(
    event: replay_codec.ReplayEvent,
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: *creatures_mod.CreaturePool,
    dt_frame: f32,
    quest_spawn_timeline_ms: *f32,
    quest_no_creatures_timer_ms: *f32,
    quest_completion_transition_ms: *f32,
    options: ApplyEventOptions,
) EventError!EventOutcome {
    var outcome: EventOutcome = .{};
    switch (event) {
        .perk_menu_open => |open| {
            outcome.menu_open_seen_this_tick = true;
            if (options.game_mode == .rush) {
                if (options.strict_events) return error.UnsupportedEventKind;
                return outcome;
            }
            if (open.player_index < 0 or open.player_index >= @as(i32, @intCast(players.len))) {
                return error.UnsupportedEventPlayerIndex;
            }
            _ = perks.perkSelectionCurrentChoices(
                state,
                players,
                options.game_mode,
                options.player_count,
                options.quest_unlock_index,
            );
            outcome.perk_menu_open_count_delta = 1;
            return outcome;
        },
        .perk_pick => |pick| {
            if (options.game_mode == .rush) {
                if (options.strict_events) return error.UnsupportedEventKind;
                return outcome;
            }
            if (pick.player_index < 0 or pick.player_index >= @as(i32, @intCast(players.len))) {
                return error.UnsupportedEventPlayerIndex;
            }
            const applied = perks.perkSelectionPickWithContext(
                state,
                players,
                pick.choice_index,
                options.game_mode,
                options.player_count,
                options.quest_unlock_index,
                .{
                    .creatures = creatures,
                    .dt_frame = dt_frame,
                },
            ) catch unreachable;
            if (applied == null) {
                return outcome;
            }
            outcome.perk_pick_count_delta = 1;
            return outcome;
        },
        .typo_char => |command| {
            if (options.game_mode != .typo) {
                if (options.strict_events) return error.UnsupportedEventKind;
                return outcome;
            }
            if (command.player_index < 0 or command.player_index >= @as(i32, @intCast(players.len))) {
                return error.UnsupportedEventPlayerIndex;
            }
            typo_runtime.applyCharCommand(state, command.ch);
            return outcome;
        },
        .typo_backspace => |command| {
            if (options.game_mode != .typo) {
                if (options.strict_events) return error.UnsupportedEventKind;
                return outcome;
            }
            if (command.player_index < 0 or command.player_index >= @as(i32, @intCast(players.len))) {
                return error.UnsupportedEventPlayerIndex;
            }
            typo_runtime.applyBackspaceCommand(state);
            return outcome;
        },
        .typo_submit => |command| {
            if (options.game_mode != .typo) {
                if (options.strict_events) return error.UnsupportedEventKind;
                return outcome;
            }
            if (command.player_index < 0 or command.player_index >= @as(i32, @intCast(players.len))) {
                return error.UnsupportedEventPlayerIndex;
            }
            typo_runtime.applySubmitCommand(state, creatures);
            return outcome;
        },
        .capture_bootstrap => |bootstrap| {
            try capture_state.applyCaptureBootstrapEvent(
                bootstrap,
                state,
                players,
                quest_spawn_timeline_ms,
                quest_no_creatures_timer_ms,
                quest_completion_transition_ms,
            );
            return outcome;
        },
        .capture_perk_apply => |capture_perk_apply| {
            if (options.game_mode == .rush) {
                if (options.strict_events) return error.UnsupportedEventKind;
                return outcome;
            }
            if (players.len == 0) return outcome;
            var rng_state_before: ?u32 = null;
            if (capture_perk_apply.outside_before) {
                if (capture_perk_apply.pending_before) |pending_before| {
                    state.perk_selection.pending_count = pending_before;
                }
                rng_state_before = state.rng.state;
            }
            const perk_id = std.enums.fromInt(PerkId, capture_perk_apply.perk_id) orelse {
                if (options.strict_events) return error.UnsupportedEventKind;
                return outcome;
            };
            perks.applyPerkWithContext(
                state,
                players,
                perk_id,
                .{
                    .creatures = creatures,
                    .dt_frame = dt_frame,
                },
            ) catch unreachable;
            if (capture_perk_apply.outside_before) {
                if (capture_perk_apply.pending_after) |pending_after| {
                    state.perk_selection.pending_count = pending_after;
                }
                if (state.perk_selection.pending_count > 0) {
                    state.perk_selection.pending_count -= 1;
                }
                if (rng_state_before) |rng_state| {
                    state.rng.srand(rng_state);
                }
            }
            return outcome;
        },
        .capture_perk_pending => |capture_perk_pending| {
            if (options.game_mode == .rush) {
                if (options.strict_events) return error.UnsupportedEventKind;
                return outcome;
            }
            if (capture_perk_pending.perk_pending < 0) {
                if (options.strict_events) return error.UnsupportedEventKind;
                return outcome;
            }
            state.perk_selection.pending_count = capture_perk_pending.perk_pending;
            state.perk_selection.choices_dirty = true;
            return outcome;
        },
        .capture_creature_spawn => |capture_spawn| {
            try capture_state.applyCaptureCreatureSpawnEvent(
                state,
                creatures,
                capture_spawn,
            );
            return outcome;
        },
        .capture_state_transition => |capture_state_transition| {
            for (capture_state_transition.transitions[0..capture_state_transition.transition_count]) |transition| {
                if (transition.target_state == capture_state.capture_state_reset_target) {
                    outcome.signal = .request_capture_state_reset;
                    break;
                }
            }
            return outcome;
        },
    }
}

test "tick event classification defers state transition then spawn then menu in capture mode" {
    var transition: replay_codec.CaptureStateTransitionEvent = .{
        .tick_index = 0,
    };
    transition.transition_count = 1;
    transition.transitions[0] = .{
        .target_state = 6,
        .has_before_state = false,
        .before_state = 0,
        .has_after_state = false,
        .after_state = 0,
    };
    const events = [_]replay_codec.ReplayEvent{
        .{ .perk_menu_open = .{ .tick_index = 0, .player_index = 0 } },
        .{ .capture_creature_spawn = .{ .tick_index = 0 } },
        .{ .capture_state_transition = transition },
    };

    var pre_count: usize = 0;
    for (events) |event| {
        if (classifyTickEvent(event, true) == .pre_step) pre_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), pre_count);

    var ordered = [_]TickEventPhase{.pre_step} ** 3;
    var ordered_count: usize = 0;
    for ([_]TickEventPhase{
        .post_state_transition,
        .post_spawn_hook,
        .post_menu_open,
    }) |phase| {
        for (events) |event| {
            if (classifyTickEvent(event, true) != phase) continue;
            ordered[ordered_count] = phase;
            ordered_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 3), ordered_count);
    try std.testing.expectEqual(TickEventPhase.post_state_transition, ordered[0]);
    try std.testing.expectEqual(TickEventPhase.post_spawn_hook, ordered[1]);
    try std.testing.expectEqual(TickEventPhase.post_menu_open, ordered[2]);
}

test "capture state transition event returns reset request through event outcome" {
    var state = state_mod.GameplayState.init(42);
    var creatures: creatures_mod.CreaturePool = .{};
    var players_storage: [state_mod.max_players]state_mod.PlayerState = undefined;
    const players = players_storage[0..0];
    var quest_spawn_timeline_ms: f32 = 0.0;
    var quest_no_creatures_timer_ms: f32 = 0.0;
    var quest_completion_transition_ms: f32 = -1.0;

    var transition: replay_codec.CaptureStateTransitionEvent = .{
        .tick_index = 1,
    };
    transition.transition_count = 1;
    transition.transitions[0] = .{
        .target_state = capture_state.capture_state_reset_target,
        .has_before_state = true,
        .before_state = 9,
        .has_after_state = true,
        .after_state = capture_state.capture_state_reset_target,
    };

    const outcome = try applyReplayEvent(
        .{ .capture_state_transition = transition },
        &state,
        players,
        &creatures,
        0.016,
        &quest_spawn_timeline_ms,
        &quest_no_creatures_timer_ms,
        &quest_completion_transition_ms,
        .{
            .game_mode = .quests,
            .player_count = 1,
            .quest_unlock_index = 0,
            .strict_events = true,
        },
    );
    try std.testing.expectEqual(EventOutcomeSignal.request_capture_state_reset, outcome.signal);
}

test "typo replay commands apply in typo mode and reject in other modes" {
    var state = state_mod.GameplayState.init(42);
    var creatures: creatures_mod.CreaturePool = .{};
    var players_storage: [state_mod.max_players]state_mod.PlayerState = undefined;
    const players = players_storage[0..1];
    players[0] = .{};
    var quest_spawn_timeline_ms: f32 = 0.0;
    var quest_no_creatures_timer_ms: f32 = 0.0;
    var quest_completion_transition_ms: f32 = -1.0;

    _ = try applyReplayEvent(
        .{ .typo_char = .{ .tick_index = 0, .player_index = 0, .ch = 'a' } },
        &state,
        players,
        &creatures,
        1.0 / 60.0,
        &quest_spawn_timeline_ms,
        &quest_no_creatures_timer_ms,
        &quest_completion_transition_ms,
        .{
            .game_mode = .typo,
            .player_count = 1,
            .quest_unlock_index = 0,
            .strict_events = true,
        },
    );
    try std.testing.expectEqualStrings("a", state.typo.typing.slice());

    try std.testing.expectError(
        error.UnsupportedEventKind,
        applyReplayEvent(
            .{ .typo_submit = .{ .tick_index = 0, .player_index = 0 } },
            &state,
            players,
            &creatures,
            1.0 / 60.0,
            &quest_spawn_timeline_ms,
            &quest_no_creatures_timer_ms,
            &quest_completion_transition_ms,
            .{
                .game_mode = .survival,
                .player_count = 1,
                .quest_unlock_index = 0,
                .strict_events = true,
            },
        ),
    );
}

test "lifeline 50-50 replay perk effect deactivates every other eligible creature slot" {
    var state = state_mod.GameplayState.init(1);
    const before_rng = state.rng.state;
    var creatures: creatures_mod.CreaturePool = .{};

    for (0..8) |idx| {
        creatures.entries[idx].active = true;
        creatures.entries[idx].hp = 100.0;
        creatures.entries[idx].pos = .{
            .x = @floatFromInt(idx),
            .y = @as(f32, @floatFromInt(idx)) * 10.0,
        };
        creatures.entries[idx].flags = 0;
    }
    creatures.entries[3].flags = spawn_mod.CreatureFlags.anim_ping_pong;
    creatures.entries[5].hp = 600.0;

    perks.applyReplayPerkCreatureEffects(
        PerkId.lifeline_50_50,
        &state,
        &creatures,
        0.016,
    );

    const expected = [_]bool{ true, false, true, true, true, true, true, false };
    for (expected, 0..) |active_expected, idx| {
        try std.testing.expectEqual(active_expected, creatures.entries[idx].active);
    }
    try std.testing.expect(before_rng != state.rng.state);
}

test "perk pick event applies immediate creature perk effects through shared path" {
    var state = state_mod.GameplayState.init(1);
    var creatures: creatures_mod.CreaturePool = .{};
    var players = [_]state_mod.PlayerState{
        .{ .index = 0, .pos = .{}, .health = 90.0 },
    };
    var quest_spawn_timeline_ms: f32 = 0.0;
    var quest_no_creatures_timer_ms: f32 = 0.0;
    var quest_completion_transition_ms: f32 = -1.0;

    state.perk_selection.pending_count = 1;
    state.perk_selection.choice_count = 1;
    state.perk_selection.choices[0] = .breathing_room;
    state.perk_selection.choices_dirty = false;
    creatures.entries[0].active = true;
    creatures.entries[0].lifecycle_stage = 5.0;

    const outcome = try applyReplayEvent(
        .{ .perk_pick = .{ .tick_index = 0, .player_index = 0, .choice_index = 0 } },
        &state,
        players[0..],
        &creatures,
        0.075,
        &quest_spawn_timeline_ms,
        &quest_no_creatures_timer_ms,
        &quest_completion_transition_ms,
        .{
            .game_mode = .survival,
            .player_count = 1,
            .quest_unlock_index = 0,
            .strict_events = true,
        },
    );

    try std.testing.expectEqual(@as(usize, 1), outcome.perk_pick_count_delta);
    try std.testing.expectApproxEqAbs(@as(f32, 4.925), creatures.entries[0].lifecycle_stage, 1e-6);
}
