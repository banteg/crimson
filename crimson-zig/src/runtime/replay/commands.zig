//! Replay commands, applied like `DeterministicSession.apply_command`.
//!
//! Perk commands the live UI cannot issue are errors: without the check
//! they would silently no-op or reroll the offered choices.
const std = @import("std");
const game_ids = @import("../../game_ids.zig");
const replay_codec = @import("../../replay_codec.zig");

const movement = @import("../movement.zig");
const perks = @import("../perks.zig");
const session_mod = @import("../session.zig");
const survival_progression = @import("../survival_progression.zig");
const typo_runtime = @import("../../typo/runtime.zig");

pub const CommandError = error{
    NoPendingPerk,
    EveryPlayerDead,
    ChoiceNotOffered,
};

/// The perk prompt only offers the menu while a perk is pending and a player
/// is alive; each command sees the state left by the commands before it.
fn requirePerkCommandAllowed(context: *const session_mod.DeterministicSession) CommandError!void {
    if (context.state.perk_selection.pending_count <= 0) return error.NoPendingPerk;
    if (session_mod.allPlayersDead(context.playersConst())) return error.EveryPlayerDead;
}

pub fn applyCommand(
    context: *session_mod.DeterministicSession,
    command: replay_codec.Command,
    dt: f32,
) CommandError!void {
    const state = &context.state;
    switch (command) {
        .perk_menu_open => {
            try requirePerkCommandAllowed(context);
            _ = perks.perkSelectionCurrentChoices(
                state,
                context.players(),
                context.game_mode,
                context.player_count,
                context.quest_unlock_index,
            );
            context.perk_menu_open_count += 1;
        },
        .perk_pick => |pick| {
            try requirePerkCommandAllowed(context);
            // Each pick sees any timing changes made by earlier picks.
            const dt_sim = survival_progression.timeScaleReflexBoostBonus(
                state.bonuses.reflex_boost,
                state.time_scale_active,
                movement.applyPerkWorldDtSteps(context.playersConst(), dt),
            );
            // A pick prepares the offer when no menu-open did, but leaves the
            // next offer to a later menu-open.
            _ = perks.perkSelectionCurrentChoices(
                state,
                context.players(),
                context.game_mode,
                context.player_count,
                context.quest_unlock_index,
            );
            const picked = perks.perkSelectionPickPreparedWithContext(
                state,
                context.players(),
                pick.choice_index,
                .{ .creatures = &context.creatures, .dt_frame = dt_sim },
            ) catch unreachable;
            if (picked == null) return error.ChoiceNotOffered;
            context.perk_pick_count += 1;
        },
        .typo_char => |typed| typo_runtime.applyCharCommand(state, typed.ch),
        .typo_backspace => typo_runtime.applyBackspaceCommand(state),
        .typo_submit => typo_runtime.applySubmitCommand(state, &context.creatures),
    }
}

/// Why `command` was illegal, worded like the Python session.
pub fn writeError(writer: *std.Io.Writer, err: CommandError, command: replay_codec.Command) std.Io.Writer.Error!void {
    try writer.writeAll(@tagName(command));
    switch (err) {
        error.NoPendingPerk => try writer.writeAll(" without a pending perk"),
        error.EveryPlayerDead => try writer.writeAll(" while every player is dead"),
        error.ChoiceNotOffered => try writer.print(" choice_index={d} is not an offered choice", .{command.perk_pick.choice_index}),
    }
}

const testing = std.testing;

fn testSession(game_mode: game_ids.GameModeId) !session_mod.DeterministicSession {
    return session_mod.DeterministicSession.init(.fromRunSpec(.{
        .game_mode = game_mode,
        .seed = 42,
        .quest_level = if (game_mode == .quests) .{ .major = 1, .minor = 1 } else null,
    }), .{});
}

test "perk commands require a pending perk and an offered choice" {
    var session = try testSession(.survival);
    try testing.expectError(
        error.NoPendingPerk,
        applyCommand(&session, .{ .perk_menu_open = .{ .player_index = 0 } }, replay_codec.tick_dt),
    );
    try testing.expectError(
        error.NoPendingPerk,
        applyCommand(&session, .{ .perk_pick = .{ .player_index = 0, .choice_index = 0 } }, replay_codec.tick_dt),
    );

    session.state.perk_selection.pending_count = 1;
    session.players()[0].health = 0.0;
    try testing.expectError(
        error.EveryPlayerDead,
        applyCommand(&session, .{ .perk_menu_open = .{ .player_index = 0 } }, replay_codec.tick_dt),
    );
    session.players()[0].health = 100.0;
    try applyCommand(&session, .{ .perk_menu_open = .{ .player_index = 0 } }, replay_codec.tick_dt);
    const bad_pick: replay_codec.Command = .{ .perk_pick = .{ .player_index = 0, .choice_index = 6 } };
    try testing.expectError(error.ChoiceNotOffered, applyCommand(&session, bad_pick, replay_codec.tick_dt));
    var message: [96]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&message);
    try writeError(&writer, error.ChoiceNotOffered, bad_pick);
    try testing.expectEqualStrings("perk_pick choice_index=6 is not an offered choice", writer.buffered());
    try applyCommand(&session, .{ .perk_pick = .{ .player_index = 0, .choice_index = 0 } }, replay_codec.tick_dt);
    try testing.expectEqual(@as(i32, 0), session.state.perk_selection.pending_count);
    try testing.expect(session.state.perk_selection.choices_dirty);
    try testing.expectEqual(@as(usize, 1), session.perk_pick_count);
}

test "a pick without a menu-open prepares the offer first" {
    var opened = try testSession(.survival);
    opened.state.perk_selection.pending_count = 1;
    var direct = opened;
    try applyCommand(&opened, .{ .perk_menu_open = .{ .player_index = 0 } }, replay_codec.tick_dt);
    try applyCommand(&opened, .{ .perk_pick = .{ .player_index = 0, .choice_index = 1 } }, replay_codec.tick_dt);
    try applyCommand(&direct, .{ .perk_pick = .{ .player_index = 0, .choice_index = 1 } }, replay_codec.tick_dt);
    try testing.expectEqual(opened.state.rng.state, direct.state.rng.state);
    try testing.expectEqual(opened.players()[0].perk_counts, direct.players()[0].perk_counts);
}

test "typo commands edit the typing buffer" {
    var session = try testSession(.typo);
    try applyCommand(&session, .{ .typo_char = .{ .player_index = 0, .ch = "a" } }, replay_codec.tick_dt);
    try applyCommand(&session, .{ .typo_char = .{ .player_index = 0, .ch = "b" } }, replay_codec.tick_dt);
    try applyCommand(&session, .{ .typo_backspace = .{ .player_index = 0 } }, replay_codec.tick_dt);
    try testing.expectEqualStrings("a", session.state.typo.typing.slice());
    try applyCommand(&session, .{ .typo_submit = .{ .player_index = 0 } }, replay_codec.tick_dt);
    try testing.expectEqual(@as(i32, 1), session.state.typo.typing.submit_count);
}

test "perk pick applies immediate creature perk effects through the shared path" {
    var session = try testSession(.survival);
    session.state.perk_selection.pending_count = 1;
    session.state.perk_selection.choice_count = 1;
    session.state.perk_selection.choices[0] = .breathing_room;
    session.state.perk_selection.choices_dirty = false;
    session.creatures.entries[0].active = true;
    session.creatures.entries[0].lifecycle_stage = 5.0;
    const rng_before_pick = session.state.rng.state;

    try applyCommand(&session, .{ .perk_pick = .{ .player_index = 0, .choice_index = 0 } }, 0.075);

    try testing.expectApproxEqAbs(@as(f32, 4.925), session.creatures.entries[0].lifecycle_stage, 1e-6);
    try testing.expect(session.state.perk_selection.choices_dirty);
    try testing.expectEqual(rng_before_pick, session.state.rng.state);
}
