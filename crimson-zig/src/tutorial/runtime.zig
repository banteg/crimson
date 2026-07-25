const creatures_mod = @import("../runtime/creatures.zig");
const effects_mod = @import("../runtime/effects.zig");
const bonuses_mod = @import("../runtime/bonuses.zig");
const player_runtime = @import("../runtime/player.zig");
const spawn_mod = @import("../runtime/spawn.zig");
const state_mod = @import("../runtime/state.zig");
const survival_progression = @import("../runtime/survival_progression.zig");
const tutorial_state = @import("state.zig");
const timeline = @import("timeline.zig");

pub fn promptText(stage_index: i32) []const u8 {
    return timeline.promptText(stage_index);
}

pub fn hintText(hint_index: i32, preserve_bugs: bool) []const u8 {
    return timeline.hintText(hint_index, preserve_bugs);
}

pub fn beforeStep(
    state: *state_mod.GameplayState,
    creatures: *const creatures_mod.CreaturePool,
) void {
    state.tutorial.preserve_bugs = state.preserve_bugs;
    const hint_ref = state.tutorial.hint_bonus_creature_ref orelse {
        state.tutorial.hint_bonus_alive_before_tick = false;
        return;
    };
    if (hint_ref >= creatures.entries.len) {
        state.tutorial.hint_bonus_alive_before_tick = false;
        return;
    }
    const entry = creatures.entries[hint_ref];
    state.tutorial.hint_bonus_alive_before_tick = entry.active and entry.hp > 0.0;
}

pub fn transformPrimaryInput(
    state: *state_mod.GameplayState,
    input: player_runtime.GameInput,
) player_runtime.GameInput {
    state.tutorial.move_active_this_tick = input.move_x * input.move_x + input.move_y * input.move_y > 0.0;
    state.tutorial.fire_active_this_tick = input.flags.fire_pressed or input.flags.fire_down;
    return input;
}

fn overlayFromActions(
    overlay: *tutorial_state.TutorialOverlayState,
    actions: timeline.TutorialFrameActions,
) void {
    overlay.* = .{
        .prompt_stage_index = if (actions.prompt_alpha > 1e-3) actions.prompt_stage_index else -1,
        .prompt_alpha = actions.prompt_alpha,
        .hint_index = if (actions.hint_alpha > 1e-3) actions.hint_index else -1,
        .hint_alpha = actions.hint_alpha,
    };
}

pub fn postStep(
    state: *state_mod.GameplayState,
    players: []state_mod.PlayerState,
    creatures: *creatures_mod.CreaturePool,
    bonuses: *bonuses_mod.BonusPool,
    effects: *effects_mod.EffectPool,
    dt_sim_ms: i32,
    world_size: f32,
    detail_preset: i32,
) !void {
    const hint_ref = state.tutorial.hint_bonus_creature_ref;
    const hint_alive_after = if (hint_ref) |idx|
        idx < creatures.entries.len and creatures.entries[idx].active and creatures.entries[idx].hp > 0.0
    else
        false;
    const hint_bonus_died = state.tutorial.hint_bonus_alive_before_tick and !hint_alive_after;

    const result = timeline.tickTutorialTimeline(
        state.tutorial,
        dt_sim_ms,
        state.tutorial.move_active_this_tick,
        state.tutorial.fire_active_this_tick,
        creatures.activeCount() == 0,
        bonuses.activeCount() == 0,
        state.perk_selection.pending_count,
        hint_bonus_died,
    );
    state.tutorial = result.state;
    state.tutorial.move_active_this_tick = false;
    state.tutorial.fire_active_this_tick = false;
    state.tutorial.hint_bonus_alive_before_tick = false;
    overlayFromActions(&state.tutorial_overlay, result.actions);

    if (players.len > 0) {
        players[0].health = result.actions.force_player_health;
        if (result.actions.force_player_experience) |xp| {
            players[0].experience = xp;
            _ = survival_progression.survivalCheckLevelUp(&players[0], &state.perk_selection);
        }
    }
    if (result.actions.play_levelup_sfx) {
        state.sfx_queue.append(.ui_levelup);
    }

    for (result.actions.spawn_bonuses[0..result.actions.spawn_bonus_count], 0..) |call, index| {
        const spawned = bonuses.seedTutorialEntry(
            index,
            .{ .x = call.pos.x, .y = call.pos.y },
            call.bonus_id,
            call.amount,
        );
        effects.spawnBurst(
            state,
            spawned.pos,
            12,
            detail_preset,
            0.4,
            null,
            .{ .r = 1.0, .g = 1.0, .b = 1.0, .a = 1.0 },
        );
    }

    for (result.actions.spawn_templates[0..result.actions.spawn_template_count]) |call| {
        var active_before = [_]bool{false} ** creatures_mod.max_creatures;
        for (creatures.entries, 0..) |entry, idx| {
            active_before[idx] = entry.active;
        }

        try creatures.spawnTemplateCallWithRuntimeContext(call, &state.rng, state, world_size);
        if (!result.actions.stage5_bonus_carrier_drop_active) continue;
        if (call.template_id != @intFromEnum(spawn_mod.SpawnId.alien_bonus_carrier_27)) continue;

        for (&creatures.entries, 0..) |*entry, idx| {
            if (active_before[idx] or !entry.active) continue;
            entry.link_index = creatures_mod.packBonusOnDeathArgs(
                result.actions.stage5_bonus_carrier_drop_id,
                result.actions.stage5_bonus_carrier_drop_amount,
            );
            state.tutorial.hint_bonus_creature_ref = idx;
            break;
        }
    }
}
