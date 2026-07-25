const std = @import("std");
const game_ids = @import("../game_ids.zig");
const spawn_mod = @import("../runtime/spawn.zig");
const tutorial_state = @import("state.zig");

pub const tutorial_stage_count: usize = 9;
pub const tutorial_hint_count: usize = 7;
pub const max_tutorial_spawn_templates: usize = 12;
pub const max_tutorial_spawn_bonuses: usize = 4;

pub const BonusSpawnCall = struct {
    bonus_id: game_ids.BonusId,
    amount: i32,
    pos: spawn_mod.Vec2,
};

pub const TutorialFrameActions = struct {
    prompt_stage_index: i32 = -1,
    prompt_alpha: f32 = 0.0,
    hint_index: i32 = -1,
    hint_alpha: f32 = 0.0,
    spawn_template_count: usize = 0,
    spawn_templates: [max_tutorial_spawn_templates]spawn_mod.SpawnTemplateCall = [_]spawn_mod.SpawnTemplateCall{
        .{ .template_id = 0, .pos = .{ .x = 0.0, .y = 0.0 }, .heading = 0.0 },
    } ** max_tutorial_spawn_templates,
    spawn_bonus_count: usize = 0,
    spawn_bonuses: [max_tutorial_spawn_bonuses]BonusSpawnCall = [_]BonusSpawnCall{
        .{ .bonus_id = .unused, .amount = 0, .pos = .{ .x = 0.0, .y = 0.0 } },
    } ** max_tutorial_spawn_bonuses,
    stage5_bonus_carrier_drop_active: bool = false,
    stage5_bonus_carrier_drop_id: game_ids.BonusId = .unused,
    stage5_bonus_carrier_drop_amount: i32 = -1,
    play_levelup_sfx: bool = false,
    force_player_health: f32 = 100.0,
    force_player_experience: ?i32 = 0,

    fn appendSpawnTemplate(self: *TutorialFrameActions, call: spawn_mod.SpawnTemplateCall) void {
        if (self.spawn_template_count >= self.spawn_templates.len) return;
        self.spawn_templates[self.spawn_template_count] = call;
        self.spawn_template_count += 1;
    }

    fn appendSpawnBonus(self: *TutorialFrameActions, call: BonusSpawnCall) void {
        if (self.spawn_bonus_count >= self.spawn_bonuses.len) return;
        self.spawn_bonuses[self.spawn_bonus_count] = call;
        self.spawn_bonus_count += 1;
    }
};

const tutorial_stage_text = [_][]const u8{
    "In this tutorial you'll learn how to play Crimsonland",
    "First learn to move by pushing the arrow keys.",
    "Now pick up the bonuses by walking over them",
    "Now learn to shoot and move at the same time.\nClick the left Mouse button to shoot.",
    "Now, move the mouse to aim at the monsters",
    "It will help you to move and shoot and aim at the same time, so practice!",
    "Now let's learn about Perks. You can pick a Perk by clicking\nthe 'level up' sign at the upper right corner of the screen.",
    "Perks can give you extra abilities that help\nyou survive in Crimsonland.",
    "Great! Now you are ready to start playing Crimsonland!",
};

const tutorial_hint_text = [_][]const u8{
    "This is the speed powerup, it makes you move faster for\na limited amount of time.",
    "This is a weapon powerup. Picking it up gets\nyou another weapon. This one is a submachine gun.",
    "This powerup doubles all experience points gained when\nx2 powerup is active.",
    "This is the nuke powerup, picking it up causes a huge\nexplosion harming all monsters nearby!",
    "Reflex Boost powerup slows down time giving you a chance to react better",
    "",
    "",
};

const tutorial_hint_text_bugs = [_][]const u8{
    "This is the speed powerup, it makes you move faster for\na limited amount of time.",
    "This is a weapon powerup. Picking it you gets\nyou another weapon. This one is a submachine gun.",
    "This powerup doubles all experience points gained when\nx2 powerup is active.",
    "This is the nuke powerup, picking it up causes a huge\nexposion harming all monsters nearby!",
    "Reflex Boost powerup slows down time giving you a chance to react better",
    "",
    "",
};

pub fn promptText(stage_index: i32) []const u8 {
    if (stage_index < 0 or stage_index >= tutorial_stage_text.len) return "";
    return tutorial_stage_text[@intCast(stage_index)];
}

pub fn hintText(hint_index: i32, preserve_bugs: bool) []const u8 {
    if (hint_index < 0 or hint_index >= tutorial_hint_text.len) return "";
    return if (preserve_bugs)
        tutorial_hint_text_bugs[@intCast(hint_index)]
    else
        tutorial_hint_text[@intCast(hint_index)];
}

fn clamp01(value: f32) f32 {
    return std.math.clamp(value, @as(f32, 0.0), @as(f32, 1.0));
}

fn tickStageTransition(stage_index: i32, transition_timer_ms: i32, frame_dt_ms: i32) struct { stage_index: i32, transition_timer_ms: i32 } {
    var out_stage = stage_index;
    var out_timer = transition_timer_ms;

    if (out_timer < -1) {
        out_timer += frame_dt_ms;
        if (out_timer < -1) return .{ .stage_index = out_stage, .transition_timer_ms = out_timer };
        out_stage += 1;
        if (out_stage == tutorial_stage_count) out_stage = 0;
        out_timer = 0;
        return .{ .stage_index = out_stage, .transition_timer_ms = out_timer };
    }

    if (out_timer > -1) {
        out_timer += frame_dt_ms;
    }
    if (out_timer > 1000) out_timer = -1;
    return .{ .stage_index = out_stage, .transition_timer_ms = out_timer };
}

fn promptAlpha(stage_index: i32, stage_timer_ms: i32, transition_timer_ms: i32) f32 {
    if (stage_index < 0) return 0.0;

    var alpha: f32 = if (transition_timer_ms < -1)
        -@as(f32, @floatFromInt(transition_timer_ms)) * 0.001
    else if (transition_timer_ms < 0)
        1.0
    else
        @as(f32, @floatFromInt(transition_timer_ms)) * 0.001;

    if (stage_index == 5) {
        if (stage_timer_ms > 5000 and transition_timer_ms > -2) {
            alpha = 1.0 - @as(f32, @floatFromInt(stage_timer_ms - 5000)) * 0.001;
        }
        if (stage_timer_ms >= 0x1771) {
            alpha = 0.0;
        }
    }

    return clamp01(alpha);
}

pub fn tutorialStage5BonusCarrierConfig(repeat_spawn_count: i32) ?struct { bonus_id: game_ids.BonusId, amount: i32 } {
    return switch (repeat_spawn_count) {
        1 => .{ .bonus_id = .speed, .amount = -1 },
        2 => .{ .bonus_id = .weapon, .amount = 5 },
        3 => .{ .bonus_id = .double_experience, .amount = -1 },
        4 => .{ .bonus_id = .nuke, .amount = -1 },
        5 => .{ .bonus_id = .reflex_boost, .amount = -1 },
        else => null,
    };
}

fn buildTutorialStage3FireSpawns(actions: *TutorialFrameActions) void {
    const heading = std.math.pi;
    actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_const_green_24), .pos = .{ .x = -164.0, .y = 412.0 }, .heading = heading });
    actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_small_gray_26), .pos = .{ .x = -184.0, .y = 512.0 }, .heading = heading });
    actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_const_green_24), .pos = .{ .x = -154.0, .y = 612.0 }, .heading = heading });
}

fn buildTutorialStage4ClearSpawns(actions: *TutorialFrameActions) void {
    const heading = std.math.pi;
    actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_const_green_24), .pos = .{ .x = 1188.0, .y = 412.0 }, .heading = heading });
    actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_small_gray_26), .pos = .{ .x = 1208.0, .y = 512.0 }, .heading = heading });
    actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_const_green_24), .pos = .{ .x = 1178.0, .y = 612.0 }, .heading = heading });
}

fn buildTutorialStage5RepeatSpawns(actions: *TutorialFrameActions, repeat_spawn_count: i32) void {
    if (repeat_spawn_count < 1 or repeat_spawn_count >= 8) return;
    const heading = std.math.pi;
    if ((repeat_spawn_count & 1) == 0) {
        if (repeat_spawn_count < 6) {
            actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_bonus_carrier_27), .pos = .{ .x = 1056.0, .y = 1056.0 }, .heading = heading });
        }
        actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_const_green_24), .pos = .{ .x = 1188.0, .y = 1136.0 }, .heading = heading });
        actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_small_gray_26), .pos = .{ .x = 1208.0, .y = 512.0 }, .heading = heading });
        actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_const_green_24), .pos = .{ .x = 1178.0, .y = 612.0 }, .heading = heading });
        if (repeat_spawn_count == 4) {
            actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.spider_small_blue_40), .pos = .{ .x = 512.0, .y = 1056.0 }, .heading = heading });
        }
        return;
    }

    if (repeat_spawn_count < 6) {
        actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_bonus_carrier_27), .pos = .{ .x = -32.0, .y = 1056.0 }, .heading = heading });
    }
    buildTutorialStage3FireSpawns(actions);
}

fn buildTutorialStage6PerksDoneSpawns(actions: *TutorialFrameActions) void {
    const heading = std.math.pi;
    buildTutorialStage3FireSpawns(actions);
    actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_const_purple_28), .pos = .{ .x = -32.0, .y = -32.0 }, .heading = heading });
    buildTutorialStage4ClearSpawns(actions);
}

fn tickHint(
    state: *tutorial_state.TutorialState,
    actions: *TutorialFrameActions,
    frame_dt_ms: i32,
    hint_bonus_died: bool,
) void {
    const delta = frame_dt_ms * 3;
    if (!state.hint_fade_in) {
        if (hint_bonus_died) {
            state.hint_fade_in = true;
            state.hint_index += 1;
            actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_const_green_24), .pos = .{ .x = 128.0, .y = 128.0 }, .heading = std.math.pi });
            actions.appendSpawnTemplate(.{ .template_id = @intFromEnum(spawn_mod.SpawnId.alien_small_gray_26), .pos = .{ .x = 152.0, .y = 160.0 }, .heading = std.math.pi });
        }
        state.hint_alpha -= delta;
    } else {
        state.hint_alpha += delta;
    }
    state.hint_alpha = std.math.clamp(state.hint_alpha, @as(i32, 0), @as(i32, 1000));
    actions.hint_index = state.hint_index;
    actions.hint_alpha = if (hintText(state.hint_index, state.preserve_bugs).len == 0)
        0.0
    else
        @as(f32, @floatFromInt(state.hint_alpha)) * 0.001;
}

pub fn tickTutorialTimeline(
    state_in: tutorial_state.TutorialState,
    frame_dt_ms: i32,
    any_move_active: bool,
    any_fire_active: bool,
    creatures_none_active: bool,
    bonus_pool_empty: bool,
    perk_pending_count: i32,
    hint_bonus_died: bool,
) struct { state: tutorial_state.TutorialState, actions: TutorialFrameActions } {
    var state = state_in;
    state.stage_timer_ms += frame_dt_ms;

    const transition = tickStageTransition(state.stage_index, state.stage_transition_timer_ms, frame_dt_ms);
    state.stage_index = transition.stage_index;
    state.stage_transition_timer_ms = transition.transition_timer_ms;

    var actions: TutorialFrameActions = .{
        .prompt_stage_index = state.stage_index,
        .prompt_alpha = promptAlpha(state.stage_index, state.stage_timer_ms, state.stage_transition_timer_ms),
        .force_player_experience = if (state.stage_index == 6) null else 0,
    };
    if (state.stage_index == 6 and perk_pending_count < 1) {
        actions.prompt_alpha = 0.0;
    }

    tickHint(&state, &actions, frame_dt_ms, hint_bonus_died);

    switch (state.stage_index) {
        0 => {
            if (state.stage_timer_ms > 6000 and state.stage_transition_timer_ms == -1) {
                state.repeat_spawn_count = 0;
                state.hint_index = state.stage_transition_timer_ms;
                state.hint_fade_in = false;
                state.stage_transition_timer_ms = -1000;
            }
        },
        1 => {
            if (any_move_active and state.stage_transition_timer_ms == -1) {
                state.stage_transition_timer_ms = -1000;
                actions.play_levelup_sfx = true;
                actions.appendSpawnBonus(.{ .bonus_id = .points, .amount = 500, .pos = .{ .x = 260.0, .y = 260.0 } });
                actions.appendSpawnBonus(.{ .bonus_id = .points, .amount = 1000, .pos = .{ .x = 600.0, .y = 400.0 } });
                actions.appendSpawnBonus(.{ .bonus_id = .points, .amount = 500, .pos = .{ .x = 300.0, .y = 400.0 } });
            }
        },
        2 => {
            if (bonus_pool_empty and state.stage_transition_timer_ms == -1) {
                state.stage_transition_timer_ms = -1000;
                actions.play_levelup_sfx = true;
            }
        },
        3 => {
            if (any_fire_active and state.stage_transition_timer_ms == -1) {
                state.stage_transition_timer_ms = -1000;
                actions.play_levelup_sfx = true;
                buildTutorialStage3FireSpawns(&actions);
            }
        },
        4 => {
            if (creatures_none_active and state.stage_transition_timer_ms == -1) {
                state.stage_timer_ms = 1000;
                state.stage_transition_timer_ms = -1000;
                actions.play_levelup_sfx = true;
                state.repeat_spawn_count = 0;
                buildTutorialStage4ClearSpawns(&actions);
            }
        },
        5 => {
            if (bonus_pool_empty and creatures_none_active) {
                state.repeat_spawn_count += 1;
                if (state.repeat_spawn_count < 8) {
                    state.hint_fade_in = false;
                    state.hint_bonus_creature_ref = null;
                    buildTutorialStage5RepeatSpawns(&actions, state.repeat_spawn_count);
                    if (tutorialStage5BonusCarrierConfig(state.repeat_spawn_count)) |drop| {
                        actions.stage5_bonus_carrier_drop_active = true;
                        actions.stage5_bonus_carrier_drop_id = drop.bonus_id;
                        actions.stage5_bonus_carrier_drop_amount = drop.amount;
                    }
                } else if (state.stage_transition_timer_ms == -1) {
                    state.stage_transition_timer_ms = -1000;
                    actions.play_levelup_sfx = true;
                    actions.force_player_experience = 3000;
                }
            }
        },
        6 => {
            if (perk_pending_count < 1 and state.stage_transition_timer_ms == -1) {
                state.stage_transition_timer_ms = -1000;
                buildTutorialStage6PerksDoneSpawns(&actions);
            }
        },
        7 => {
            if (bonus_pool_empty and creatures_none_active and state.stage_transition_timer_ms == -1) {
                state.stage_transition_timer_ms = -1000;
            }
        },
        else => {},
    }

    return .{
        .state = state,
        .actions = actions,
    };
}

test "tutorial copy preserves the native script" {
    try std.testing.expectEqualStrings(
        "It will help you to move and shoot and aim at the same time, so practice!",
        promptText(5),
    );
    try std.testing.expectEqualStrings(
        "Now let's learn about Perks. You can pick a Perk by clicking\nthe 'level up' sign at the upper right corner of the screen.",
        promptText(6),
    );
    try std.testing.expectEqualStrings(
        "Perks can give you extra abilities that help\nyou survive in Crimsonland.",
        promptText(7),
    );
    try std.testing.expectEqualStrings(
        "Great! Now you are ready to start playing Crimsonland!",
        promptText(8),
    );

    try std.testing.expectEqualStrings(
        "This is the speed powerup, it makes you move faster for\na limited amount of time.",
        hintText(0, true),
    );
    try std.testing.expectEqualStrings(
        "This is a weapon powerup. Picking it you gets\nyou another weapon. This one is a submachine gun.",
        hintText(1, true),
    );
    try std.testing.expectEqualStrings(
        "This powerup doubles all experience points gained when\nx2 powerup is active.",
        hintText(2, true),
    );
    try std.testing.expectEqualStrings(
        "This is the nuke powerup, picking it up causes a huge\nexposion harming all monsters nearby!",
        hintText(3, true),
    );
    try std.testing.expectEqualStrings(
        "This is a weapon powerup. Picking it up gets\nyou another weapon. This one is a submachine gun.",
        hintText(1, false),
    );
    try std.testing.expectEqualStrings(
        "This is the nuke powerup, picking it up causes a huge\nexplosion harming all monsters nearby!",
        hintText(3, false),
    );
}

test "tutorial stage 1 movement spawns three point bonuses" {
    const result = tickTutorialTimeline(.{
        .stage_index = 1,
        .stage_transition_timer_ms = -1,
    }, 16, true, false, false, false, 0, false);
    try std.testing.expectEqual(@as(usize, 3), result.actions.spawn_bonus_count);
    try std.testing.expect(result.actions.play_levelup_sfx);
}

test "tutorial hint fade changes direction after the carrier death frame" {
    var state: tutorial_state.TutorialState = .{
        .hint_index = -1,
        .hint_alpha = 300,
        .hint_fade_in = false,
    };
    var actions: TutorialFrameActions = .{};

    tickHint(&state, &actions, 16, true);
    try std.testing.expect(state.hint_fade_in);
    try std.testing.expectEqual(@as(i32, 0), state.hint_index);
    try std.testing.expectEqual(@as(i32, 252), state.hint_alpha);
    try std.testing.expectEqual(@as(usize, 2), actions.spawn_template_count);

    actions = .{};
    tickHint(&state, &actions, 16, false);
    try std.testing.expectEqual(@as(i32, 300), state.hint_alpha);
    try std.testing.expectEqual(@as(usize, 0), actions.spawn_template_count);
}
