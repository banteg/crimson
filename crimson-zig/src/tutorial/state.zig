pub const TutorialState = struct {
    stage_index: i32 = -1,
    stage_timer_ms: i32 = 0,
    stage_transition_timer_ms: i32 = -1000,
    hint_index: i32 = -1,
    hint_alpha: i32 = 0,
    hint_fade_in: bool = false,
    repeat_spawn_count: i32 = 0,
    hint_bonus_creature_ref: ?usize = null,
    preserve_bugs: bool = false,
    move_active_this_tick: bool = false,
    fire_active_this_tick: bool = false,
    hint_bonus_alive_before_tick: bool = false,
};

pub const TutorialOverlayState = struct {
    prompt_stage_index: i32 = -1,
    prompt_alpha: f32 = 0.0,
    hint_index: i32 = -1,
    hint_alpha: f32 = 0.0,
};

pub fn resetTutorialState(
    tutorial: *TutorialState,
    overlay: *TutorialOverlayState,
    preserve_bugs: bool,
) void {
    tutorial.* = .{
        .preserve_bugs = preserve_bugs,
    };
    overlay.* = .{};
}
