from __future__ import annotations

import msgspec


class TutorialState(msgspec.Struct):
    stage_index: int = -1
    stage_timer_ms: int = 0
    stage_transition_timer_ms: int = -1000
    hint_index: int = -1
    hint_alpha: int = 0
    hint_fade_in: bool = False
    repeat_spawn_count: int = 0
    hint_bonus_creature_ref: int | None = None
    preserve_bugs: bool = False
    move_active_this_tick: bool = False
    fire_active_this_tick: bool = False
    hint_bonus_alive_before_tick: bool = False


class TutorialOverlayState(msgspec.Struct):
    prompt_text: str = ""
    prompt_alpha: float = 0.0
    hint_text: str = ""
    hint_alpha: float = 0.0


def reset_tutorial_state(
    tutorial: TutorialState,
    overlay: TutorialOverlayState,
    *,
    preserve_bugs: bool,
) -> None:
    tutorial.stage_index = -1
    tutorial.stage_timer_ms = 0
    tutorial.stage_transition_timer_ms = -1000
    tutorial.hint_index = -1
    tutorial.hint_alpha = 0
    tutorial.hint_fade_in = False
    tutorial.repeat_spawn_count = 0
    tutorial.hint_bonus_creature_ref = None
    tutorial.preserve_bugs = bool(preserve_bugs)
    tutorial.move_active_this_tick = False
    tutorial.fire_active_this_tick = False
    tutorial.hint_bonus_alive_before_tick = False
    overlay.prompt_text = ""
    overlay.prompt_alpha = 0.0
    overlay.hint_text = ""
    overlay.hint_alpha = 0.0
