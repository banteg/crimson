from __future__ import annotations

from dataclasses import dataclass, replace

from ..bonuses import BonusId
from ..creatures.spawn import (
    SpawnTemplateCall,
    build_tutorial_stage3_fire_spawns,
    build_tutorial_stage4_clear_spawns,
    build_tutorial_stage5_repeat_spawns,
    build_tutorial_stage6_perks_done_spawns,
)

_TUTORIAL_STAGE_TEXT: tuple[str, ...] = (
    "In this tutorial you'll learn how to play Crimsonland",
    "First learn to move by pushing the arrow keys.",
    "Now pick up the bonuses by walking over them",
    "Now learn to shoot and move at the same time.\nClick the left Mouse button to shoot.",
    "Now, move the mouse to aim at the monsters",
    "It will help you to move and shoot at the same time. Just keep moving!",
    "Now let's learn about Perks. You'll receive a perk when you gain enough experience points.",
    "Perks can give you extra abilities, or boost your skills. Choose wisely!",
    "Great! Now you are ready to start playing Crimsonland",
)

_TUTORIAL_HINT_TEXT: tuple[str, ...] = (
    "This is the speed powerup, it makes you move faster!",
    "This is a weapon powerup. Picking it up gives you a new weapon.",
    "This powerup doubles all experience points you gain while it's active.",
    "This is the nuke powerup, picking it up causes a huge\nexposion harming all monsters nearby!",
    "Reflex Boost powerup slows down time giving you a chance to react better",
    "",
    "",
)


@dataclass(slots=True)
class TutorialState:
    stage_index: int = -1
    stage_timer_ms: int = 0
    stage_transition_timer_ms: int = -1000
    hint_index: int = -1
    hint_alpha: int = 0
    hint_fade_in: bool = False
    repeat_spawn_count: int = 0
    hint_bonus_creature_ref: int | None = None


@dataclass(frozen=True, slots=True)
class BonusSpawnCall:
    bonus_id: int
    amount: int
    pos: tuple[float, float]


@dataclass(frozen=True, slots=True)
class TutorialFrameActions:
    prompt_text: str = ""
    prompt_alpha: float = 0.0
    hint_text: str = ""
    hint_alpha: float = 0.0
    spawn_templates: tuple[SpawnTemplateCall, ...] = ()
    spawn_bonuses: tuple[BonusSpawnCall, ...] = ()
    stage5_bonus_carrier_drop: tuple[int, int] | None = None
    play_levelup_sfx: bool = False
    force_player_health: float = 100.0
    force_player_experience: int | None = None


def tutorial_stage5_bonus_carrier_config(repeat_spawn_count: int) -> tuple[int, int] | None:
    """Return the (bonus_id, amount_override) applied to the stage-5 bonus carrier for this repeat count.

    This reproduces the packed bonus-arg writes to `tutorial_hint_bonus_ptr` in `tutorial_timeline_update`.

    - amount_override == -1 means "use the bonus meta default".
    - For weapon bonuses, amount_override is the weapon id.
    """
    n = int(repeat_spawn_count)
    if n == 1:
        return int(BonusId.SPEED), -1
    if n == 2:
        return int(BonusId.WEAPON), 5
    if n == 3:
        return int(BonusId.DOUBLE_EXPERIENCE), -1
    if n == 4:
        return int(BonusId.NUKE), -1
    if n == 5:
        return int(BonusId.REFLEX_BOOST), -1
    return None


def _clamp01(value: float) -> float:
    if value <= 0.0:
        return 0.0
    if value >= 1.0:
        return 1.0
    return float(value)


def _tick_stage_transition(stage_index: int, transition_timer_ms: int, *, frame_dt_ms: int) -> tuple[int, int]:
    stage_index = int(stage_index)
    transition_timer_ms = int(transition_timer_ms)
    dt_ms = int(frame_dt_ms)

    if transition_timer_ms < -1:
        transition_timer_ms += dt_ms
        if transition_timer_ms < -1:
            return stage_index, transition_timer_ms
        stage_index += 1
        if stage_index == 9:
            stage_index = 0
        transition_timer_ms = 0
        return stage_index, transition_timer_ms

    if -1 < transition_timer_ms:
        transition_timer_ms += dt_ms
    if 1000 < transition_timer_ms:
        transition_timer_ms = -1
    return stage_index, transition_timer_ms


def _prompt_alpha(*, stage_index: int, stage_timer_ms: int, transition_timer_ms: int) -> float:
    stage_index = int(stage_index)
    stage_timer_ms = int(stage_timer_ms)
    transition_timer_ms = int(transition_timer_ms)

    if stage_index < 0:
        return 0.0

    if transition_timer_ms < -1:
        alpha = float(-transition_timer_ms) * 0.001
    elif transition_timer_ms < 0:
        alpha = 1.0
    else:
        alpha = float(transition_timer_ms) * 0.001

    if stage_index == 5:
        if stage_timer_ms > 5000 and transition_timer_ms > -2:
            alpha = 1.0 - float(stage_timer_ms - 5000) * 0.001
        if stage_timer_ms >= 0x1771:
            alpha = 0.0

    return _clamp01(alpha)


def _tick_hint(state: TutorialState, *, frame_dt_ms: int, hint_bonus_died: bool) -> tuple[tuple[SpawnTemplateCall, ...], str, float]:
    hint_spawns: list[SpawnTemplateCall] = []

    if (not state.hint_fade_in) and bool(hint_bonus_died):
        state.hint_fade_in = True
        state.hint_index = int(state.hint_index) + 1
        hint_spawns.extend(
            (
                SpawnTemplateCall(template_id=0x24, pos=(128.0, 128.0), heading=3.1415927),
                SpawnTemplateCall(template_id=0x26, pos=(152.0, 160.0), heading=3.1415927),
            )
        )

    delta = int(frame_dt_ms) * 3
    state.hint_alpha = int(state.hint_alpha) + (delta if state.hint_fade_in else -delta)
    if state.hint_alpha < 0:
        state.hint_alpha = 0
    elif state.hint_alpha > 1000:
        state.hint_alpha = 1000

    idx = int(state.hint_index)
    text = _TUTORIAL_HINT_TEXT[idx] if 0 <= idx < len(_TUTORIAL_HINT_TEXT) else ""
    alpha = float(state.hint_alpha) * 0.001 if text else 0.0
    return tuple(hint_spawns), text, _clamp01(alpha)


def tick_tutorial_timeline(
    state: TutorialState,
    *,
    frame_dt_ms: float,
    any_move_active: bool,
    any_fire_active: bool,
    creatures_none_active: bool,
    bonus_pool_empty: bool,
    perk_pending_count: int,
    hint_bonus_died: bool = False,
) -> tuple[TutorialState, TutorialFrameActions]:
    """Pure model of the tutorial director (`tutorial_timeline_update` / 0x00408990).

    Notes:
    - The returned UI model (prompt/hint text+alpha) reflects the state *before* any stage triggers
      applied by this tick. The returned state reflects the post-trigger values for the next frame.
    """
    dt_ms = int(float(frame_dt_ms))
    state = replace(state)
    state.stage_timer_ms = int(state.stage_timer_ms) + dt_ms

    stage_index, transition_timer_ms = _tick_stage_transition(state.stage_index, state.stage_transition_timer_ms, frame_dt_ms=dt_ms)
    state.stage_index = int(stage_index)
    state.stage_transition_timer_ms = int(transition_timer_ms)

    prompt_text = _TUTORIAL_STAGE_TEXT[stage_index] if 0 <= stage_index < len(_TUTORIAL_STAGE_TEXT) else ""
    prompt_alpha = _prompt_alpha(stage_index=stage_index, stage_timer_ms=state.stage_timer_ms, transition_timer_ms=transition_timer_ms)
    if stage_index == 6 and int(perk_pending_count) < 1:
        prompt_text = ""
        prompt_alpha = 0.0

    hint_spawns, hint_text, hint_alpha = _tick_hint(state, frame_dt_ms=dt_ms, hint_bonus_died=bool(hint_bonus_died))

    actions = TutorialFrameActions(
        prompt_text=prompt_text,
        prompt_alpha=prompt_alpha,
        hint_text=hint_text,
        hint_alpha=hint_alpha,
        spawn_templates=hint_spawns,
        spawn_bonuses=(),
        stage5_bonus_carrier_drop=None,
        play_levelup_sfx=False,
        force_player_health=100.0,
        force_player_experience=0 if stage_index != 6 else None,
    )

    spawn_templates: list[SpawnTemplateCall] = list(actions.spawn_templates)
    spawn_bonuses: list[BonusSpawnCall] = []
    play_levelup_sfx = False
    stage5_bonus_carrier_drop: tuple[int, int] | None = None
    force_experience = actions.force_player_experience

    if stage_index == 0:
        if state.stage_timer_ms > 6000 and state.stage_transition_timer_ms == -1:
            state.repeat_spawn_count = 0
            state.hint_index = int(state.stage_transition_timer_ms)
            state.hint_fade_in = False
            state.stage_transition_timer_ms = -1000
    elif stage_index == 1:
        if bool(any_move_active) and state.stage_transition_timer_ms == -1:
            state.stage_transition_timer_ms = -1000
            play_levelup_sfx = True
            spawn_bonuses.extend(
                (
                    BonusSpawnCall(bonus_id=int(BonusId.POINTS), amount=500, pos=(260.0, 260.0)),
                    BonusSpawnCall(bonus_id=int(BonusId.POINTS), amount=1000, pos=(600.0, 400.0)),
                    BonusSpawnCall(bonus_id=int(BonusId.POINTS), amount=500, pos=(300.0, 400.0)),
                )
            )
    elif stage_index == 2:
        if bool(bonus_pool_empty) and state.stage_transition_timer_ms == -1:
            state.stage_transition_timer_ms = -1000
            play_levelup_sfx = True
    elif stage_index == 3:
        if bool(any_fire_active) and state.stage_transition_timer_ms == -1:
            state.stage_transition_timer_ms = -1000
            play_levelup_sfx = True
            spawn_templates.extend(build_tutorial_stage3_fire_spawns())
    elif stage_index == 4:
        if bool(creatures_none_active) and state.stage_transition_timer_ms == -1:
            state.stage_timer_ms = 1000
            state.stage_transition_timer_ms = -1000
            play_levelup_sfx = True
            state.repeat_spawn_count = 0
            spawn_templates.extend(build_tutorial_stage4_clear_spawns())
    elif stage_index == 5:
        if bool(bonus_pool_empty) and bool(creatures_none_active):
            state.repeat_spawn_count = int(state.repeat_spawn_count) + 1
            if int(state.repeat_spawn_count) < 8:
                state.hint_fade_in = False
                state.hint_bonus_creature_ref = None
                spawn_templates.extend(build_tutorial_stage5_repeat_spawns(int(state.repeat_spawn_count)))
                stage5_bonus_carrier_drop = tutorial_stage5_bonus_carrier_config(int(state.repeat_spawn_count))
            elif state.stage_transition_timer_ms == -1:
                state.stage_transition_timer_ms = -1000
                play_levelup_sfx = True
                force_experience = 3000
    elif stage_index == 6:
        if int(perk_pending_count) < 1 and state.stage_transition_timer_ms == -1:
            state.stage_transition_timer_ms = -1000
            spawn_templates.extend(build_tutorial_stage6_perks_done_spawns())
    elif stage_index == 7:
        if bool(bonus_pool_empty) and bool(creatures_none_active) and state.stage_transition_timer_ms == -1:
            state.stage_transition_timer_ms = -1000

    return (
        state,
        TutorialFrameActions(
            prompt_text=actions.prompt_text,
            prompt_alpha=actions.prompt_alpha,
            hint_text=actions.hint_text,
            hint_alpha=actions.hint_alpha,
            spawn_templates=tuple(spawn_templates),
            spawn_bonuses=tuple(spawn_bonuses),
            stage5_bonus_carrier_drop=stage5_bonus_carrier_drop,
            play_levelup_sfx=bool(play_levelup_sfx),
            force_player_health=actions.force_player_health,
            force_player_experience=force_experience,
        ),
    )
