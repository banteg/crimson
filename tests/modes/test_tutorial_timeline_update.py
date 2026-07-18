from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.tutorial.timeline import TutorialState, tick_tutorial_timeline, tutorial_stage5_bonus_carrier_config
from grim.geom import Vec2


def test_stage_transition_advances_from_bootstrap() -> None:
    state = TutorialState(stage_index=-1, stage_timer_ms=0, stage_transition_timer_ms=-1000)
    state, _actions = tick_tutorial_timeline(
        state,
        frame_dt_ms=1000.0,
        any_move_active=False,
        any_fire_active=False,
        creatures_none_active=True,
        bonus_pool_empty=True,
        perk_pending_count=0,
    )
    assert state.stage_index == 0
    assert state.stage_transition_timer_ms == 0


def test_stage0_triggers_after_6000ms() -> None:
    state = TutorialState(stage_index=0, stage_timer_ms=6001, stage_transition_timer_ms=-1, hint_index=2, hint_alpha=1000, hint_fade_in=True)
    state, actions = tick_tutorial_timeline(
        state,
        frame_dt_ms=16.0,
        any_move_active=False,
        any_fire_active=False,
        creatures_none_active=True,
        bonus_pool_empty=True,
        perk_pending_count=0,
    )
    assert state.stage_transition_timer_ms == -1000
    assert state.repeat_spawn_count == 0
    assert state.hint_index == -1
    assert state.hint_fade_in is False
    assert actions.play_levelup_sfx is False


def test_stage1_move_spawns_point_bonuses() -> None:
    state = TutorialState(stage_index=1, stage_timer_ms=0, stage_transition_timer_ms=-1)
    state, actions = tick_tutorial_timeline(
        state,
        frame_dt_ms=16.0,
        any_move_active=True,
        any_fire_active=False,
        creatures_none_active=True,
        bonus_pool_empty=True,
        perk_pending_count=0,
    )
    assert state.stage_transition_timer_ms == -1000
    assert actions.play_levelup_sfx is True
    assert [(c.bonus_id, c.amount, c.pos) for c in actions.spawn_bonuses] == [
        (BonusId.POINTS, 500, Vec2(260.0, 260.0)),
        (BonusId.POINTS, 1000, Vec2(600.0, 400.0)),
        (BonusId.POINTS, 500, Vec2(300.0, 400.0)),
    ]


def test_stage5_bonus_carrier_config() -> None:
    assert tutorial_stage5_bonus_carrier_config(1) == (BonusId.SPEED, -1)
    assert tutorial_stage5_bonus_carrier_config(2) == (BonusId.WEAPON, 5)
    assert tutorial_stage5_bonus_carrier_config(3) == (BonusId.DOUBLE_EXPERIENCE, -1)
    assert tutorial_stage5_bonus_carrier_config(4) == (BonusId.NUKE, -1)
    assert tutorial_stage5_bonus_carrier_config(5) == (BonusId.REFLEX_BOOST, -1)
    assert tutorial_stage5_bonus_carrier_config(0) is None
    assert tutorial_stage5_bonus_carrier_config(6) is None


@pytest.mark.parametrize(
    ("hint_index", "fixed_text", "bugged_text"),
    [
        (
            1,
            "This is a weapon powerup. Picking it up gives you a new weapon.",
            "This is a weapon powerup. Picking it you gets a new weapon.",
        ),
        (
            3,
            "This is the nuke powerup, picking it up causes a huge\nexplosion harming all monsters nearby!",
            "This is the nuke powerup, picking it up causes a huge\nexposion harming all monsters nearby!",
        ),
    ],
)
def test_hint_text_respects_preserve_bugs(hint_index: int, fixed_text: str, bugged_text: str) -> None:
    base = TutorialState(
        stage_index=0,
        stage_timer_ms=0,
        stage_transition_timer_ms=-1,
        hint_index=hint_index,
        hint_alpha=1000,
        hint_fade_in=True,
    )
    _fixed_state, fixed_actions = tick_tutorial_timeline(
        base,
        frame_dt_ms=0.0,
        any_move_active=False,
        any_fire_active=False,
        creatures_none_active=True,
        bonus_pool_empty=True,
        perk_pending_count=0,
    )
    bugged = TutorialState(
        stage_index=0,
        stage_timer_ms=0,
        stage_transition_timer_ms=-1,
        hint_index=hint_index,
        hint_alpha=1000,
        hint_fade_in=True,
        preserve_bugs=True,
    )
    _bug_state, bug_actions = tick_tutorial_timeline(
        bugged,
        frame_dt_ms=0.0,
        any_move_active=False,
        any_fire_active=False,
        creatures_none_active=True,
        bonus_pool_empty=True,
        perk_pending_count=0,
    )
    assert fixed_actions.hint_text == fixed_text
    assert bug_actions.hint_text == bugged_text


@pytest.mark.parametrize("repeat", [1, 2, 5])
def test_stage5_emits_bonus_carrier_drop_for_first_repeats(repeat: int) -> None:
    state = TutorialState(stage_index=5, stage_timer_ms=0, stage_transition_timer_ms=-1, repeat_spawn_count=repeat - 1)
    _state, actions = tick_tutorial_timeline(
        state,
        frame_dt_ms=16.0,
        any_move_active=False,
        any_fire_active=False,
        creatures_none_active=True,
        bonus_pool_empty=True,
        perk_pending_count=0,
    )
    assert actions.stage5_bonus_carrier_drop == tutorial_stage5_bonus_carrier_config(repeat)


def test_hint_carrier_death_keeps_native_one_frame_fade_out() -> None:
    state = TutorialState(
        stage_index=5,
        stage_timer_ms=0,
        stage_transition_timer_ms=-1,
        hint_index=-1,
        hint_alpha=600,
        hint_fade_in=False,
    )
    state, actions = tick_tutorial_timeline(
        state,
        frame_dt_ms=100.0,
        any_move_active=False,
        any_fire_active=False,
        creatures_none_active=False,
        bonus_pool_empty=False,
        perk_pending_count=0,
        hint_bonus_died=True,
    )

    assert state.hint_fade_in is True
    assert state.hint_index == 0
    assert state.hint_alpha == 300
    assert actions.hint_alpha == pytest.approx(0.3)

    state, actions = tick_tutorial_timeline(
        state,
        frame_dt_ms=100.0,
        any_move_active=False,
        any_fire_active=False,
        creatures_none_active=False,
        bonus_pool_empty=False,
        perk_pending_count=0,
    )
    assert state.hint_alpha == 600
    assert actions.hint_alpha == pytest.approx(0.6)
