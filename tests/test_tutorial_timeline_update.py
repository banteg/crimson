from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.tutorial.timeline import TutorialState, tick_tutorial_timeline, tutorial_stage5_bonus_carrier_config


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
        (int(BonusId.POINTS), 500, (260.0, 260.0)),
        (int(BonusId.POINTS), 1000, (600.0, 400.0)),
        (int(BonusId.POINTS), 500, (300.0, 400.0)),
    ]


def test_stage5_bonus_carrier_config() -> None:
    assert tutorial_stage5_bonus_carrier_config(1) == (int(BonusId.SPEED), -1)
    assert tutorial_stage5_bonus_carrier_config(2) == (int(BonusId.WEAPON), 5)
    assert tutorial_stage5_bonus_carrier_config(3) == (int(BonusId.DOUBLE_EXPERIENCE), -1)
    assert tutorial_stage5_bonus_carrier_config(4) == (int(BonusId.NUKE), -1)
    assert tutorial_stage5_bonus_carrier_config(5) == (int(BonusId.REFLEX_BOOST), -1)
    assert tutorial_stage5_bonus_carrier_config(0) is None
    assert tutorial_stage5_bonus_carrier_config(6) is None


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

