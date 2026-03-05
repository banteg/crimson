from __future__ import annotations

from builders.session import make_session

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import PerkPickCommand
from crimson.sim.presentation_reactions import (
    PostApplyReaction,
    apply_post_apply_reaction,
    resolve_quest_presentation_reaction,
)
from crimson.sim.sessions import QuestSpawnState


def test_session_step_tick_adds_bonus_post_apply_sfx_for_successful_perk_pick() -> None:
    session, sim_world = make_session()
    sim_world.state.perk_selection.pending_count = 1

    tick = session.step_tick(
        timing=session.timing_for_dt(1.0 / 60.0),
        inputs=[PlayerInput()],
        commands=[PerkPickCommand(player_index=0, choice_index=0)],
    )

    assert tick.step.post_apply_sfx_keys == ("sfx_ui_bonus",)


def test_session_step_tick_skips_bonus_post_apply_sfx_for_stale_perk_pick() -> None:
    session, _sim_world = make_session()

    tick = session.step_tick(
        timing=session.timing_for_dt(1.0 / 60.0),
        inputs=[PlayerInput()],
        commands=[PerkPickCommand(player_index=0, choice_index=0)],
    )

    assert tick.step.post_apply_sfx_keys == ()


def test_resolve_quest_presentation_reaction_updates_timer_and_flags() -> None:
    reaction = resolve_quest_presentation_reaction(
        QuestSpawnState(
            spawn_timeline_ms=444.0,
            completion_transition_ms=222.0,
            play_hit_sfx=True,
            play_completion_music=True,
        ),
        dt_seconds=1.0 / 60.0,
        current_name_timer_ms=10.0,
    )

    assert reaction.spawn_timeline_ms == 444.0
    assert reaction.completion_transition_ms == 222.0
    assert reaction.name_timer_ms == 10.0 + (1000.0 / 60.0)
    assert reaction.play_hit_sfx is True
    assert reaction.play_completion_music is True


def test_apply_post_apply_reaction_applies_sfx_and_completion_music() -> None:
    play_sfx = []
    play_completion_music = []
    quest_reactions = []

    apply_post_apply_reaction(
        reaction=PostApplyReaction(
            sfx_keys=("sfx_ui_bonus",),
            quest=resolve_quest_presentation_reaction(
                QuestSpawnState(
                    spawn_timeline_ms=444.0,
                    completion_transition_ms=222.0,
                    play_hit_sfx=True,
                    play_completion_music=True,
                ),
                dt_seconds=1.0 / 60.0,
                current_name_timer_ms=0.0,
            ),
        ),
        play_sfx=lambda key: play_sfx.append(str(key)),
        play_completion_music=lambda: play_completion_music.append("crimsonquest"),
        on_quest_reaction=lambda reaction: quest_reactions.append(reaction),
    )

    assert play_sfx == ["sfx_ui_bonus", "sfx_questhit"]
    assert play_completion_music == ["crimsonquest"]
    assert len(quest_reactions) == 1
