from __future__ import annotations

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import PerkPickCommand
from crimson.sim.presentation_reactions import (
    PostApplyReaction,
    QuestPresentationReaction,
    apply_post_apply_reaction,
)
from tests.support.builders.session import make_session


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


def test_quest_presentation_reaction_tracks_audio_flags() -> None:
    reaction = QuestPresentationReaction(
        play_hit_sfx=True,
        play_completion_music=True,
    )

    assert reaction.play_hit_sfx is True
    assert reaction.play_completion_music is True


def test_apply_post_apply_reaction_applies_sfx_and_completion_music() -> None:
    play_sfx = []
    play_completion_music = []

    apply_post_apply_reaction(
        reaction=PostApplyReaction(
            sfx_keys=("sfx_ui_bonus",),
            quest=QuestPresentationReaction(
                play_hit_sfx=True,
                play_completion_music=True,
            ),
        ),
        play_sfx=lambda key: play_sfx.append(str(key)),
        play_completion_music=lambda: play_completion_music.append("crimsonquest"),
    )

    assert play_sfx == ["sfx_ui_bonus", "sfx_questhit"]
    assert play_completion_music == ["crimsonquest"]
