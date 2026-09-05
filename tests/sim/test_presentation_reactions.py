from __future__ import annotations

import pytest

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import PerkPickCommand
from crimson.sim.presentation_step import DeterministicPresentationPlan
from crimson.sim.session_builders import build_quest_session
from crimson.sim.tick_runner import TickRunner
from crimson.world import audio_bridge
from crimson.world.audio_bridge import AudioBridge
from crimson.world.sim_world_state import SimWorldState
from grim.audio import AudioState
from grim.music import init_music_state
from grim.rand import Crand
from grim.sfx import init_sfx_state
from grim.sfx_map import SfxId
from tests.support.builders.input_providers import ReadyTickInputProvider
from tests.support.builders.session import make_session


def test_session_step_tick_adds_bonus_post_apply_sfx_for_successful_perk_pick() -> None:
    session, sim_world = make_session()
    sim_world.state.perk_selection.pending_count = 1

    tick = session.step_tick(
        dt=1.0 / 60.0,
        inputs=[PlayerInput()],
        commands=[PerkPickCommand(player_index=0, choice_index=0)],
    )

    assert tick.presentation.post_apply_sfx == (SfxId.UI_BONUS,)


def test_session_step_tick_skips_bonus_post_apply_sfx_for_stale_perk_pick() -> None:
    session, _sim_world = make_session()

    tick = session.step_tick(
        dt=1.0 / 60.0,
        inputs=[PlayerInput()],
        commands=[PerkPickCommand(player_index=0, choice_index=0)],
    )

    assert tick.presentation.post_apply_sfx == ()


@pytest.mark.parametrize(
    ("start_ms", "expected_hit", "expected_music"),
    [
        (810.0, [True, False], [False, False]),
        (790.0, [False, True], [False, False]),
        (2001.0, [False, False], [True, False]),
    ],
)
@pytest.mark.parametrize("ticks_per_frame", [(0, 1, 0, 1), (1, 1), (2,)])
def test_quest_audio_requests_survive_render_partitions(
    start_ms, expected_hit, expected_music, ticks_per_frame,
) -> None:
    sim = SimWorldState()
    session, spawn = build_quest_session(
        world=sim.world_state,
        world_size=1024.0,
        damage_scale_by_type=sim.damage_scale_by_type,
        detail_preset=5,
        violence_disabled=0,
        game_tune_started=False,
        demo_mode_active=False,
        apply_world_dt_steps=True,
        finalize_post_render_lifecycle=True,
        spawn_entries=(),
        quest_level=None,
        start_weapon_id=None,
    )
    spawn.completion_transition_ms = start_ms
    runner = TickRunner(session=session, input_provider=ReadyTickInputProvider(inputs=(PlayerInput(),)))
    outputs = []
    tick_index = 0
    for tick_count in ticks_per_frame:
        batch = runner.advance_ticks(start_tick=tick_index, ticks_requested=tick_count, tick_dt=1 / 60)
        outputs.extend(row.payload.presentation for row in batch.completed_results)
        tick_index = batch.next_tick_index
    # Read after all frames: these outputs must not consult the mutated quest state.
    assert [SfxId.QUESTHIT in output.post_apply_sfx for output in outputs] == expected_hit
    assert [output.play_quest_completion_music for output in outputs] == expected_music


def test_shared_audio_sink_applies_post_tick_sfx_and_quest_music(mocker) -> None:
    audio = AudioState(
        ready=False,
        music=init_music_state(ready=False, enabled=True, volume=1.0),
        sfx=init_sfx_state(ready=False, enabled=True, volume=1.0),
    )
    bridge = AudioBridge(audio_rng=Crand(1), audio=audio)
    play_sfx = mocker.patch.object(type(bridge.router), "play_sfx")
    play_music = mocker.patch.object(audio_bridge, "play_music")
    plan = DeterministicPresentationPlan(
        post_apply_sfx=(SfxId.UI_BONUS, SfxId.QUESTHIT),
        play_quest_completion_music=True,
    )
    bridge.apply_post_plan(plan=plan, apply_audio=False)
    play_sfx.assert_not_called()
    play_music.assert_not_called()
    bridge.apply_post_plan(plan=plan)
    assert [call.args[0] for call in play_sfx.call_args_list] == [SfxId.UI_BONUS, SfxId.QUESTHIT]
    play_music.assert_called_once_with(audio, "crimsonquest")
