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
    start_ms,
    expected_hit,
    expected_music,
    ticks_per_frame,
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
    play_sfx = mocker.patch.object(type(bridge), "play_sfx")
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
    play_music.assert_called_once_with(audio, "crimsonquest", fade_in=True)


def test_audio_sink_preserves_order_and_explicit_timer(mocker) -> None:
    from unittest.mock import call

    from tests.gameplay.test_game_tune_trigger import _audio_state_stub

    calls = mocker.Mock()
    calls.attach_mock(mocker.patch.object(audio_bridge, "trigger_game_tune"), "tune")
    calls.attach_mock(mocker.patch.object(audio_bridge, "play_sfx"), "sfx")
    audio = _audio_state_stub()
    rng = Crand(1)
    bridge = AudioBridge(audio_rng=rng, audio=audio, reflex_boost_timer=lambda: -1.0)
    plan = DeterministicPresentationPlan(
        trigger_game_tune=True,
        sfx=(SfxId.UI_BONUS,),
        post_apply_sfx=(SfxId.UI_LEVELUP,),
        reflex_boost_timer=0.5,
    )
    bridge.apply_plan(plan=plan, apply_audio=False)
    bridge.apply_post_plan(plan=plan, apply_audio=False)
    assert calls.mock_calls == []
    bridge.apply_plan(plan=plan)
    bridge.apply_post_plan(plan=plan)
    assert calls.mock_calls == [
        call.tune(audio, rng=rng),
        call.sfx(audio, SfxId.UI_BONUS, reflex_boost_timer=0.5),
        call.sfx(audio, SfxId.UI_LEVELUP, reflex_boost_timer=0.5),
    ]


@pytest.mark.parametrize("partition", [(1, 1), (2,), (0, 2, 0), (1, 0, 1)])
def test_audio_and_camera_consumption_are_independent_of_tick_partition(mocker, tmp_path, partition) -> None:
    from crimson.dbg.state_digest import session_digest
    from crimson.game_modes import GameMode
    from crimson.math_parity import f32
    from crimson.sim.batch_apply import PresentationTickOutput, apply_presentation_outputs
    from crimson.sim.sessions import DeterministicSession
    from crimson.world.runtime import WorldRuntime
    from grim.geom import Vec2
    from grim.raylib_api import rl
    from tests.gameplay.test_game_tune_trigger import _audio_state_stub

    mocker.patch.object(rl, "get_screen_width", return_value=640)
    mocker.patch.object(rl, "get_screen_height", return_value=480)
    play = mocker.patch.object(audio_bridge, "play_sfx")

    def run(counts):
        play.reset_mock()
        runtime = WorldRuntime(assets_dir=tmp_path, audio_rng=Crand(1), audio=_audio_state_stub())
        world = runtime.sim_world.world_state
        world.state.bonuses.reflex_boost = f32(0.025)
        world.players[0].weapon.shot_cooldown = 0
        world.state.camera_shake_timer = 10.0
        session = DeterministicSession(
            world=world,
            world_size=1024,
            damage_scale_by_type=runtime.sim_world.damage_scale_by_type,
            game_mode=GameMode.SURVIVAL,
            perk_progression_enabled=False,
        )
        tick = 0
        for count in counts:
            outputs = []
            for _ in range(count):
                # The second tick must retain the camera established by the first,
                # then add its own shake even though no player is alive anymore.
                if tick == 1:
                    world.players[0].health = 0.0
                world.state.camera_shake_offset = Vec2(3, 4) if tick == 0 else Vec2(-5, 2)
                step = session.step_tick(dt=1 / 60, inputs=(PlayerInput(aim=Vec2(600, 512), fire_down=tick == 0),))
                outputs.append(
                    PresentationTickOutput(tick_index=tick, dt_sim=step.dt_sim, presentation=step.presentation),
                )
                tick += 1
            apply_presentation_outputs(outputs=outputs, runtime=runtime, apply_audio=True)
        sounds = [(call.args[1], call.kwargs["reflex_boost_timer"]) for call in play.call_args_list]
        return runtime.camera, sounds, session_digest(session)

    expected = run((1, 1))
    assert expected[1] and expected[1][0][1] > 0.0
    assert run(partition) == expected


def test_audio_plan_captures_typo_post_step_bonus_reset() -> None:
    from crimson.game_modes import GameMode
    from crimson.sim.run_init import initialize_run
    from crimson.sim.run_spec import RunSpec

    session = initialize_run(RunSpec(game_mode_id=GameMode.TYPO, seed=1)).session
    session.world.state.bonuses.reflex_boost = 1.0
    tick = session.step_tick(dt=1 / 60, inputs=(PlayerInput(),))
    assert tick.presentation.sfx  # Initial loadout enforcement requests reload audio.
    assert session.world.state.bonuses.reflex_boost == 0.0
    assert tick.presentation.reflex_boost_timer == 0.0
