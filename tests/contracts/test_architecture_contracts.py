from __future__ import annotations

from pathlib import Path

import crimson.world.audio_bridge as audio_bridge_module
from crimson.replay.ticks import LiveTickSource, step_replay_tick
from crimson.sim.batch_apply import apply_presentation_plans
from crimson.sim.presentation_step import DeterministicPresentationPlan
from crimson.sim.sessions import DeterministicSession
from crimson.world import WorldRuntime
from grim.audio import AudioState
from grim.geom import Vec2
from grim.music import init_music_state
from grim.rand import Crand
from grim.sfx import init_sfx_state
from tests.support.audio import sfx_ids
from tests.support.factories import player_input


def test_contract_6_state_apply_and_presentation_apply_stay_separate(mocker, tmp_path: Path) -> None:
    audio = AudioState(
        ready=False,
        music=init_music_state(ready=False, enabled=False, volume=1.0),
        sfx=init_sfx_state(ready=False, enabled=False, volume=1.0, rng=Crand(0x1234)),
    )
    runtime = WorldRuntime(assets_dir=tmp_path, audio_rng=Crand(0xBEEF), audio=audio)
    runtime.world.players[0].weapon.shot_cooldown = 0.0
    session = DeterministicSession.start(
        world=runtime.world,
        perk_progression_enabled=False,
    )
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    ticks = LiveTickSource()
    plans: list[DeterministicPresentationPlan] = []
    for _ in range(2):
        ticks.poll([player_input(aim=Vec2(700.0, 512.0), fire_down=True, fire_pressed=True)])
        step = step_replay_tick(session, ticks.next_tick())
        camera = runtime.camera
        runtime.presentation.advance(step.dt_sim)
        # Advancing the presentation clock applies no presentation output.
        assert runtime.camera == camera
        assert play_sfx.call_count == 0
        plans.append(step.presentation)
    clock = (runtime.presentation.elapsed_ms, runtime.presentation.bonus_anim_phase)
    assert clock[0] > 0.0

    apply_presentation_plans(plans=plans, runtime=runtime)

    # Presentation output does not touch the presentation clock and plays
    # each plan's sounds in tick order.
    assert (runtime.presentation.elapsed_ms, runtime.presentation.bonus_anim_phase) == clock
    expected_sfx = [sfx for plan in plans for sfx in (*sfx_ids(plan.sfx), *sfx_ids(plan.post_apply_sfx))]
    assert expected_sfx
    assert [call.args[1] for call in play_sfx.call_args_list] == expected_sfx

