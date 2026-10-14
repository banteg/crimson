from __future__ import annotations

from unittest.mock import call

from crimson.game_modes import GameMode
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.presentation_step import DeterministicPresentationPlan
from crimson.sim.world_state import WorldState
from crimson.world import audio_bridge
from crimson.world.audio_bridge import AudioBridge
from grim.audio import AudioState
from grim.geom import Vec2
from grim.music import init_music_state
from grim.rand import Crand
from grim.sfx import init_sfx_state
from grim.sfx_map import SfxId
from tests.support.factories import make_step_runtime
from tests.support.helpers import ScriptedCrand


def _audio_state_stub() -> AudioState:
    return AudioState(
        ready=False,
        music=init_music_state(ready=False, enabled=True, volume=1.0),
        sfx=init_sfx_state(ready=False, enabled=True, volume=1.0, rng=Crand(0x1234)),
    )


def _hits(count: int) -> list[ProjectileHit]:
    return [
        ProjectileHit(type_id=ProjectileTemplateId.PISTOL, origin=Vec2(), hit=Vec2(), target=Vec2())
        for _ in range(int(count))
    ]


def test_game_tune_triggers_in_typo_mode(mocker) -> None:
    trigger_game_tune = mocker.patch.object(audio_bridge, "trigger_game_tune", return_value="gt1_ingame")
    play_sfx = mocker.patch.object(audio_bridge, "play_sfx")
    audio = _audio_state_stub()
    bridge = AudioBridge(audio=audio, audio_rng=Crand(0xBEEF))
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    world = WorldState.build(hardcore=False, quest_fail_retry_count=0)
    step_runtime = make_step_runtime(world)
    world.state.game_mode = GameMode.TYPO
    world.state.game_tune_started = False
    world.state.rng = rng
    for hit in _hits(2):
        step_runtime.finish_hit_presentation(hit, step_runtime.begin_hit_presentation(hit))
    tune, sounds = step_runtime.trigger_game_tune, step_runtime.hit_sfx
    bridge.apply_plan(
        plan=DeterministicPresentationPlan(trigger_game_tune=tune, sfx=tuple(sounds)), camera=Vec2(), screen_width=1024.0,
    )

    assert trigger_game_tune.call_count == 1
    assert trigger_game_tune.call_args.kwargs["rng"] is bridge.audio_rng
    assert play_sfx.call_args_list == [
        call(audio.sfx, SfxId.BULLET_HIT_01, reflex_boost_timer=0.0, gain=1.0, pan=-850),
    ]
    assert [
        record.caller
        for record in rng.records_since()
        if record.caller in (RngCallerStatic.SFX_PLAY_EXCLUSIVE_PLAYLIST_PICK, RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX)
    ] == [
        RngCallerStatic.SFX_PLAY_EXCLUSIVE_PLAYLIST_PICK,
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
    ]
