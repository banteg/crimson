from __future__ import annotations

from unittest.mock import call

from crimson.game_modes import GameMode
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.presentation_step import DeterministicPresentationPlan, plan_hit_sfx
from crimson.world import audio_bridge
from crimson.world.audio_bridge import AudioBridge
from grim.audio import AudioState
from grim.geom import Vec2
from grim.music import init_music_state
from grim.rand import Crand
from grim.sfx import init_sfx_state
from grim.sfx_map import SfxId
from tests.support.helpers import ScriptedCrand


def _audio_state_stub() -> AudioState:
    return AudioState(
        ready=False,
        music=init_music_state(ready=False, enabled=True, volume=1.0),
        sfx=init_sfx_state(ready=False, enabled=True, volume=1.0),
    )


def _hits(count: int) -> list[ProjectileHit]:
    return [
        ProjectileHit(type_id=ProjectileTemplateId.PISTOL, origin=Vec2(), hit=Vec2(), target=Vec2())
        for _ in range(int(count))
    ]


def test_game_tune_triggers_in_typo_mode(mocker) -> None:
    trigger_game_tune = mocker.patch.object(audio_bridge, "trigger_game_tune", return_value="gt1_ingame")
    play_sfx = mocker.patch.object(audio_bridge, "play_sfx")
    bridge = AudioBridge(audio=_audio_state_stub(), audio_rng=Crand(0xBEEF))
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    tune, sounds = plan_hit_sfx(
        _hits(2), game_mode=GameMode.TYPO, rng=rng, demo_mode_active=False, game_tune_started=False,
    )
    bridge.apply_plan(plan=DeterministicPresentationPlan(trigger_game_tune=tune, sfx=tuple(sounds)))

    assert trigger_game_tune.call_count == 1
    assert trigger_game_tune.call_args.kwargs["rng"] is bridge.audio_rng
    assert play_sfx.call_args_list == [
        call(bridge.audio, SfxId.BULLET_HIT_01, reflex_boost_timer=0.0),
    ]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.SFX_PLAY_EXCLUSIVE_PLAYLIST_PICK,
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
    ]


def test_game_tune_not_triggered_in_rush_mode(mocker) -> None:
    trigger_game_tune = mocker.patch.object(audio_bridge, "trigger_game_tune", return_value="gt1_ingame")
    play_sfx = mocker.patch.object(audio_bridge, "play_sfx")
    bridge = AudioBridge(audio=_audio_state_stub(), audio_rng=Crand(0xBEEF))
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    tune, sounds = plan_hit_sfx(
        _hits(2),
        game_mode=GameMode.RUSH,
        rng=rng,
        demo_mode_active=False,
        game_tune_started=False,
    )
    bridge.apply_plan(plan=DeterministicPresentationPlan(trigger_game_tune=tune, sfx=tuple(sounds)))

    trigger_game_tune.assert_not_called()
    assert play_sfx.call_args_list == [
        call(bridge.audio, SfxId.BULLET_HIT_01, reflex_boost_timer=0.0),
        call(bridge.audio, SfxId.BULLET_HIT_01, reflex_boost_timer=0.0),
    ]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
    ]


def test_game_tune_not_triggered_in_demo(mocker) -> None:
    trigger_game_tune = mocker.patch.object(audio_bridge, "trigger_game_tune", return_value="gt1_ingame")
    play_sfx = mocker.patch.object(audio_bridge, "play_sfx")
    bridge = AudioBridge(audio=_audio_state_stub(), audio_rng=Crand(0xBEEF))
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    tune, sounds = plan_hit_sfx(
        _hits(2),
        game_mode=GameMode.TYPO,
        rng=rng,
        demo_mode_active=True,
        game_tune_started=False,
    )
    bridge.apply_plan(plan=DeterministicPresentationPlan(trigger_game_tune=tune, sfx=tuple(sounds)))

    trigger_game_tune.assert_not_called()
    assert play_sfx.call_args_list == [
        call(bridge.audio, SfxId.BULLET_HIT_01, reflex_boost_timer=0.0),
        call(bridge.audio, SfxId.BULLET_HIT_01, reflex_boost_timer=0.0),
    ]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
    ]
