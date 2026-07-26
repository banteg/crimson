from __future__ import annotations

from unittest.mock import call

from crimson import audio_router
from crimson.audio_router import AudioRouter
from crimson.game_modes import GameMode
from crimson.projectiles.types import ProjectileHit, ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
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
    trigger_game_tune = mocker.patch.object(audio_router, "trigger_game_tune", return_value="gt1_ingame")
    play_sfx = mocker.patch.object(audio_router, "play_sfx")
    router = AudioRouter(audio=_audio_state_stub(), audio_rng=Crand(0xBEEF))
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    router.play_hit_sfx(_hits(2), game_mode=GameMode.TYPO, rng=rng, beam_types=frozenset())

    assert trigger_game_tune.call_count == 1
    assert trigger_game_tune.call_args.kwargs["rng"] is rng
    assert play_sfx.call_args_list == [
        call(router.audio, SfxId.BULLET_HIT_01, reflex_boost_timer=0.0),
    ]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
    ]


def test_game_tune_not_triggered_in_rush_mode(mocker) -> None:
    trigger_game_tune = mocker.patch.object(audio_router, "trigger_game_tune", return_value="gt1_ingame")
    play_sfx = mocker.patch.object(audio_router, "play_sfx")
    router = AudioRouter(audio=_audio_state_stub(), audio_rng=Crand(0xBEEF))
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    router.play_hit_sfx(
        _hits(2),
        game_mode=GameMode.RUSH,
        rng=rng,
        beam_types=frozenset(),
    )

    trigger_game_tune.assert_not_called()
    assert play_sfx.call_args_list == [
        call(router.audio, SfxId.BULLET_HIT_01, reflex_boost_timer=0.0),
        call(router.audio, SfxId.BULLET_HIT_01, reflex_boost_timer=0.0),
    ]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
    ]


def test_game_tune_not_triggered_in_demo(mocker) -> None:
    trigger_game_tune = mocker.patch.object(audio_router, "trigger_game_tune", return_value="gt1_ingame")
    play_sfx = mocker.patch.object(audio_router, "play_sfx")
    router = AudioRouter(audio=_audio_state_stub(), audio_rng=Crand(0xBEEF), demo_mode_active=True)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    router.play_hit_sfx(
        _hits(2),
        game_mode=GameMode.TYPO,
        rng=rng,
        beam_types=frozenset(),
    )

    trigger_game_tune.assert_not_called()
    assert play_sfx.call_args_list == [
        call(router.audio, SfxId.BULLET_HIT_01, reflex_boost_timer=0.0),
        call(router.audio, SfxId.BULLET_HIT_01, reflex_boost_timer=0.0),
    ]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
    ]
