from __future__ import annotations

from unittest.mock import call

import crimson.audio_router as audio_router
from crimson.audio_router import AudioRouter
from crimson.game_modes import GameMode
from crimson.projectiles import ProjectileHit, ProjectileTypeId
from grim.audio import AudioState
from grim.geom import Vec2
from grim.music import init_music_state
from grim.sfx import init_sfx_state


def _audio_state_stub() -> AudioState:
    return AudioState(
        ready=False,
        music=init_music_state(ready=False, enabled=True, volume=1.0),
        sfx=init_sfx_state(ready=False, enabled=True, volume=1.0),
    )


def _hits(count: int) -> list[ProjectileHit]:
    return [
        ProjectileHit(type_id=int(ProjectileTypeId.PISTOL), origin=Vec2(), hit=Vec2(), target=Vec2())
        for _ in range(int(count))
    ]


def test_game_tune_triggers_in_typo_mode(mocker) -> None:
    trigger_game_tune = mocker.patch.object(audio_router, "trigger_game_tune", return_value="gt1_ingame")
    play_sfx = mocker.patch.object(AudioRouter, "play_sfx", autospec=True)
    router = AudioRouter(audio=_audio_state_stub())

    def rand() -> int:
        return 0

    router.play_hit_sfx(_hits(2), game_mode=int(GameMode.TYPO), rand=rand, beam_types=frozenset())

    assert trigger_game_tune.call_count == 1
    assert trigger_game_tune.call_args.kwargs["rand"] is rand
    assert play_sfx.call_args_list == [call(router, "sfx_bullet_hit_01")]


def test_game_tune_not_triggered_in_rush_mode(mocker) -> None:
    trigger_game_tune = mocker.patch.object(audio_router, "trigger_game_tune", return_value="gt1_ingame")
    play_sfx = mocker.patch.object(AudioRouter, "play_sfx", autospec=True)
    router = AudioRouter(audio=_audio_state_stub())

    router.play_hit_sfx(_hits(2), game_mode=int(GameMode.RUSH), rand=lambda: 0, beam_types=frozenset())

    trigger_game_tune.assert_not_called()
    assert play_sfx.call_args_list == [call(router, "sfx_bullet_hit_01"), call(router, "sfx_bullet_hit_01")]


def test_game_tune_not_triggered_in_demo(mocker) -> None:
    trigger_game_tune = mocker.patch.object(audio_router, "trigger_game_tune", return_value="gt1_ingame")
    play_sfx = mocker.patch.object(AudioRouter, "play_sfx", autospec=True)
    router = AudioRouter(audio=_audio_state_stub(), demo_mode_active=True)

    router.play_hit_sfx(_hits(2), game_mode=int(GameMode.TYPO), rand=lambda: 0, beam_types=frozenset())

    trigger_game_tune.assert_not_called()
    assert play_sfx.call_args_list == [call(router, "sfx_bullet_hit_01"), call(router, "sfx_bullet_hit_01")]
