from __future__ import annotations

import crimson.audio_router as audio_router
from crimson.audio_router import AudioRouter
from crimson.game_modes import GameMode
from crimson.projectiles import ProjectileHit
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
    return [ProjectileHit(type_id=0, origin=Vec2(), hit=Vec2(), target=Vec2()) for _ in range(int(count))]


def test_game_tune_triggers_in_typo_mode(monkeypatch) -> None:
    triggered: list[object] = []

    def fake_trigger_game_tune(_audio, *, rand=None):
        triggered.append(rand)
        return "gt1_ingame"

    monkeypatch.setattr(audio_router, "trigger_game_tune", fake_trigger_game_tune)

    played: list[str | None] = []
    router = AudioRouter(audio=_audio_state_stub())

    def fake_play_sfx(_self: AudioRouter, key: str | None) -> None:
        played.append(key)

    monkeypatch.setattr(AudioRouter, "play_sfx", fake_play_sfx)

    router.play_hit_sfx(_hits(2), game_mode=int(GameMode.TYPO), rand=lambda: 0, beam_types=frozenset())

    assert len(triggered) == 1
    assert played == ["sfx_bullet_hit_01", "sfx_bullet_hit_01"]


def test_game_tune_not_triggered_in_rush_mode(monkeypatch) -> None:
    triggered: list[object] = []

    def fake_trigger_game_tune(_audio, *, rand=None):
        triggered.append(rand)
        return "gt1_ingame"

    monkeypatch.setattr(audio_router, "trigger_game_tune", fake_trigger_game_tune)

    played: list[str | None] = []
    router = AudioRouter(audio=_audio_state_stub())

    def fake_play_sfx(_self: AudioRouter, key: str | None) -> None:
        played.append(key)

    monkeypatch.setattr(AudioRouter, "play_sfx", fake_play_sfx)

    router.play_hit_sfx(_hits(2), game_mode=int(GameMode.RUSH), rand=lambda: 0, beam_types=frozenset())

    assert not triggered
    assert played == ["sfx_bullet_hit_01", "sfx_bullet_hit_01"]


def test_game_tune_not_triggered_in_demo(monkeypatch) -> None:
    triggered: list[object] = []

    def fake_trigger_game_tune(_audio, *, rand=None):
        triggered.append(rand)
        return "gt1_ingame"

    monkeypatch.setattr(audio_router, "trigger_game_tune", fake_trigger_game_tune)

    played: list[str | None] = []
    router = AudioRouter(audio=_audio_state_stub(), demo_mode_active=True)

    def fake_play_sfx(_self: AudioRouter, key: str | None) -> None:
        played.append(key)

    monkeypatch.setattr(AudioRouter, "play_sfx", fake_play_sfx)

    router.play_hit_sfx(_hits(2), game_mode=int(GameMode.TYPO), rand=lambda: 0, beam_types=frozenset())

    assert not triggered
    assert played == ["sfx_bullet_hit_01", "sfx_bullet_hit_01"]
