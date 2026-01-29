from __future__ import annotations

from pathlib import Path
import random

from crimson.bonuses import BonusId
from crimson.gameplay import PlayerInput, player_update
from crimson.game_world import GameWorld


def test_reload_finish_and_immediate_shot_plays_fire_sfx(monkeypatch) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")

    played: list[str | None] = []

    def _play_sfx(_state, key, *, rng=None, allow_variants=True) -> None:  # noqa: ARG001
        played.append(key)

    monkeypatch.setattr("crimson.audio_router.play_sfx", _play_sfx)
    world.audio = object()
    world.audio_rng = random.Random(0)
    world.audio_router.audio = world.audio
    world.audio_router.audio_rng = world.audio_rng

    player = world.players[0]

    # Setup: reload is about to finish and the player is holding fire.
    player.weapon_id = 0
    player.clip_size = 12
    player.ammo = 0
    player.reload_active = True
    player.reload_timer = 0.01
    player.reload_timer_max = 1.0
    player.shot_cooldown = 0.0

    prev_shot_seq = int(player.shot_seq)
    prev_reload_active = bool(player.reload_active)
    prev_reload_timer = float(player.reload_timer)

    input_state = PlayerInput(
        fire_down=True,
        aim_x=player.pos_x + 10.0,
        aim_y=player.pos_y,
    )
    player_update(player, input_state, 0.05, world.state, world_size=float(world.world_size))

    world.audio_router.handle_player_audio(
        player,
        prev_shot_seq=prev_shot_seq,
        prev_reload_active=prev_reload_active,
        prev_reload_timer=prev_reload_timer,
    )

    assert played == ["sfx_pistol_fire"]


def test_pending_perk_increase_plays_levelup_sfx(monkeypatch) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")

    played: list[str | None] = []

    def _play_sfx(_state, key, *, rng=None, allow_variants=True) -> None:  # noqa: ARG001
        played.append(key)

    monkeypatch.setattr("crimson.audio_router.play_sfx", _play_sfx)
    world.audio = object()
    world.audio_rng = random.Random(0)

    player = world.players[0]
    player.experience = 10_000

    world.update(
        0.05,
        inputs=[PlayerInput()],
        auto_pick_perks=False,
        perk_progression_enabled=True,
    )

    assert played == ["sfx_ui_levelup"]


def test_bonus_pickup_plays_bonus_sfx(monkeypatch) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")

    played: list[str | None] = []

    def _play_sfx(_state, key, *, rng=None, allow_variants=True) -> None:  # noqa: ARG001
        played.append(key)

    monkeypatch.setattr("crimson.audio_router.play_sfx", _play_sfx)
    world.audio = object()
    world.audio_rng = random.Random(0)

    player = world.players[0]
    entry = world.state.bonus_pool.spawn_at(player.pos_x, player.pos_y, int(BonusId.POINTS))
    assert entry is not None

    world.update(0.016, perk_progression_enabled=False)

    assert entry.picked
    assert played == ["sfx_ui_bonus"]
