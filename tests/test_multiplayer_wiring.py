from __future__ import annotations

from pathlib import Path

from crimson.game_world import GameWorld
from crimson.modes.survival_mode import SurvivalMode
from grim.config import ensure_crimson_cfg
from grim.view import ViewContext


def test_game_world_init_honors_config_player_count(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.data["player_count"] = 2

    world = GameWorld(assets_dir=assets_dir, config=cfg)
    assert [player.index for player in world.players] == [0, 1]


def test_game_world_reset_spreads_player_spawn_positions() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    world = GameWorld(assets_dir=assets_dir)
    world.reset(seed=0xBEEF, player_count=4)

    positions = {(round(player.pos.x, 3), round(player.pos.y, 3)) for player in world.players}
    assert len(positions) == 4


def test_survival_mode_uses_config_player_count(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.data["player_count"] = 2
    ctx = ViewContext(assets_dir=assets_dir)

    mode = SurvivalMode(ctx, config=cfg)
    assert len(mode._world.players) == 2  # intentional: wiring smoke test
