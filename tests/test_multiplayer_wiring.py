from __future__ import annotations

from pathlib import Path

from crimson.gameplay import PlayerInput
from crimson.game_world import GameWorld
from crimson.modes.quest_mode import QuestMode
from crimson.modes.survival_mode import SurvivalMode
from grim.config import ensure_crimson_cfg
from grim.geom import Vec2
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


def test_quest_mode_update_uses_per_player_input_frame(monkeypatch, tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.data["player_count"] = 3
    ctx = ViewContext(assets_dir=assets_dir)
    mode = QuestMode(ctx, config=cfg)

    inputs = [PlayerInput(move=Vec2(float(idx), 0.0)) for idx in range(len(mode._world.players))]
    captured: dict[str, object] = {}

    def _world_update(_self, _dt, *, inputs=None, **_kwargs):  # noqa: ANN001
        captured["inputs"] = inputs
        return []

    monkeypatch.setattr("crimson.game_world.GameWorld.update", _world_update)
    monkeypatch.setattr("crimson.modes.quest_mode.tick_quest_mode_spawns", lambda *args, **kwargs: (args[0], kwargs.get("quest_spawn_timeline_ms", 0.0), False, 0.0, ()))
    monkeypatch.setattr(
        "crimson.modes.quest_mode.tick_quest_completion_transition",
        lambda *_args, **_kwargs: (-1.0, False, False, False),
    )
    monkeypatch.setattr(mode, "_update_audio", lambda _dt: None)
    monkeypatch.setattr(mode, "_tick_frame", lambda _dt: (0.016, 16.0))
    monkeypatch.setattr(mode, "_handle_input", lambda: None)
    monkeypatch.setattr(mode, "_build_local_inputs", lambda *, dt_frame: inputs)
    monkeypatch.setattr(mode, "_death_transition_ready", lambda: False)

    mode.update(0.016)

    assert captured["inputs"] is inputs
    assert len(inputs) == 3
