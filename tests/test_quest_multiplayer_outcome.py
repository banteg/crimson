from __future__ import annotations

from pathlib import Path

from crimson.modes.quest_mode import QuestMode
from grim.config import ensure_crimson_cfg
from grim.view import ViewContext


def test_quest_failed_outcome_captures_all_player_health_values(tmp_path: Path, monkeypatch) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.data["player_count"] = 4
    ctx = ViewContext(assets_dir=assets_dir)

    monkeypatch.setattr("crimson.game_world.GameWorld.set_terrain", lambda self, **_kwargs: None)
    mode = QuestMode(ctx, config=cfg)
    mode.prepare_new_run("1.1", status=None)
    health_values = (91.2, 50.6, 10.4, 0.49)
    for idx, health in enumerate(health_values):
        mode.world.players[idx].health = float(health)
    mode._close_failed_run()
    outcome = mode.consume_outcome()
    assert outcome is not None
    assert outcome.player_health_values == health_values
    assert outcome.player_health == health_values[0]
    assert outcome.player2_health == health_values[1]
