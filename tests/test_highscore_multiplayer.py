from __future__ import annotations

from pathlib import Path

from crimson.modes.survival_mode import SurvivalMode
from grim.config import CrimsonConfig
from grim.view import ViewContext


def test_survival_high_score_record_uses_player0_stats_in_multiplayer(monkeypatch) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    config = CrimsonConfig(path=repo_root / "crimson.cfg", data={"player_count": 2, "game_mode": 1})

    mode = SurvivalMode(ctx, config=config)
    monkeypatch.setattr("crimson.ui.game_over.GameOverUi.open", lambda self: None)  # noqa: ARG005

    player0, player1 = mode._world.players[:2]
    player0.experience = 1234
    player1.experience = 9999

    mode._state.shots_fired[0] = 10
    mode._state.shots_hit[0] = 7
    mode._state.shots_fired[1] = 999
    mode._state.shots_hit[1] = 888

    mode._state.weapon_shots_fired[0][1] = 5
    mode._state.weapon_shots_fired[1][2] = 999

    mode._enter_game_over()

    record = mode._game_over_record
    assert record is not None
    assert record.score_xp == 1234
    assert record.shots_fired == 10
    assert record.shots_hit == 7
    assert record.most_used_weapon_id == 1
