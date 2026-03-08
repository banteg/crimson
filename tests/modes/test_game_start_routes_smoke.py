from __future__ import annotations

import time
from pathlib import Path

from crimson.game.loop_actions import ModeId, ScreenId
from crimson.game.loop_view import GameLoopView
from crimson.game.types import GameState
from crimson.modes.quest_mode import QuestMode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.modes.tutorial_mode import TutorialMode
from crimson.modes.typo_mode import TypoShooterMode
from crimson.persistence import save_status
from crimson.screens.high_scores_view import HighScoresView
from crimson.screens.panels.network_session import NetworkSessionPanelView
from grim.config import ensure_crimson_cfg
from grim.console import create_console
from grim.rand import Crand


def test_start_actions_map_to_expected_views(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    state = GameState(
        base_dir=tmp_path,
        assets_dir=assets_dir,
        rng=Crand(0),
        config=cfg,
        status=save_status.ensure_game_status(tmp_path),
        console=create_console(tmp_path, assets_dir=assets_dir),
        demo_enabled=False,
        preserve_bugs=False,
        resources=None,
        audio=None,
        session_start=time.monotonic(),
    )

    loop = GameLoopView(state)
    assert isinstance(loop._screens.gameplay(ModeId.SURVIVAL), SurvivalMode)
    assert isinstance(loop._screens.gameplay(ModeId.RUSH), RushMode)
    assert isinstance(loop._screens.gameplay(ModeId.TYPO), TypoShooterMode)
    assert isinstance(loop._screens.gameplay(ModeId.TUTORIAL), TutorialMode)
    assert isinstance(loop._screens.gameplay(ModeId.QUEST), QuestMode)
    assert isinstance(loop._screens.screen(ScreenId.HIGH_SCORES), HighScoresView)
    assert isinstance(loop._screens.screen(ScreenId.LAN_SESSION), NetworkSessionPanelView)
