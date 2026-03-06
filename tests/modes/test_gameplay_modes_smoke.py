from __future__ import annotations

from pathlib import Path

from crimson.modes.base_gameplay_mode import BaseGameplayMode
from crimson.modes.quest_mode import QuestMode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.modes.tutorial_mode import TutorialMode
from crimson.modes.typo_mode import TypoShooterMode
from grim.rand import Crand
from grim.view import ViewContext


def test_modes_construct_without_window() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")

    assert isinstance(SurvivalMode(ctx, audio_rng=Crand(0xBEEF)), BaseGameplayMode)
    assert isinstance(RushMode(ctx, audio_rng=Crand(0xBEEF)), BaseGameplayMode)
    assert isinstance(QuestMode(ctx, audio_rng=Crand(0xBEEF)), BaseGameplayMode)
    assert isinstance(TutorialMode(ctx, audio_rng=Crand(0xBEEF)), BaseGameplayMode)
    assert isinstance(TypoShooterMode(ctx, audio_rng=Crand(0xBEEF)), BaseGameplayMode)
