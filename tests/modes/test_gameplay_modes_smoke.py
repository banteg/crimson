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
    runtime_dir = repo_root / ".tmp-test-runtime"
    ctx = ViewContext(
        assets_dir=repo_root / "artifacts" / "assets",
        base_dir=runtime_dir,
    )

    for mode in (
        SurvivalMode(ctx, audio_rng=Crand(0xBEEF)),
        RushMode(ctx, audio_rng=Crand(0xBEEF)),
        QuestMode(ctx, audio_rng=Crand(0xBEEF)),
        TutorialMode(ctx, audio_rng=Crand(0xBEEF)),
        TypoShooterMode(ctx, audio_rng=Crand(0xBEEF)),
    ):
        assert isinstance(mode, BaseGameplayMode)
        assert mode._base_dir == runtime_dir
