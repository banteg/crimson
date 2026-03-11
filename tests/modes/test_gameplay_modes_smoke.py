from __future__ import annotations

from pathlib import Path

from crimson.modes.base_gameplay_mode import BaseGameplayMode
from crimson.modes.quest_mode import QuestMode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.modes.tutorial_mode import TutorialMode
from crimson.modes.typo_mode import TypoShooterMode
from crimson.paths import default_runtime_dir
from grim.rand import Crand
from grim.view import ViewContext


def test_modes_construct_without_window(assets_dir: Path, tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    ctx = ViewContext(
        assets_dir=assets_dir,
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


def test_modes_without_base_dir_use_default_runtime_dir(assets_dir: Path) -> None:
    ctx = ViewContext(assets_dir=assets_dir)

    for mode in (
        SurvivalMode(ctx, audio_rng=Crand(0xBEEF)),
        RushMode(ctx, audio_rng=Crand(0xBEEF)),
        QuestMode(ctx, audio_rng=Crand(0xBEEF)),
        TutorialMode(ctx, audio_rng=Crand(0xBEEF)),
        TypoShooterMode(ctx, audio_rng=Crand(0xBEEF)),
    ):
        assert isinstance(mode, BaseGameplayMode)
        assert mode._base_dir == default_runtime_dir()
