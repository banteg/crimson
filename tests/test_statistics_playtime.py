from __future__ import annotations

from pathlib import Path
import random
import time

from crimson.frontend.panels.stats import _format_playtime_text
from crimson.game.loop_view import GameLoopView
from crimson.game.types import GameState
from crimson.persistence import save_status
from grim.config import ensure_crimson_cfg
from grim.console import create_console


def _build_state(tmp_path: Path, *, demo_enabled: bool) -> GameState:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"
    cfg = ensure_crimson_cfg(tmp_path)
    return GameState(
        base_dir=tmp_path,
        assets_dir=assets_dir,
        rng=random.Random(0),
        config=cfg,
        status=save_status.ensure_game_status(tmp_path),
        console=create_console(tmp_path, assets_dir=assets_dir),
        demo_enabled=demo_enabled,
        preserve_bugs=False,
        logos=None,
        texture_cache=None,
        audio=None,
        resource_paq=assets_dir / "crimson.paq",
        session_start=time.monotonic(),
    )


def test_format_playtime_text_uses_hour_and_minute_buckets() -> None:
    assert _format_playtime_text(0) == "played for 0 hours 0 minutes"
    assert _format_playtime_text((2 * 60 * 60 + 35 * 60 + 59) * 1000) == "played for 2 hours 35 minutes"


def test_format_playtime_text_pluralizes_in_default_mode() -> None:
    assert _format_playtime_text((1 * 60 * 60 + 1 * 60) * 1000) == "played for 1 hour 1 minute"
    assert _format_playtime_text((1 * 60 * 60 + 2 * 60) * 1000) == "played for 1 hour 2 minutes"


def test_format_playtime_text_preserve_bugs_keeps_native_plural_form() -> None:
    assert (
        _format_playtime_text(
            (1 * 60 * 60 + 1 * 60) * 1000,
            preserve_bugs=True,
        )
        == "played for 1 hours 1 minutes"
    )


def test_tick_statistics_playtime_accumulates_for_non_demo_gameplay(tmp_path: Path) -> None:
    state = _build_state(tmp_path, demo_enabled=False)
    loop = GameLoopView(state)
    loop._front_active = loop._front_views["start_survival"]
    state.status.game_sequence_id = 10

    loop._tick_statistics_playtime(0.0169)

    assert state.status.game_sequence_id == 26


def test_tick_statistics_playtime_skips_non_gameplay_views(tmp_path: Path) -> None:
    state = _build_state(tmp_path, demo_enabled=False)
    loop = GameLoopView(state)
    loop._front_active = loop._front_views["open_statistics"]
    state.status.game_sequence_id = 123

    loop._tick_statistics_playtime(0.5)

    assert state.status.game_sequence_id == 123


def test_tick_statistics_playtime_skips_demo_builds(tmp_path: Path) -> None:
    state = _build_state(tmp_path, demo_enabled=True)
    loop = GameLoopView(state)
    loop._front_active = loop._front_views["start_survival"]
    state.status.game_sequence_id = 123

    loop._tick_statistics_playtime(0.5)

    assert state.status.game_sequence_id == 123
