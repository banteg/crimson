from __future__ import annotations

from pathlib import Path
import random
import time

from crimson.game.runtime import _boot_command_handlers
from crimson.game.types import GameState
from crimson.persistence import save_status
from grim.config import ensure_crimson_cfg
from grim.console import create_console


def _make_state(tmp_path: Path) -> GameState:
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
        demo_enabled=False,
        preserve_bugs=False,
        logos=None,
        texture_cache=None,
        audio=None,
        resource_paq=assets_dir / "crimson.paq",
        session_start=time.monotonic(),
    )


def test_telltimesurvived_uses_gameplay_elapsed_ms(tmp_path: Path) -> None:
    state = _make_state(tmp_path)
    state.survival_elapsed_ms = 12_999.0
    handlers = _boot_command_handlers(state)

    handlers["telltimesurvived"]([])

    assert state.console.log.lines[-1] == "Survived: 12 seconds."
