from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import crimson.modes.base_gameplay_mode as base_gameplay_mode
import crimson.world.render_resources as render_resources_module
from crimson.game_modes import GameMode
from crimson.modes.tutorial_mode import TutorialMode
from crimson.sim.sessions import DeterministicSession
from grim.config import ensure_crimson_cfg
from grim.rand import Crand
from grim.view import ViewContext


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def test_tutorial_constructor_starts_without_placeholder_session() -> None:
    mode = TutorialMode(ViewContext(assets_dir=_assets_dir()), audio_rng=Crand(0xBEEF))
    assert mode._sim_session is None


def test_tutorial_open_creates_session_and_recorder(mocker, tmp_path: Path) -> None:
    cfg = ensure_crimson_cfg(tmp_path)
    cfg.data["player_count"] = 4
    mode = TutorialMode(ViewContext(assets_dir=_assets_dir()), config=cfg, audio_rng=Crand(0xBEEF))
    mocker.patch.object(mode, "apply_terrain_setup", return_value=None)
    resources = SimpleNamespace(texture=lambda _texture_id: object())
    small_font = SimpleNamespace(cell_size=10)
    mocker.patch.object(render_resources_module, "runtime_resources_for", return_value=resources)
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=small_font)
    reset_runtime = mocker.patch.object(mode._world_runtime, "reset", wraps=mode._world_runtime.reset)
    mode.open()

    assert int(mode.config.player_count) == 4
    assert reset_runtime.call_args.kwargs["player_count"] == 1
    assert isinstance(mode._sim_session, DeterministicSession)
    assert mode._replay_recorder is not None
    assert mode._replay_recorder.header.game_mode_id == GameMode.TUTORIAL
    assert int(mode._replay_recorder.header.player_count) == 1
