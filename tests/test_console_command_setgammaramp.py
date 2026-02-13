from __future__ import annotations

from pathlib import Path
import random
import time

import crimson.game.loop_view as loop_view
from crimson.game.loop_view import GameLoopView
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


def test_setgammaramp_updates_state_and_logs(tmp_path: Path) -> None:
    state = _make_state(tmp_path)
    handlers = _boot_command_handlers(state)

    handlers["setGammaRamp"](["1.25"])

    assert state.gamma_ramp == 1.25
    assert state.console.log.lines[-1] == "Gamma ramp regenerated and multiplied with 1.250000"


def test_setgammaramp_prints_usage_on_bad_arity(tmp_path: Path) -> None:
    state = _make_state(tmp_path)
    handlers = _boot_command_handlers(state)

    handlers["setGammaRamp"]([])

    assert state.console.log.lines[-2:] == [
        "setGammaRamp <scalar > 0>",
        "Command adjusts gamma ramp linearly by multiplying with given scalar",
    ]


def test_game_loop_draw_applies_gamma_shader_when_gain_non_default(monkeypatch, tmp_path: Path) -> None:
    calls: list[object] = []
    state = _make_state(tmp_path)
    state.gamma_ramp = 1.4
    view = GameLoopView(state)
    monkeypatch.setattr(view, "_draw_scene_layers", lambda: calls.append("scene"))

    sentinel_shader = object()

    monkeypatch.setattr(loop_view, "_get_gamma_ramp_shader", lambda: (sentinel_shader, 7))
    monkeypatch.setattr(
        loop_view,
        "_set_gamma_ramp_gain",
        lambda shader, gain_loc, gain: calls.append(("gain", shader, gain_loc, gain)),
    )
    monkeypatch.setattr(loop_view.rl, "begin_shader_mode", lambda shader: calls.append(("begin", shader)))
    monkeypatch.setattr(loop_view.rl, "end_shader_mode", lambda: calls.append("end"))

    view.draw()

    assert calls == [("gain", sentinel_shader, 7, 1.4), ("begin", sentinel_shader), "scene", "end"]


def test_game_loop_draw_skips_gamma_shader_for_default_gain(monkeypatch, tmp_path: Path) -> None:
    calls: list[object] = []
    state = _make_state(tmp_path)
    state.gamma_ramp = 1.0
    view = GameLoopView(state)
    monkeypatch.setattr(view, "_draw_scene_layers", lambda: calls.append("scene"))

    def _unexpected_shader_lookup() -> tuple[object, int]:
        raise AssertionError("gamma shader lookup should not happen for gain=1")

    monkeypatch.setattr(loop_view, "_get_gamma_ramp_shader", _unexpected_shader_lookup)

    view.draw()

    assert calls == ["scene"]
