from __future__ import annotations

import math
from pathlib import Path

import pytest

from grim.console import CONSOLE_BLINK_SPEED, ConsoleLog, ConsoleState


def _make_console() -> ConsoleState:
    return ConsoleState(base_dir=Path("."), log=ConsoleLog(base_dir=Path(".")))


def test_caret_blink_uses_native_eighth_power_pulse() -> None:
    console = _make_console()
    console._blink_time = (math.pi / 3.0) / CONSOLE_BLINK_SPEED

    assert console._caret_blink_alpha() == pytest.approx(0.31640625)


def test_caret_blink_alpha_has_native_floor() -> None:
    console = _make_console()
    console._blink_time = (math.pi / 4.0) / CONSOLE_BLINK_SPEED

    assert console._caret_blink_alpha() == pytest.approx(0.2)
