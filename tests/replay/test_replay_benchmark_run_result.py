from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from crimson.modes.replay_playback_mode import ReplayPlaybackMode
from crimson.replay.driver.replay_benchmark import ReplayBenchmarkError, _run_result_for_replay_mode


def test_run_result_for_replay_mode_delegates_to_driver_build_result() -> None:
    expected = object()
    mode = SimpleNamespace(_driver=SimpleNamespace(build_result=lambda: expected), tick_index=88)

    assert _run_result_for_replay_mode(mode=cast(ReplayPlaybackMode, mode)) is expected


def test_run_result_for_replay_mode_requires_driver() -> None:
    mode = SimpleNamespace(
        _driver=None,
        tick_index=88,
    )

    with pytest.raises(ReplayBenchmarkError, match="replay driver was not available"):
        _run_result_for_replay_mode(mode=cast(ReplayPlaybackMode, mode))
