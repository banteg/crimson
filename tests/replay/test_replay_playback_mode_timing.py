from __future__ import annotations

from pathlib import Path

from crimson.modes import replay_playback_mode
from crimson.world import WorldRuntime
from grim.rand import Crand
from tests.support.builders import FakePlaybackDriver
from tests.support.replay_runner_helpers import idle_replay


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def _runtime() -> WorldRuntime:
    return WorldRuntime(assets_dir=_assets_dir(), audio_rng=Crand(0))


def _capture_applied_plans(mocker, driver: FakePlaybackDriver, captured_ticks: list[int]) -> None:
    """Record which stepped tick produced each applied presentation plan."""

    stepped: list[tuple[int, object]] = []
    step_tick = driver.step_tick

    def _step(tick_index: int):
        result = step_tick(tick_index)
        stepped.append((tick_index, result.payload.presentation))
        return result

    mocker.patch.object(driver, "step_tick", side_effect=_step)

    def _apply_presentation_plans(*, plans, **_kwargs) -> None:
        for plan in plans:
            captured_ticks.append(next(index for index, stepped_plan in stepped if stepped_plan is plan))

    mocker.patch.object(replay_playback_mode, "apply_presentation_plans", side_effect=_apply_presentation_plans)


def test_replay_runner_eos_applies_partial_completed_results(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view

    view._replay = idle_replay(2)
    view._runtime = _runtime()
    view._max_ticks = None
    view._tick_index = 0
    view._finished = False
    applied_ticks: list[int] = []
    view._driver = FakePlaybackDriver(tick_limit=2)
    _capture_applied_plans(mocker, view._driver, applied_ticks)

    view._advance_runner(
        dt_seconds=2.0 * float(view._dt),
        max_ticks=2,
    )

    assert applied_ticks == [0, 1]
    assert view._tick_index == 2
    assert view._finished is True
