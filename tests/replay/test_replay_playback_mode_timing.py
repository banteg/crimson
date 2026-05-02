from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import crimson.modes.replay_playback_mode as replay_playback_mode
from crimson.game_modes import GameMode
from crimson.replay import Replay, ReplayHeader, ReplayTick
from crimson.world.render_resources import RenderResources
from crimson.world.sim_world_state import SimWorldState
from tests.support.builders import FakePlaybackDriver


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


@dataclass
class _StubReplayRuntime:
    """Minimal stub for ``view._runtime`` in replay timing tests."""

    sim_world: SimWorldState = field(default_factory=SimWorldState)
    render_resources: RenderResources = field(
        default_factory=lambda: RenderResources(assets_dir=_assets_dir()),
    )
    audio_bridge: object = field(
        default_factory=lambda: SimpleNamespace(
            apply_plan=lambda **_kwargs: None,
            router=SimpleNamespace(play_sfx=lambda _key: None),
        ),
    )

    def sync_audio_bridge_state(self) -> None:
        return None

    def update_camera(self, _dt: float) -> None:
        return None


def _replay_with_ticks(tick_count: int) -> Replay:
    return Replay(
        header=ReplayHeader(game_mode_id=GameMode.DEMO, seed=0),
        ticks=[ReplayTick(dt=1 / 60, inputs=[[0.0, 0.0, 0.0, 0.0, 0]]) for _ in range(max(0, int(tick_count)))],
    )


def _capture_output_ticks(mocker, captured_ticks: list[int]) -> None:
    def _apply_presentation_outputs(*, outputs, apply_runtime, **_kwargs) -> None:
        for output in outputs:
            captured_ticks.append(int(output.tick_index))
            apply_runtime.output_applied(output)

    mocker.patch.object(
        replay_playback_mode,
        "apply_presentation_outputs",
        side_effect=_apply_presentation_outputs,
    )


def test_replay_playback_mode_tick_loop_decrements_accum(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view

    mocker.patch.object(replay_playback_mode.rl, "is_key_pressed", return_value=False)
    view._replay = _replay_with_ticks(16)
    view._runtime = _StubReplayRuntime()
    view._finished = False
    view._paused = False
    view._tick_index = 0
    view._tick_rate = 60
    view._dt = 1.0 / 60.0
    view._dt_accum = 0.0
    view._max_ticks = None

    view._driver = FakePlaybackDriver(tick_limit=16)

    view.update(0.05)

    # 0.05s at 60Hz should advance exactly 3 ticks (0.0166.. * 3 == 0.05).
    assert view._tick_index == 3
    assert view._dt_accum <= (1.0 / 60.0)


def test_replay_runner_advance_does_not_stop_on_player_death(replay_playback_view) -> None:
    view, _console = replay_playback_view

    view._replay = _replay_with_ticks(2)
    view._runtime = _StubReplayRuntime()
    view._max_ticks = None
    view._tick_index = 0
    view._finished = False
    view._driver = FakePlaybackDriver(tick_limit=2)

    view._advance_runner(
        dt_seconds=float(view._dt),
        max_ticks=1,
    )

    assert view._tick_index == 1
    assert not view._finished


def test_replay_runner_eos_applies_partial_completed_results(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view

    view._replay = _replay_with_ticks(2)
    view._runtime = _StubReplayRuntime()
    view._max_ticks = None
    view._tick_index = 0
    view._finished = False
    applied_ticks: list[int] = []
    _capture_output_ticks(mocker, applied_ticks)

    view._driver = FakePlaybackDriver(tick_limit=2)

    view._advance_runner(
        dt_seconds=2.0 * float(view._dt),
        max_ticks=2,
    )

    assert applied_ticks == [0, 1]
    assert view._tick_index == 2
    assert view._finished is True


def test_replay_runner_preserves_tick_complete_order_for_mixed_payload_batches(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view

    view._replay = _replay_with_ticks(2)
    view._runtime = SimpleNamespace(
        sim_world=SimpleNamespace(apply_step_metadata=lambda **_kwargs: None),
        audio_bridge=SimpleNamespace(
            apply_plan=lambda **_kwargs: None,
            router=SimpleNamespace(play_sfx=lambda _key: None),
        ),
        sync_audio_bridge_state=lambda: None,
        update_camera=lambda _dt: None,
        render_resources=SimpleNamespace(
            ground=None,
            fx_textures=None,
            fx_queue=[],
            fx_queue_rotated=[],
            consume_terrain_fx_batch=lambda _batch: None,
        ),
    )
    view._max_ticks = None
    view._tick_index = 0
    view._finished = False
    callback_order: list[int] = []
    _capture_output_ticks(mocker, callback_order)

    view._driver = FakePlaybackDriver(tick_limit=2)

    view._advance_runner(
        dt_seconds=2.0 * float(view._dt),
        max_ticks=2,
    )

    assert callback_order == [0, 1]
