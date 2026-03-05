from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest
from builders import FakeRunner

import crimson.modes.replay_playback_mode as replay_playback_mode
from crimson.game_modes import GameMode
from crimson.replay import Replay, ReplayHeader, ReplayTick
from crimson.sim.hooks import TickResult
from crimson.sim.input_providers import InputStatus
from crimson.sim.presentation_step import PresentationStepCommands
from crimson.sim.tick_runner import TickBatchResult
from crimson.sim.world_state import WorldEvents
from crimson.world.render_resources import RenderResources
from crimson.world.sim_world_state import SimWorldState
from crimson.world.terrain_runtime import TerrainRuntime


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


@dataclass
class _StubReplayRuntime:
    """Minimal stub for ``view._runtime`` in replay timing tests."""

    render_resources: RenderResources = field(
        default_factory=lambda: RenderResources(assets_dir=_assets_dir()),
    )


def _replay_with_ticks(tick_count: int) -> Replay:
    return Replay(
        header=ReplayHeader(game_mode_id=GameMode.DEMO, seed=0),
        ticks=[ReplayTick(inputs=[[0.0, 0.0, 0.0, 0.0, 0]]) for _ in range(max(0, int(tick_count)))],
    )


def test_replay_playback_mode_tick_loop_decrements_accum(mocker, replay_playback_view) -> None:
    # Regression test: frame delta should be consumed by runner clock debt and
    # advance the expected number of ticks in one `advance_frame` call.
    import crimson.modes.replay_playback_mode as replay_playback_mode
    view, _console = replay_playback_view

    # Prevent key handlers from running.
    mocker.patch.object(replay_playback_mode.rl, "is_key_pressed", return_value=False)
    view._replay = _replay_with_ticks(16)
    view._runtime = _StubReplayRuntime()
    view._finished = False
    view._paused = False
    view._tick_index = 0
    view._tick_rate = 60
    view._dt = 1.0 / 60.0
    view._dt_accum = 0.0
    view._on_runner_tick_complete = lambda _tick_index, _tick: False

    view._tick_runner = FakeRunner()

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
    view._on_runner_tick_complete = lambda _tick_index, _tick: False

    view._tick_runner = FakeRunner(
        results=[
            TickBatchResult(
                ticks_completed=1,
                batch_status=InputStatus.READY,
                next_tick_index=1,
                completed_results=[
                    TickResult(tick_index=0, dt_sim=1.0 / 60.0, payload=object()),
                ],
            ),
        ],
    )

    view._advance_runner(
        dt_seconds=float(view._dt),
        max_ticks=1,
    )

    assert view._tick_index == 1
    assert not view._finished


def test_replay_runner_eos_applies_partial_completed_results(replay_playback_view) -> None:
    view, _console = replay_playback_view

    view._replay = _replay_with_ticks(2)
    view._runtime = _StubReplayRuntime()
    view._max_ticks = None
    view._tick_index = 0
    view._finished = False
    applied_ticks: list[int] = []
    view._on_runner_tick_complete = lambda tick_index, _tick: applied_ticks.append(int(tick_index)) or False

    view._tick_runner = FakeRunner(
        results=[
            TickBatchResult(
                ticks_completed=2,
                batch_status=InputStatus.EOS,
                next_tick_index=2,
                completed_results=[
                    TickResult(tick_index=0, dt_sim=1.0 / 60.0, payload=object()),
                    TickResult(tick_index=1, dt_sim=1.0 / 60.0, payload=object()),
                ],
            ),
        ],
    )

    view._advance_runner(
        dt_seconds=float(view._dt),
        max_ticks=2,
    )

    assert applied_ticks == [0, 1]
    assert view._tick_index == 2
    assert view._finished is True


def test_replay_runner_preserves_tick_complete_order_for_mixed_payload_batches(replay_playback_view) -> None:
    view, _console = replay_playback_view

    view._replay = _replay_with_ticks(2)
    view._runtime = SimpleNamespace(
        sim_world=SimpleNamespace(apply_step_metadata=lambda **_kwargs: None),
        audio_bridge=SimpleNamespace(
            apply_plan=lambda **_kwargs: None,
            router=None,
        ),
        sync_audio_bridge_state=lambda: None,
        update_camera=lambda _dt: None,
        render_resources=SimpleNamespace(
            ground=None,
            fx_textures=None,
            fx_queue=[],
            fx_queue_rotated=[],
        ),
    )
    view._max_ticks = None
    view._tick_index = 0
    view._finished = False
    callback_order: list[int] = []
    view._on_runner_tick_complete = lambda tick_index, _tick: callback_order.append(int(tick_index)) or False

    step_payload = SimpleNamespace(
        step=SimpleNamespace(
            events=WorldEvents(hits=[], deaths=(), pickups=[], sfx=[]),
            presentation=PresentationStepCommands(),
            dt_sim=1.0 / 60.0,
        ),
        spawn_timeline_ms=0.0,
        completion_transition_ms=-1.0,
        play_hit_sfx=False,
        play_completion_music=False,
    )

    @dataclass
    class _FakeRunner:
        frame_count: int = 0

        def begin_frame(self, frame_ctx) -> None:
            _ = frame_ctx
            self.frame_count += 1

        def advance_ticks(self, *, start_tick: int, ticks_requested: int, tick_dt: float) -> object:
            _ = ticks_requested, tick_dt
            return TickBatchResult(
                ticks_completed=2,
                batch_status=InputStatus.READY,
                next_tick_index=int(start_tick) + 2,
                completed_results=[
                    TickResult(
                        tick_index=int(start_tick),
                        dt_sim=1.0 / 60.0,
                        payload=step_payload,
                    ),
                    TickResult(
                        tick_index=int(start_tick) + 1,
                        dt_sim=1.0 / 60.0,
                        payload=SimpleNamespace(),
                    ),
                ],
            )

    view._tick_runner = _FakeRunner()

    view._advance_runner(
        dt_seconds=float(view._dt),
        max_ticks=2,
    )

    assert callback_order == [0, 1]


def test_replay_open_uses_driver_tick_runner_builder(mocker, replay_playback_view) -> None:
    view, _console = replay_playback_view
    replay = Replay(
        header=ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=0),
        ticks=[ReplayTick(inputs=[[0.0, 0.0, 0.0, 0.0, 0]])],
    )
    captured: dict[str, object] = {}

    class _StopOpen(Exception):
        pass

    class _FakeDriver:
        def __init__(self, *_args, **_kwargs) -> None:
            self.survival_session = object()
            self.rush_session = None
            self.quest_session = None

        def open(self) -> None:
            return

        def build_tick_runner(self) -> object:
            captured["called"] = True
            raise _StopOpen()

    mocker.patch.object(replay_playback_mode, "load_small_font", return_value=None)
    mocker.patch.object(replay_playback_mode, "load_hud_assets", return_value=None)
    mocker.patch.object(replay_playback_mode, "load_replay_file", return_value=replay)
    mocker.patch.object(replay_playback_mode, "init_audio_state", return_value=None)
    mocker.patch.object(replay_playback_mode, "apply_replay_bootstrap", return_value=None)

    @dataclass
    class _StubWorldRuntime:
        sim_world: SimWorldState = field(default_factory=SimWorldState)
        render_resources: RenderResources = field(
            default_factory=lambda: RenderResources(assets_dir=_assets_dir()),
        )
        terrain_runtime: TerrainRuntime = field(default_factory=lambda: TerrainRuntime())
        texture_cache: object = None

        def reset(self, **_kw: object) -> None:
            pass

        def open_runtime(self) -> None:
            pass

    mocker.patch.object(
        replay_playback_mode,
        "WorldRuntime",
        lambda **_kwargs: _StubWorldRuntime(),
    )
    mocker.patch.object(replay_playback_mode, "PlaybackDriver", _FakeDriver)

    with pytest.raises(_StopOpen):
        view.open()

    assert captured.get("called") is True
