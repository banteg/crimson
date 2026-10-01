from __future__ import annotations

import itertools

import msgspec
from pytest_mock import MockerFixture
from typer.testing import CliRunner

from crimson.cli import app
from crimson.replay import Replay, load_replay_file
from crimson.replay.checkpoints import load_checkpoints_file
from crimson.replay.driver.playback_driver import PlaybackDriver, PlaybackWalkObserver, build_verify_playback_driver
from crimson.replay.rng_call_order import UNTAGGED_CALLER, caller_names
from crimson.sim.hooks import TickResult
from crimson.sim.world_state import WorldState
from grim.rand import CallerStatic, CrtRand
from tests.support.replay_runner_helpers import RECORDED_REPLAYS

_FIXTURE = next(path for path in RECORDED_REPLAYS if path.name == "quest-2.5-completed.crd")


class _TickCallers(PlaybackWalkObserver):
    driver: PlaybackDriver
    callers_by_tick: list[list[int]]

    def after_tick(self, tick_result: TickResult, world: WorldState) -> None:
        self.callers_by_tick.append(list(self.driver.rng_call_order.callers))


def _callers_by_tick(replay: Replay, *, max_ticks: int) -> list[list[int]]:
    driver = build_verify_playback_driver(replay, max_ticks=max_ticks, warn_on_version_mismatch=False)
    observer = _TickCallers(driver=driver, callers_by_tick=[])
    driver.run(observer=observer)
    return observer.callers_by_tick


def test_verify_checkpoints_catches_draws_reordered_within_a_tick(mocker: MockerFixture) -> None:
    replay = load_replay_file(_FIXTURE)
    expected = {
        ckpt.tick_index: ckpt for ckpt in load_checkpoints_file(_FIXTURE.with_name(f"{_FIXTURE.name}.chk")).checkpoints
    }
    callers_by_tick = _callers_by_tick(replay, max_ticks=600)
    # The first tick after the opening second with two consecutive draws from different tagged call sites.
    tick, pos = next(
        (tick, pos)
        for tick, callers in enumerate(callers_by_tick)
        if tick >= 60
        for pos in range(len(callers) - 1)
        if callers[pos] != callers[pos + 1] and UNTAGGED_CALLER not in callers[pos : pos + 2]
    )
    first, second = callers_by_tick[tick][pos : pos + 2]
    swap_at = sum(len(callers) for callers in callers_by_tick[:tick]) + pos

    # Swap which call site each of the two draws belongs to, as swapping the two draw statements would. The
    # draw count, and so the RNG state after the tick, stays the same.
    draw = CrtRand._draw
    traced_draws = itertools.count()

    def reordered_draw(self: CrtRand, caller: CallerStatic | None) -> int:
        if self.trace_sink is not None:  # the world RNG while a tick records its call order
            index = next(traced_draws)
            caller = {swap_at: second, swap_at + 1: first}.get(index, caller)
        return draw(self, caller)

    mocker.patch.object(CrtRand, "_draw", reordered_draw)
    driver = build_verify_playback_driver(replay, max_ticks=tick + 1, warn_on_version_mismatch=False)
    driver.walk_ticks(stop_tick=tick)
    actual = driver.build_checkpoint(tick_result=driver.step_tick(tick))
    reordered = list(driver.rng_call_order.callers)

    # Every field the checkpoint had before the call-order digest, the RNG state included, still matches.
    assert reordered[pos : pos + 2] == [second, first]
    assert actual.rng_state == expected[tick].rng_state
    assert actual.rng_callers_crc32 != expected[tick].rng_callers_crc32
    assert msgspec.structs.replace(actual, rng_callers_crc32=expected[tick].rng_callers_crc32) == expected[tick]

    # The verifier replays from tick 0: count its draws afresh.
    traced_draws = itertools.count()
    result = CliRunner().invoke(app, ["replay", "verify-checkpoints", str(_FIXTURE), "--max-ticks", str(tick + 1)])

    assert result.exit_code == 1
    assert f"checkpoint mismatch at tick={tick}\n" in result.output
    assert f"rng_state expected={actual.rng_state} actual={actual.rng_state}\n" in result.output
    assert (
        f"rng call order diverged at tick={tick}: {len(reordered)} draws {caller_names(reordered)}\n" in result.output
    )
