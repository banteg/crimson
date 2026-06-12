from __future__ import annotations

import json
from pathlib import Path

import msgspec
import pytest

from crimson.dbg.diff import diff_traces
from crimson.dbg.record import record_replay_to_trace
from crimson.dbg.trace import TraceReader, iter_trace_ticks
from crimson.replay.codec import dump_replay_file, load_replay_file

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "captures"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"

if not MANIFEST_PATH.is_file():
    pytest.skip(
        "no capture fixtures imported (run `just capture-fixtures-import`)",
        allow_module_level=True,
    )

MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
CASES = {case["name"]: case for case in MANIFEST["cases"]}

pytestmark = [pytest.mark.replay_fixture]


@pytest.fixture(scope="session")
def recorded_candidates() -> dict[str, Path]:
    return {}


def _candidate_trace(case: dict, recorded: dict[str, Path], tmp_path_factory: pytest.TempPathFactory) -> Path:
    name = case["name"]
    if name in recorded:
        return recorded[name]
    work_dir = tmp_path_factory.mktemp(f"capture_{name}")
    replay = load_replay_file(FIXTURE_DIR / case["crd"])
    last_window_end = int(case["windows"][-1]["end_tick"])
    trimmed = msgspec.structs.replace(replay, ticks=replay.ticks[: last_window_end + 1])
    trimmed_crd = work_dir / "window.crd"
    candidate_cdt = work_dir / "candidate.cdt"
    dump_replay_file(trimmed_crd, trimmed)
    record_replay_to_trace(
        replay_path=trimmed_crd,
        out_path=candidate_cdt,
        warnings_out=[],
        pre_tick_rand_draws=int(case["outside_draws_per_tick"] or 0),
    )
    recorded[name] = candidate_cdt
    return candidate_cdt


@pytest.mark.parametrize("name", sorted(CASES))
def test_fixture_metadata_matches_manifest(name: str) -> None:
    case = CASES[name]
    windows = case["windows"]
    with TraceReader(FIXTURE_DIR / case["cdt"]) as trace:
        assert trace.meta.producer.impl == "frida_original"
        assert int(trace.meta.tick_range.start_tick) == int(windows[0]["start_tick"])
        assert int(trace.meta.tick_range.end_tick) == int(windows[-1]["end_tick"])
        assert int(trace.meta.tick_range.tick_count) == int(case["window_tick_count"])
        assert str(trace.meta.source.run_start_seed_source) == str(case["seed_source"])
    assert sum(int(window["tick_count"]) for window in windows) == int(case["window_tick_count"])
    replay = load_replay_file(FIXTURE_DIR / case["crd"])
    assert int(replay.header.seed) == int(case["seed"])
    assert int(replay.header.game_mode_id) == int(case["game_mode_id"])
    assert len(replay.ticks) == int(case["tick_count"])


@pytest.mark.parametrize(
    "name",
    sorted(
        name
        for name, case in CASES.items()
        if case["seed_aligned"] and case["native_first_draw"] is not None
    ),
)
def test_first_gameplay_draw_matches_native(
    name: str,
    recorded_candidates: dict[str, Path],
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Ratchet: with the capture-derived seed, our sim's first in-tick rng draw
    must replay the native capture's draw exactly (same tick, state, value, caller)."""
    case = CASES[name]
    candidate = _candidate_trace(case, recorded_candidates, tmp_path_factory)
    expected = case["native_first_draw"]
    for tick in iter_trace_ticks(candidate):
        rows = tick.channels.rng_stream
        if not rows:
            continue
        row = rows[0]
        assert int(tick.tick_index) == int(expected["tick_index"])
        assert int(row.state_before_u32) == int(expected["state_before_u32"])
        assert int(row.value_15) == int(expected["value_15"])
        caller = -1 if row.caller is None else int(row.caller)
        assert caller == int(expected["caller"])
        return
    pytest.fail(f"{name}: candidate trace has no rng draws within the recorded window")


def _window_cases() -> list[tuple[str, int, int]]:
    return [
        (name, int(window["start_tick"]), int(window["end_tick"]))
        for name, case in sorted(CASES.items())
        for window in case["windows"]
    ]


@pytest.mark.parametrize(
    ("name", "start_tick", "end_tick"),
    _window_cases(),
    ids=[f"{name}-{start}..{end}" for name, start, end in _window_cases()],
)
@pytest.mark.xfail(
    strict=True,
    reason=(
        "known capture parity gaps: native burns rng draws outside the hooked gameplay "
        "stream (see the .rng_evidence.json finalize reports), native weapon state at "
        "run start is not modeled, and capture encodes some channel fields as raw f32 "
        "bit patterns"
    ),
)
def test_capture_window_strict_diff(
    name: str,
    start_tick: int,
    end_tick: int,
    recorded_candidates: dict[str, Path],
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    case = CASES[name]
    candidate = _candidate_trace(case, recorded_candidates, tmp_path_factory)
    report = diff_traces(
        expected_trace_path=FIXTURE_DIR / case["cdt"],
        actual_trace_path=candidate,
        tick_start=start_tick,
        tick_end=end_tick,
    )
    assert report.ok, msgspec.json.encode(report.mismatch).decode()
