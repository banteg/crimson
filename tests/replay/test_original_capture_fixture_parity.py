from __future__ import annotations

import json
from pathlib import Path

import msgspec
import pytest

from crimson.dbg.diff import diff_traces
from crimson.dbg.record import record_replay_to_trace
from crimson.dbg.schema import TRACE_FORMAT_VERSION, TRACE_SCHEMA_VERSION
from crimson.dbg.trace import TraceReader, iter_trace_ticks
from crimson.replay.codec import load_replay_file
from crimson.replay.types import REPLAY_FORMAT_VERSION

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "captures"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"

if not MANIFEST_PATH.is_file():
    pytest.skip(
        "no capture fixtures imported (run `just capture-fixtures-import`)",
        allow_module_level=True,
    )

MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
assert int(MANIFEST["format_version"]) == 1
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
    replay_path = FIXTURE_DIR / case["crd"]
    candidate_cdt = work_dir / "candidate.cdt"
    record_replay_to_trace(
        replay_path=replay_path,
        out_path=candidate_cdt,
        warnings_out=[],
    )
    recorded[name] = candidate_cdt
    return candidate_cdt


@pytest.mark.parametrize("name", sorted(CASES))
def test_fixture_metadata_matches_manifest(name: str) -> None:
    case = CASES[name]
    tick_range = case["trace_tick_range"]
    with TraceReader(FIXTURE_DIR / case["cdt"]) as trace:
        assert trace.meta.producer.impl == "frida_original"
        assert int(trace.meta.tick_range.start_tick) == int(tick_range["start_tick"])
        assert int(trace.meta.tick_range.end_tick) == int(tick_range["end_tick"])
        assert int(trace.meta.tick_range.tick_count) == int(tick_range["tick_count"])
        assert str(trace.meta.source.run_start_seed_source) == str(case["seed_source"])
        assert int(trace.meta.trace_format_version) == int(TRACE_FORMAT_VERSION)
        assert int(trace.meta.trace_schema_version) == int(TRACE_SCHEMA_VERSION)
        assert int(case["trace_format_version"]) == int(TRACE_FORMAT_VERSION)
        assert int(case["trace_schema_version"]) == int(TRACE_SCHEMA_VERSION)
    replay = load_replay_file(FIXTURE_DIR / case["crd"])
    assert int(replay.header.seed) == int(case["seed"])
    assert int(replay.header.game_mode_id) == int(case["game_mode_id"])
    assert int(replay.header.replay_format_version) == int(REPLAY_FORMAT_VERSION)
    assert int(case["replay_format_version"]) == int(REPLAY_FORMAT_VERSION)
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
    pytest.fail(f"{name}: candidate trace has no rng draws")


@pytest.mark.parametrize(
    "name",
    sorted(CASES),
)
def test_capture_strict_diff(
    name: str,
    recorded_candidates: dict[str, Path],
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    case = CASES[name]
    candidate = _candidate_trace(case, recorded_candidates, tmp_path_factory)
    report = diff_traces(
        expected_trace_path=FIXTURE_DIR / case["cdt"],
        actual_trace_path=candidate,
    )
    assert report.ok, msgspec.json.encode(report.mismatch).decode()
