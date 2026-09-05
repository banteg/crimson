from __future__ import annotations

import json
import struct
import subprocess
from pathlib import Path

import msgspec
import pytest

import crimson.dbg.record as dbg_record
from crimson.dbg.diff import diff_traces
from crimson.dbg.health import summarize_trace_health
from crimson.dbg.schema import TickRecord
from crimson.dbg.trace import load_trace, write_trace
from crimson.game_modes import GameMode
from crimson.replay.codec import dump_replay_file
from tests.debug.test_dbg_trace import _write_raw_trace, _write_unchecked_trace
from tests.replay.cli._helpers import build_replay


@pytest.fixture(scope="module")
def zig_bin() -> Path:
    build = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build.returncode == 0, dbg_record._command_detail(build)
    return dbg_record._ZIG_BIN


def _zig(binary: Path, *args: str | Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(binary), "dbg", *map(str, args)], capture_output=True, text=True, check=False)


@pytest.fixture
def fresh_trace(tmp_path: Path) -> Path:
    replay_path = tmp_path / "survival.crd"
    dump_replay_file(replay_path, build_replay(mode=GameMode.SURVIVAL, ticks=5))
    path = tmp_path / "survival.cdt"
    dbg_record.record_replay_to_trace(replay_path=replay_path, out_path=path, impl="python")
    return path


@pytest.mark.parametrize(
    ("channel", "path", "value"),
    [
        ("replay_step", ("inputs", 0, "aim_x"), 123.0),
        ("sim_state", ("players", 0, "health"), 17.0),
        ("entity_samples", ("creatures", 0, "hp"), 123.0),
        ("timing_samples", (0, "time_scale_factor"), 0.5),
        ("checkpoint", ("players", 0, "health"), 17.0),
    ],
)
def test_zig_compares_channel_contents(zig_bin: Path, fresh_trace: Path, channel, path, value) -> None:
    meta, ticks, _ = load_trace(fresh_trace)
    raw = msgspec.to_builtins(ticks[2])
    target = raw["channels"][channel]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    ticks[2] = msgspec.convert(raw, type=TickRecord)
    changed = fresh_trace.with_name("changed.cdt")
    write_trace(changed, meta=meta, ticks=ticks)
    assert not diff_traces(expected_trace_path=fresh_trace, actual_trace_path=changed).ok
    for command in ["diff", "bisect", "focus"]:
        args = ["--tick", "2"] if command == "focus" else []
        result = _zig(zig_bin, command, fresh_trace, changed, "--json", *args)
        assert result.returncode == (1 if command == "diff" else 0), result.stderr
        report = json.loads(result.stdout)
        assert report["mismatch"]["tick_index"] == 2
        assert report["mismatch"]["field"].startswith(channel)
        assert report["mismatch"]["actual_float"] == value
        if command == "diff":
            assert report["channel_first_mismatches"][channel] == report["mismatch"]
    assert _zig(zig_bin, "diff", fresh_trace, changed, "--tick-end", "1").returncode == 0


@pytest.mark.parametrize(
    "fault", ["rng", "checkpoint", "timing", "missing", "unknown", "f64", "stage", "flags", "old_schema"],
)
def test_both_readers_reject_invalid_fresh_trace(zig_bin: Path, fresh_trace: Path, fault: str) -> None:
    meta, ticks, _ = load_trace(fresh_trace)
    meta_raw = msgspec.msgpack.decode(msgspec.msgpack.encode(meta))
    block = {"start_tick": 0, "end_tick": 4, "ticks": msgspec.msgpack.decode(msgspec.msgpack.encode(ticks))}
    channels = block["ticks"][0]["channels"]
    match fault:
        case "rng":
            channels["rng_stream"][0]["value_15"] ^= 1
        case "checkpoint":
            channels["checkpoint"]["tick_index"] = 99
        case "timing":
            channels["timing_samples"][0]["phase"] = "wrong"
        case "missing":
            del channels["sim_state"]["players"][0]["health"]
        case "unknown":
            channels["sim_state"]["extra"] = 0
        case "f64":
            channels["sim_state"]["players"][0]["health"] = 0.1
        case "stage":
            channels["sim_state"]["gameplay"]["quest_stage_major"] = 1
        case "flags":
            channels["replay_step"]["inputs"][0]["flags"] = 1 << 31
        case "old_schema":
            meta_raw["trace_schema_version"] -= 1
    changed = fresh_trace.with_name("invalid.cdt")
    _write_raw_trace(changed, meta_raw=meta_raw, block_raw=block)
    assert not summarize_trace_health(changed)["ok_for_parity_analysis"]
    assert _zig(zig_bin, "health", changed, "--format", "json").returncode != 0
    assert _zig(zig_bin, "diff", changed, changed).returncode != 0


def test_zig_compares_all_channels_and_treats_callers_as_diagnostics(zig_bin: Path, fresh_trace: Path) -> None:
    meta, ticks, _ = load_trace(fresh_trace)
    ticks[0].channels.rng_stream[0] = msgspec.structs.replace(ticks[0].channels.rng_stream[0], caller=None)
    changed = fresh_trace.with_name("callers.cdt")
    write_trace(changed, meta=meta, ticks=ticks)
    result = _zig(zig_bin, "diff", fresh_trace, changed, "--json")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["channel_first_diagnostics"]["rng_stream"] is not None
    ticks[1].channels.sim_state.players[0] = msgspec.structs.replace(
        ticks[1].channels.sim_state.players[0], health=17.0,
    )
    ticks[3].channels.replay_step.inputs[0] = msgspec.structs.replace(
        ticks[3].channels.replay_step.inputs[0], aim_x=123.0,
    )
    write_trace(changed, meta=meta, ticks=ticks)
    result = _zig(zig_bin, "diff", fresh_trace, changed, "--json")
    report = json.loads(result.stdout)
    assert result.returncode == 1
    assert report["mismatch"]["tick_index"] == 1
    assert report["channel_first_mismatches"]["sim_state"]["tick_index"] == 1
    assert report["channel_first_mismatches"]["replay_step"]["tick_index"] == 3


def test_zig_entity_order_and_tick_coverage(zig_bin: Path, fresh_trace: Path) -> None:
    meta, ticks, _ = load_trace(fresh_trace)
    for tick in ticks:
        tick.channels.entity_samples.creatures.reverse()
    changed = fresh_trace.with_name("reordered.cdt")
    write_trace(changed, meta=meta, ticks=ticks)
    assert _zig(zig_bin, "diff", fresh_trace, changed).returncode == 0
    del ticks[2]
    meta = msgspec.structs.replace(meta, tick_range=msgspec.structs.replace(meta.tick_range, tick_count=4))
    _write_unchecked_trace(changed, meta=meta, ticks=ticks)
    assert not summarize_trace_health(changed)["ok_for_parity_analysis"]
    assert _zig(zig_bin, "health", changed, "--format", "json").returncode == 1
    for left, right, kind in [(fresh_trace, changed, "missing_tick"), (changed, fresh_trace, "extra_tick")]:
        result = _zig(zig_bin, "diff", left, right, "--json")
        assert result.returncode == 1
        assert json.loads(result.stdout)["mismatch"]["kind"] == kind
    assert _zig(zig_bin, "focus", fresh_trace, fresh_trace, "--tick", "99").returncode != 0


@pytest.mark.parametrize(("mode", "level"), [(GameMode.SURVIVAL, ""), (GameMode.RUSH, ""), (GameMode.QUESTS, "1.1")])
def test_fresh_python_and_zig_trace_parity(zig_bin: Path, tmp_path: Path, mode: GameMode, level: str) -> None:
    replay = tmp_path / "run.crd"
    dump_replay_file(replay, build_replay(mode=mode, ticks=5, quest_level=level))
    python_trace, zig_trace = tmp_path / "python.cdt", tmp_path / "zig.cdt"
    dbg_record.record_replay_to_trace(replay_path=replay, out_path=python_trace, impl="python")
    result = _zig(zig_bin, "record", replay, "--out", zig_trace)
    assert result.returncode == 0, result.stderr
    report = diff_traces(expected_trace_path=python_trace, actual_trace_path=zig_trace)
    assert report.ok, report.mismatch
    assert _zig(zig_bin, "diff", python_trace, zig_trace).returncode == 0
    if mode == GameMode.RUSH:
        _, ticks, _ = load_trace(python_trace)
        # Native 0x407336 fmul then 0x40733c fadd, with f32 constants and PC24.
        assert struct.pack("<f", ticks[0].channels.entity_samples.creatures[0].tint.r).hex() == "b29a993e"
