from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import crimson.dbg.record as dbg_record
from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.sim.input_providers import PerkPickCommand

from ._helpers import (
    build_replay,
    inject_tick_commands,
    write_current_bad_event_player_index_replay,
    write_current_bad_tick_player_count_replay,
    write_current_missing_perk_choice_replay,
    write_current_typo_event_replay,
    write_current_unknown_command_replay,
    write_replay,
)


def test_zig_replay_benchmark_reports_headless_summary(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = _run_zig_replay_benchmark(
        [str(replay_path), "--runs", "2", "--warmup-runs", "0", "--max-ticks", "2"],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "ok: mode=headless runs=2 warmup_runs=0 ticks=2" in result.stdout
    lines = result.stdout.splitlines()
    wall_ms_line = next(line for line in lines if line.startswith("wall_ms "))
    throughput_line = next(line for line in lines if line.startswith("throughput_tps "))
    assert " p50=" in wall_ms_line
    assert " p95=" in wall_ms_line
    assert " stdev=" in wall_ms_line
    assert " p50=" in throughput_line
    assert " p95=" in throughput_line
    assert " stdev=" in throughput_line
    assert " | realtime_x " in throughput_line
    assert "json_report=None" not in result.stdout


def test_zig_replay_benchmark_emits_json_payload(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = _run_zig_replay_benchmark(
        [str(replay_path), "--runs", "2", "--warmup-runs", "0", "--max-ticks", "2", "--format", "json"],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 3
    assert payload["status"] == "ok"
    assert payload["settings"] == {
        "mode": "headless",
        "runs": 2,
        "warmup_runs": 0,
        "max_ticks": 2,
        "trace_rng": False,
        "profile": False,
        "profile_sort": "cumtime",
        "top": 20,
        "profile_out": None,
        "render_telemetry": False,
        "render_telemetry_out": None,
        "render_charts_out_dir": None,
    }
    assert payload["run_result"]["ticks"] == 2
    assert "creature_kill_count" in payload["run_result"]
    assert "kills" not in payload["run_result"]
    assert payload["benchmark"]["sample_count"] == 2
    assert len(payload["benchmark"]["samples"]) == 2
    assert "run_index" not in payload["benchmark"]["samples"][0]
    assert set(payload["benchmark"]["wall_ms"]) == {"min", "p50", "mean", "p95", "max", "stdev"}
    assert payload["benchmark"]["wall_ms"]["max"] >= payload["benchmark"]["wall_ms"]["min"] >= 0.0
    assert payload["benchmark"]["ticks_per_second"]["max"] >= payload["benchmark"]["ticks_per_second"]["min"] >= 0.0
    assert payload["profile"] is None
    assert payload["render_telemetry"] is None


def test_zig_replay_benchmark_accepts_relative_base_dir(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    write_replay(tmp_path / "replays", replay=replay, name="relative.crd")
    relative_base = os.path.relpath(tmp_path, dbg_record._REPO_ROOT)

    result = _run_zig_replay_benchmark(
        [
            "relative.crd",
            "--base-dir",
            relative_base,
            "--runs",
            "1",
            "--warmup-runs",
            "0",
            "--format",
            "json",
        ],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["replay"] == f"{relative_base}/replays/relative.crd"
    assert payload["run_result"]["ticks"] == 2


def test_zig_replay_benchmark_matches_python_stable_json_payload(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    args = [str(replay_path), "--runs", "1", "--warmup-runs", "0", "--max-ticks", "2", "--format", "json"]

    python_result = CliRunner().invoke(app, ["replay", "benchmark", *args])
    assert python_result.exit_code == 0, python_result.output

    zig_result = _run_zig_replay_benchmark(args)
    assert zig_result.returncode == 0, dbg_record._command_detail(zig_result)

    python_payload = json.loads(python_result.output)
    zig_payload = json.loads(zig_result.stdout)
    for key in ("schema_version", "status", "replay", "settings", "run_result", "profile", "render_telemetry"):
        assert zig_payload[key] == python_payload[key]
    assert zig_payload["benchmark"]["sample_count"] == python_payload["benchmark"]["sample_count"]
    assert zig_payload["benchmark"]["samples"][0].keys() == python_payload["benchmark"]["samples"][0].keys()
    for key in ("wall_ms", "ticks_per_second", "realtime_x"):
        assert zig_payload["benchmark"][key].keys() == python_payload["benchmark"][key].keys()


def test_zig_replay_benchmark_matches_python_tutorial_run_result(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.TUTORIAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="tutorial.crd")
    args = [str(replay_path), "--runs", "1", "--warmup-runs", "0", "--max-ticks", "2", "--format", "json"]

    python_result = CliRunner().invoke(app, ["replay", "benchmark", *args])
    assert python_result.exit_code == 0, python_result.output

    zig_result = _run_zig_replay_benchmark(args)
    assert zig_result.returncode == 0, dbg_record._command_detail(zig_result)

    python_payload = json.loads(python_result.output)
    zig_payload = json.loads(zig_result.stdout)
    assert zig_payload["replay"] == python_payload["replay"]
    assert zig_payload["settings"] == python_payload["settings"]
    assert zig_payload["run_result"] == python_payload["run_result"]


def test_zig_replay_benchmark_supports_trace_rng(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = _run_zig_replay_benchmark(
        [
            str(replay_path),
            "--runs",
            "1",
            "--warmup-runs",
            "0",
            "--max-ticks",
            "2",
            "--trace-rng",
            "--format",
            "json",
        ],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    payload = json.loads(result.stdout)
    assert payload["settings"]["trace_rng"] is True
    assert payload["run_result"]["ticks"] == 2
    assert payload["benchmark"]["sample_count"] == 1


def test_zig_replay_benchmark_writes_json_out(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    json_out = tmp_path / "reports" / "benchmark.json"

    result = _run_zig_replay_benchmark(
        [str(replay_path), "--runs", "1", "--warmup-runs", "0", "--json-out", str(json_out)],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert f"json_report={json_out}" in result.stdout
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["benchmark"]["sample_count"] == 1
    assert payload["run_result"]["ticks"] == 2


def test_zig_replay_benchmark_supports_native_profile_summary(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    profile_out = tmp_path / "profiles" / "native-profile.json"

    result = _run_zig_replay_benchmark(
        [
            str(replay_path),
            "--runs",
            "1",
            "--warmup-runs",
            "0",
            "--max-ticks",
            "2",
            "--profile",
            "--profile-sort",
            "tottime",
            "--top",
            "5",
            "--profile-out",
            str(profile_out),
            "--format",
            "json",
        ],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    payload = json.loads(result.stdout)
    assert payload["settings"]["profile"] is True
    assert payload["settings"]["profile_sort"] == "tottime"
    assert payload["settings"]["top"] == 5
    assert payload["settings"]["profile_out"] == str(profile_out)
    assert payload["profile"]["sort"] == "tottime"
    assert payload["profile"]["source"] == "project"
    assert payload["profile"]["top"] == 5
    assert len(payload["profile"]["hotspots"]) == 1
    hotspot = payload["profile"]["hotspots"][0]
    assert hotspot["file"] == "crimson-zig/src/replay_benchmark_native.zig"
    assert hotspot["function"] == "runReplayWithOptions"
    assert hotspot["primitive_calls"] == 1
    assert hotspot["total_calls"] == 1
    assert hotspot["cumtime"] >= 0.0
    profile_payload = json.loads(profile_out.read_text(encoding="utf-8"))
    assert profile_payload["sort"] == payload["profile"]["sort"]
    assert profile_payload["source"] == payload["profile"]["source"]
    assert profile_payload["hotspots"][0]["function"] == "runReplayWithOptions"


def test_zig_replay_benchmark_stale_perk_pick_is_noop(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    inject_tick_commands(replay, 0, [PerkPickCommand(player_index=0, choice_index=0)])
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = _run_zig_replay_benchmark(
        [str(replay_path), "--runs", "1", "--warmup-runs", "0", "--format", "json"],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["run_result"]["ticks"] == 1


def test_zig_replay_benchmark_reports_tick_player_count_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_bad_tick_player_count_replay(
        tmp_path,
        replay=replay,
        name="bad-tick-player-count.crd",
    )

    result = _run_zig_replay_benchmark([str(replay_path), "--runs", "1", "--warmup-runs", "0"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay benchmark failed: replay tick 0 has 0 players, expected 1" in result.stderr
    assert "canonical wire shape" not in result.stderr


def test_zig_replay_benchmark_reports_event_shape_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_missing_perk_choice_replay(
        tmp_path,
        replay=replay,
        name="missing-perk-choice.crd",
    )

    result = _run_zig_replay_benchmark([str(replay_path), "--runs", "1", "--warmup-runs", "0"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay benchmark failed: replay prelude perk_pick missing choice_index: tick=0 operation_index=0"
        in result.stderr
    )
    assert "canonical wire shape" not in result.stderr


def test_zig_replay_benchmark_reports_event_player_index_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_bad_event_player_index_replay(
        tmp_path,
        replay=replay,
        name="event-player-index.crd",
    )

    result = _run_zig_replay_benchmark([str(replay_path), "--runs", "1", "--warmup-runs", "0"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay benchmark failed: replay prelude player_index out of range: 1 "
        "(player_count=1, tick=0, event=perk_menu_open)"
    ) in result.stderr
    assert "native replay benchmark" not in result.stderr


def test_zig_replay_benchmark_reports_event_kind_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_typo_event_replay(tmp_path, replay=replay, name="event-kind.crd")

    result = _run_zig_replay_benchmark([str(replay_path), "--runs", "1", "--warmup-runs", "0"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay benchmark failed: replay command invalid for game mode: "
        "type=typo_char tick=0 command_index=0 game_mode=survival"
    ) in result.stderr
    assert "replay events include invalid kinds or values for this mode" not in result.stderr


def test_zig_replay_benchmark_reports_unknown_command_as_replay_failure(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_unknown_command_replay(tmp_path, replay=replay, name="unknown-command.crd")

    result = _run_zig_replay_benchmark([str(replay_path), "--runs", "1", "--warmup-runs", "0"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay benchmark failed: replay command type is unknown: "
        "type=network_ping tick=0 command_index=0"
    ) in result.stderr
    assert "native replay benchmark" not in result.stderr


def test_zig_replay_benchmark_rejects_render_mode(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = _run_zig_replay_benchmark([str(replay_path), "--mode", "render"])

    assert result.returncode == 1
    assert "native replay benchmark supports only --mode headless" in result.stderr


@pytest.mark.parametrize(
    ("args", "detail"),
    [
        (["--rtx"], "native replay benchmark does not support render-mode option --rtx"),
        (
            ["--render-telemetry"],
            "native replay benchmark does not support render-mode option --render-telemetry",
        ),
        (
            ["--render-telemetry-out", "telemetry.json"],
            "native replay benchmark does not support render-mode option --render-telemetry-out",
        ),
        (
            ["--render-charts-out-dir", "charts"],
            "native replay benchmark does not support render-mode option --render-charts-out-dir",
        ),
    ],
)
def test_zig_replay_benchmark_rejects_render_only_flags_in_headless_mode(
    tmp_path: Path,
    args: list[str],
    detail: str,
) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = _run_zig_replay_benchmark([str(replay_path), *args])

    assert result.returncode == 1
    assert f"invalid replay benchmark args: {detail}" in result.stderr


def test_zig_replay_benchmark_human_profile_out_reports_path(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    profile_out = tmp_path / "profiles" / "native-profile.json"

    result = _run_zig_replay_benchmark(
        [
            str(replay_path),
            "--runs",
            "1",
            "--warmup-runs",
            "0",
            "--profile",
            "--profile-out",
            str(profile_out),
        ],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert f"profile_report={profile_out}" in result.stdout
    assert profile_out.is_file()


def test_zig_replay_benchmark_rejects_non_crd_extension(tmp_path: Path) -> None:
    replay_path = tmp_path / "survival.txt"
    replay_path.write_bytes(b"not checked before extension validation")

    result = _run_zig_replay_benchmark([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay benchmark failed: replay file must use .crd extension" in result.stderr


def _run_zig_replay_benchmark(args: list[str]) -> subprocess.CompletedProcess[str]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    return dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "replay", "benchmark", *args],
        cwd=dbg_record._REPO_ROOT,
    )
