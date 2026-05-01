from __future__ import annotations

import json
import subprocess
from pathlib import Path

import msgspec
from typer.testing import CliRunner

import crimson.dbg.record as dbg_record
from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.replay import ReplayClaimedStatsSnapshot
from crimson.weapons import WeaponId

from ._helpers import build_replay, write_replay


def test_zig_replay_verify_respects_max_ticks_partial_run_contract(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json", "--max-ticks", "2"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json", "--max-ticks", "2"],
    )

    assert zig_payload == python_payload


def test_zig_replay_verify_matches_python_full_payload_on_simple_replay(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json"],
    )

    assert zig_payload == python_payload


def test_zig_replay_verify_writes_json_out_like_python(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    json_out = tmp_path / "reports" / "verify.json"

    result = _run_zig_replay_verify_process(
        [str(replay_path), "--format", "json", "--json-out", str(json_out)],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    stdout_payload = json.loads(result.stdout)
    file_payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert file_payload == stdout_payload


def test_zig_replay_verify_reports_header_claim_mismatch_like_python(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay = msgspec.structs.replace(
        replay,
        header=msgspec.structs.replace(
            replay.header,
            claimed_stats=ReplayClaimedStatsSnapshot(
                complete=True,
                ticks=2,
                elapsed_ms=1,
                score_xp=999,
                kills=4,
                most_used_weapon_id=WeaponId.PISTOL,
                shots_fired=2,
                shots_hit=1,
            ),
        ),
    )
    replay_path = write_replay(tmp_path, replay=replay, name="survival-claimed-bad.crd")

    python_result = _run_python_replay_verify_process([str(replay_path), "--format", "json"])
    zig_result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert python_result.exit_code == 3, python_result.output
    assert zig_result.returncode == 3, dbg_record._command_detail(zig_result)
    assert json.loads(zig_result.stdout) == json.loads(python_result.output)


def _run_python_replay_verify(args: list[str]) -> dict[str, object]:
    result = _run_python_replay_verify_process(args)
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _run_python_replay_verify_process(args: list[str]):
    runner = CliRunner()
    result = runner.invoke(app, ["replay", "verify", *args])
    return result


def _run_zig_replay_verify(args: list[str]) -> dict[str, object]:
    verify_run = _run_zig_replay_verify_process(args)
    assert verify_run.returncode == 0, dbg_record._command_detail(verify_run)
    return json.loads(verify_run.stdout)


def _run_zig_replay_verify_process(args: list[str]) -> subprocess.CompletedProcess[str]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    return dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "replay", "verify", *args],
        cwd=dbg_record._REPO_ROOT,
    )
