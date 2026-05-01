from __future__ import annotations

import json
import subprocess
from typing import Any

import crimson.dbg.record as dbg_record


def test_zig_net_host_builds_rollback_session_json() -> None:
    payload = _run_zig_net_json(
        [
            "host",
            "--mode",
            "rush",
            "--players",
            "3",
            "--relay-host",
            "203.0.113.10",
            "--relay-port",
            "32011",
            "--room-code",
            "AB12",
            "--format",
            "json",
        ],
    )

    assert payload["role"] == "host"
    assert payload["runtime_supported"] is True
    assert payload["mode"] == "rush"
    assert payload["mode_id"] == 2
    assert payload["player_count"] == 3
    assert payload["netcode_mode"] == "rollback"
    assert payload["endpoint"]["relay_host"] == "203.0.113.10"
    assert payload["endpoint"]["relay_port"] == 32011
    assert payload["endpoint"]["room_code"] == "ab12"


def test_zig_net_join_builds_lockstep_session_json() -> None:
    payload = _run_zig_net_json(
        [
            "join",
            "--netcode",
            "lockstep",
            "--host",
            "192.168.1.42",
            "--port",
            "32001",
            "--format",
            "json",
        ],
    )

    assert payload["role"] == "join"
    assert payload["mode"] == "survival"
    assert payload["netcode_mode"] == "lockstep"
    assert payload["endpoint"]["kind"] == "lockstep"
    assert payload["endpoint"]["host"] == "192.168.1.42"
    assert payload["endpoint"]["port"] == 32001


def test_zig_net_join_lockstep_requires_host() -> None:
    result = _run_zig_net_process(["join", "--netcode", "lockstep", "--format", "json"])

    assert result.returncode == 2
    assert result.stdout == ""
    assert "host is required in lockstep mode" in result.stderr


def _run_zig_net_json(args: list[str]) -> dict[str, Any]:
    result = _run_zig_net_process(args)
    assert result.returncode == 0, dbg_record._command_detail(result)
    return json.loads(result.stdout)


def _run_zig_net_process(args: list[str]) -> subprocess.CompletedProcess[str]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    return dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "net", *args],
        cwd=dbg_record._REPO_ROOT,
    )
