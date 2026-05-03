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


def test_zig_net_smoke_rollback_reports_live_exchange() -> None:
    payload = _run_zig_net_json(["smoke-rollback", "--format", "json"])

    assert payload["status"] == "ok"
    assert payload["runtime_supported"] is True
    assert payload["player_count"] == 2
    assert payload["host_input_flags"] == 3
    assert payload["guest_input_flags"] == 7
    assert payload["impairment"] == "none"
    assert payload["delayed_packets"] == 0
    assert payload["released_packets"] == 0
    assert payload["dropped_packets"] == 0
    assert payload["host_resync_count"] == 0
    assert payload["guest_resync_count"] == 0
    assert payload["host_live_ticks_advanced"] >= 1
    assert payload["guest_live_ticks_advanced"] >= 1


def test_zig_net_smoke_rollback_reports_delayed_input_recovery() -> None:
    payload = _run_zig_net_json(
        [
            "smoke-rollback",
            "--impair",
            "delay-first-guest-input",
            "--format",
            "json",
        ],
    )

    assert payload["status"] == "ok"
    assert payload["impairment"] == "delay-first-guest-input"
    assert payload["host_input_flags"] == 3
    assert payload["guest_input_flags"] == 7
    assert payload["delayed_packets"] == 1
    assert payload["released_packets"] == 1
    assert payload["dropped_packets"] == 0
    assert payload["host_rollback_count"] >= 1
    assert payload["host_prediction_mismatches"] >= 1
    assert payload["host_resync_count"] == 0
    assert payload["guest_resync_count"] == 0


def test_zig_net_smoke_rollback_reports_reordered_input_recovery() -> None:
    payload = _run_zig_net_json(
        [
            "smoke-rollback",
            "--impair",
            "reorder-first-guest-input",
            "--format",
            "json",
        ],
    )

    assert payload["status"] == "ok"
    assert payload["impairment"] == "reorder-first-guest-input"
    assert payload["host_input_flags"] == 4
    assert payload["guest_input_flags"] == 5
    assert payload["host_tick_index"] == payload["guest_tick_index"] == 2
    assert payload["delayed_packets"] == 1
    assert payload["released_packets"] == 1
    assert payload["dropped_packets"] == 0
    assert payload["host_rollback_count"] >= 1
    assert payload["guest_rollback_count"] >= 1
    assert payload["host_prediction_mismatches"] >= 1
    assert payload["guest_prediction_mismatches"] >= 1
    assert payload["host_resync_count"] == 0
    assert payload["guest_resync_count"] == 0


def test_zig_net_smoke_rollback_reports_dropped_input_recovery() -> None:
    payload = _run_zig_net_json(
        [
            "smoke-rollback",
            "--impair",
            "drop-first-guest-input",
            "--format",
            "json",
        ],
    )

    assert payload["status"] == "ok"
    assert payload["impairment"] == "drop-first-guest-input"
    assert payload["host_input_flags"] == 4
    assert payload["guest_input_flags"] == 5
    assert payload["host_tick_index"] == payload["guest_tick_index"] == 2
    assert payload["delayed_packets"] == 0
    assert payload["released_packets"] == 0
    assert payload["dropped_packets"] == 1
    assert payload["host_rollback_count"] >= 1
    assert payload["guest_rollback_count"] >= 1
    assert payload["host_prediction_mismatches"] >= 1
    assert payload["guest_prediction_mismatches"] >= 1
    assert payload["host_resync_count"] == 0
    assert payload["guest_resync_count"] == 0


def test_zig_net_smoke_rollback_reports_guest_resync_recovery() -> None:
    payload = _run_zig_net_json(
        [
            "smoke-rollback",
            "--impair",
            "force-guest-resync",
            "--format",
            "json",
        ],
    )

    assert payload["status"] == "ok"
    assert payload["impairment"] == "force-guest-resync"
    assert payload["delayed_packets"] == 1
    assert payload["released_packets"] == 1
    assert payload["dropped_packets"] >= 1
    assert payload["host_resync_count"] == 0
    assert payload["guest_resync_count"] == 1
    assert payload["resync_snapshot_tick"] == 4
    assert payload["host_paused_for_resync"] is False
    assert payload["guest_paused_for_resync"] is False
    assert payload["guest_prediction_mismatches"] >= 1


def test_zig_net_smoke_rollback_reports_guest_reconnect_recovery() -> None:
    payload = _run_zig_net_json(
        [
            "smoke-rollback",
            "--impair",
            "guest-reconnect",
            "--format",
            "json",
        ],
    )

    assert payload["status"] == "ok"
    assert payload["impairment"] == "guest-reconnect"
    assert payload["host_input_flags"] == 13
    assert payload["guest_input_flags"] == 11
    assert payload["host_tick_index"] == payload["guest_tick_index"]
    assert payload["host_live_ticks_advanced"] >= 1
    assert payload["guest_live_ticks_advanced"] >= 1
    assert payload["host_reconnect_count"] == 1
    assert payload["guest_reconnect_count"] == 1
    assert payload["host_paused_for_reconnect"] is False
    assert payload["guest_paused_for_reconnect"] is False
    assert payload["host_resync_count"] == 0
    assert payload["guest_resync_count"] == 0


def test_zig_net_smoke_rollback_reports_reconnect_then_resync_recovery() -> None:
    payload = _run_zig_net_json(
        [
            "smoke-rollback",
            "--impair",
            "guest-reconnect-resync",
            "--format",
            "json",
        ],
    )

    assert payload["status"] == "ok"
    assert payload["impairment"] == "guest-reconnect-resync"
    assert payload["host_tick_index"] >= 8
    assert payload["guest_tick_index"] >= 8
    assert payload["delayed_packets"] == 1
    assert payload["released_packets"] == 1
    assert payload["dropped_packets"] >= 1
    assert payload["host_reconnect_count"] == 1
    assert payload["guest_reconnect_count"] == 1
    assert payload["host_resync_count"] == 0
    assert payload["guest_resync_count"] == 1
    assert payload["resync_snapshot_tick"] >= 8
    assert payload["host_paused_for_reconnect"] is False
    assert payload["guest_paused_for_reconnect"] is False
    assert payload["host_paused_for_resync"] is False
    assert payload["guest_paused_for_resync"] is False


def test_zig_net_smoke_rollback_reports_double_reconnect_then_resync_recovery() -> None:
    payload = _run_zig_net_json(
        [
            "smoke-rollback",
            "--impair",
            "guest-double-reconnect-resync",
            "--format",
            "json",
        ],
    )

    assert payload["status"] == "ok"
    assert payload["impairment"] == "guest-double-reconnect-resync"
    assert payload["host_input_flags"] == 165
    assert payload["guest_input_flags"] == 125
    assert payload["host_tick_index"] == payload["guest_tick_index"]
    assert payload["delayed_packets"] == 1
    assert payload["released_packets"] == 1
    assert payload["dropped_packets"] >= 1
    assert payload["host_reconnect_count"] == 2
    assert payload["guest_reconnect_count"] == 2
    assert payload["host_resync_count"] == 0
    assert payload["guest_resync_count"] == 1
    assert payload["resync_snapshot_tick"] >= 4
    assert payload["host_paused_for_reconnect"] is False
    assert payload["guest_paused_for_reconnect"] is False
    assert payload["host_paused_for_resync"] is False
    assert payload["guest_paused_for_resync"] is False


def test_zig_net_smoke_rollback_reports_jitter_burst_recovery() -> None:
    payload = _run_zig_net_json(
        [
            "smoke-rollback",
            "--impair",
            "jitter-burst",
            "--format",
            "json",
        ],
    )

    assert payload["status"] == "ok"
    assert payload["impairment"] == "jitter-burst"
    assert payload["host_input_flags"] == 34
    assert payload["guest_input_flags"] == 74
    assert payload["host_tick_index"] == payload["guest_tick_index"] == 4
    assert payload["delayed_packets"] == 4
    assert payload["released_packets"] == 4
    assert payload["dropped_packets"] == 0
    assert payload["host_rollback_count"] >= 4
    assert payload["guest_rollback_count"] >= 3
    assert payload["host_prediction_mismatches"] >= 4
    assert payload["guest_prediction_mismatches"] >= 3
    assert payload["host_resync_count"] == 0
    assert payload["guest_resync_count"] == 0


def test_zig_net_smoke_rollback_reports_bidirectional_jitter_recovery() -> None:
    payload = _run_zig_net_json(
        [
            "smoke-rollback",
            "--impair",
            "bidirectional-jitter-burst",
            "--format",
            "json",
        ],
    )

    assert payload["status"] == "ok"
    assert payload["impairment"] == "bidirectional-jitter-burst"
    assert payload["host_input_flags"] == 43
    assert payload["guest_input_flags"] == 83
    assert payload["host_tick_index"] == payload["guest_tick_index"] == 3
    assert payload["delayed_packets"] == 6
    assert payload["released_packets"] == 6
    assert payload["dropped_packets"] == 0
    assert payload["host_rollback_count"] >= 3
    assert payload["guest_rollback_count"] >= 3
    assert payload["host_prediction_mismatches"] >= 3
    assert payload["guest_prediction_mismatches"] >= 3
    assert payload["host_resync_count"] == 0
    assert payload["guest_resync_count"] == 0


def test_zig_net_smoke_rollback_reports_triple_reconnect_jitter_recovery() -> None:
    payload = _run_zig_net_json(
        [
            "smoke-rollback",
            "--impair",
            "guest-triple-reconnect-bidirectional-jitter-burst",
            "--format",
            "json",
        ],
    )

    assert payload["status"] == "ok"
    assert payload["impairment"] == "guest-triple-reconnect-bidirectional-jitter-burst"
    assert payload["host_input_flags"] == 43
    assert payload["guest_input_flags"] == 83
    assert payload["host_tick_index"] == payload["guest_tick_index"]
    assert payload["delayed_packets"] == 6
    assert payload["released_packets"] == 6
    assert payload["dropped_packets"] == 0
    assert payload["host_reconnect_count"] == 3
    assert payload["guest_reconnect_count"] == 3
    assert payload["host_paused_for_reconnect"] is False
    assert payload["guest_paused_for_reconnect"] is False
    assert payload["host_resync_count"] == 0
    assert payload["guest_resync_count"] == 0


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
