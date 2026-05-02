from __future__ import annotations

import json
from pathlib import Path

import crimson.dbg.record as dbg_record
from crimson.persistence import save_status


def test_zig_status_human_output_reports_summary(tmp_path: Path) -> None:
    weapon_counts = [0] * int(save_status.WEAPON_USAGE_COUNT)
    weapon_counts[3] = 4
    weapon_counts[10] = 5
    quest_counts = [0] * int(save_status.QUEST_PLAY_COUNT)
    quest_counts[7] = 2
    quest_counts[14] = 6
    data = save_status.GameStatusData(
        quest_unlock_index=12,
        quest_unlock_index_full=34,
        weapon_usage_counts=tuple(weapon_counts),
        quest_play_counts=tuple(quest_counts),
        mode_play_survival=1,
        mode_play_rush=2,
        mode_play_typo=3,
        mode_play_other=4,
        game_sequence_id=123456,
        unknown_tail=b"zig-status-test!",
    )
    path = tmp_path / save_status.GAME_CFG_NAME
    save_status.save_status(path, data)

    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    result = dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "status", "--path", str(path)],
        cwd=dbg_record._REPO_ROOT,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert f"path: {path}" in result.stdout
    assert "checksum: ok" in result.stdout
    assert "quest_unlock_index: 12" in result.stdout
    assert "quest_unlock_index_full: 34" in result.stdout
    assert "mode_plays: survival=1 rush=2 typo=3 other=4" in result.stdout
    assert "total_weapon_usage: 9" in result.stdout
    assert "total_quest_plays: 8" in result.stdout
    assert "game_sequence_id: 123456" in result.stdout
    assert "fields:" in result.stdout
    assert "unknown_tail: 0x7a69672d7374617475732d7465737421 (len=16)" in result.stdout


def test_zig_status_json_output_reports_summary_and_fields(tmp_path: Path) -> None:
    weapon_counts = [0] * int(save_status.WEAPON_USAGE_COUNT)
    weapon_counts[5] = 99
    quest_counts = [0] * int(save_status.QUEST_PLAY_COUNT)
    quest_counts[7] = 1234
    data = save_status.GameStatusData(
        quest_unlock_index=12,
        quest_unlock_index_full=34,
        weapon_usage_counts=tuple(weapon_counts),
        quest_play_counts=tuple(quest_counts),
        mode_play_survival=1,
        mode_play_rush=2,
        mode_play_typo=3,
        mode_play_other=4,
        game_sequence_id=0x12345678,
        unknown_tail=b"crimsonland-test".ljust(save_status.UNKNOWN_TAIL_SIZE, b"\x00"),
    )
    path = tmp_path / save_status.GAME_CFG_NAME
    save_status.save_status(path, data)
    json_out = tmp_path / "reports" / "status.json"

    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    result = dbg_record._run_process(
        [
            str(dbg_record._ZIG_BIN),
            "status",
            "--base-dir",
            str(tmp_path),
            "--format",
            "json",
            "--json-out",
            str(json_out),
        ],
        cwd=dbg_record._REPO_ROOT,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    payload = json.loads(result.stdout)
    assert payload == json.loads(json_out.read_text())
    assert payload["schema_version"] == 1
    assert payload["status"] == "ok"
    assert payload["path"] == str(path)
    assert payload["checksum"]["valid"] is True
    assert payload["summary"] == {
        "quest_unlock_index": 12,
        "quest_unlock_index_full": 34,
        "total_weapon_usage": 99,
        "total_quest_plays": 1234,
        "mode_play_survival": 1,
        "mode_play_rush": 2,
        "mode_play_typo": 3,
        "mode_play_other": 4,
        "game_sequence_id": 0x12345678,
    }
    assert payload["fields"]["weapon_usage_counts"][5] == 99
    assert payload["fields"]["quest_play_counts"][7] == 1234
    assert payload["fields"]["unknown_tail"].startswith("crimsonland-test")


def test_zig_status_rejects_checksum_mismatch(tmp_path: Path) -> None:
    path = tmp_path / save_status.GAME_CFG_NAME
    save_status.save_status(path, save_status.default_status_data())
    raw = bytearray(path.read_bytes())
    raw[0] ^= 0xFF
    path.write_bytes(raw)

    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    result = dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "status", "--path", str(path), "--format", "json"],
        cwd=dbg_record._REPO_ROOT,
    )

    assert result.returncode == 1
    assert "status failed: game.cfg checksum mismatch" in result.stderr
