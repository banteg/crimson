from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast

import msgspec
import zstandard as zstd
from typer.testing import CliRunner

import crimson.dbg.record as dbg_record
from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.replay import ReplayClaimedStatsSnapshot, dump_replay
from crimson.sim.input_providers import PerkPickCommand
from crimson.weapons import WeaponId

from ._helpers import build_replay, build_typo_submit_replay, inject_tick_commands, write_replay


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


def test_zig_replay_verify_matches_python_full_payload_on_quest_replay(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.QUESTS, ticks=3, quest_level="1.1")
    replay_path = write_replay(tmp_path, replay=replay, name="quest.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json"],
    )

    assert zig_payload == python_payload


def test_zig_replay_verify_matches_python_rush_spawn_boundary(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.RUSH, ticks=16)
    replay_path = write_replay(tmp_path, replay=replay, name="rush.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json"],
    )

    assert zig_payload == python_payload


def test_zig_replay_verify_counts_typo_submit_stats_like_python(tmp_path: Path) -> None:
    replay = build_typo_submit_replay(word="reload")
    replay_path = write_replay(tmp_path, replay=replay, name="typo-submit.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json"],
    )

    python_run_result = cast("dict[str, object]", python_payload["run_result"])
    assert python_run_result["shots_fired"] == 1
    assert python_run_result["shots_hit"] == 0
    assert zig_payload == python_payload


def test_zig_replay_verify_matches_python_partial_typo_rng_state(tmp_path: Path) -> None:
    replay = build_typo_submit_replay(word="reload")
    replay_path = write_replay(tmp_path, replay=replay, name="typo-submit.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json", "--max-ticks", "1"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json", "--max-ticks", "1"],
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


def test_zig_replay_verify_stale_perk_pick_is_noop(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    inject_tick_commands(replay, 0, [PerkPickCommand(player_index=0, choice_index=0)])
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_payload = _run_python_replay_verify([str(replay_path), "--format", "json"])
    zig_payload = _run_zig_replay_verify([str(replay_path), "--format", "json"])

    assert zig_payload == python_payload


def test_zig_replay_verify_rejects_non_crd_extension(tmp_path: Path) -> None:
    replay_path = tmp_path / "survival.txt"
    replay_path.write_bytes(b"not checked before extension validation")

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay verification failed: replay file must use .crd extension" in result.stderr


def test_zig_replay_verify_reports_old_format_as_replay_failure(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay = msgspec.structs.replace(
        replay,
        header=msgspec.structs.replace(replay.header, replay_format_version=10),
    )
    replay_path = tmp_path / "old-format.crd"
    replay_path.write_bytes(msgspec.msgpack.encode(replay))

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay verification failed: replay format version is not supported" in result.stderr
    assert "native runtime limitation" not in result.stderr


def test_zig_replay_verify_reports_unknown_command_as_replay_failure(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    raw_payload = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = msgspec.msgpack.decode(raw_payload)
    payload["ticks"][0]["commands"] = [{"type": "network_ping", "player_index": 0}]
    replay_path = tmp_path / "unknown-command.crd"
    replay_path.write_bytes(msgspec.msgpack.encode(payload))

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay verification failed: replay events include an unknown command kind" in result.stderr
    assert "native runtime limitation" not in result.stderr


def test_zig_replay_verify_reports_old_ruleset_as_replay_failure(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay = msgspec.structs.replace(
        replay,
        header=msgspec.structs.replace(replay.header, game_version="0.6.9"),
    )
    replay_path = write_replay(tmp_path, replay=replay, name="old-ruleset.crd")

    result = _run_zig_replay_verify_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay verification failed: native replay tools require latest ruleset replays" in result.stderr
    assert "native runtime limitation" not in result.stderr


def test_zig_replay_verify_rejects_removed_score_options_as_invalid(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = _run_zig_replay_verify_process([str(replay_path), "--submitted-score", "0"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "invalid replay verify args: --submitted-score" in result.stderr


def test_zig_replay_verify_rejects_removed_lenient_events_option_as_invalid(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = _run_zig_replay_verify_process([str(replay_path), "--lenient-events"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "invalid replay verify args: --lenient-events" in result.stderr


def test_zig_replay_verify_rejects_removed_strict_events_option_as_invalid(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = _run_zig_replay_verify_process([str(replay_path), "--strict-events"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "invalid replay verify args: --strict-events" in result.stderr


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
