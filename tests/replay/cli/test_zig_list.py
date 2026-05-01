from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import msgspec

import crimson.dbg.record as dbg_record
from crimson.game_modes import GameMode
from crimson.replay import ReplayClaimedStatsSnapshot
from crimson.weapons import WeaponId

from ._helpers import build_replay, write_replay


def test_zig_replay_list_shows_replays_under_base_dir(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    write_replay(tmp_path / "replays", replay=replay, name="zeta.crd")
    write_replay(tmp_path / "replays", replay=replay, name="alpha.crd")
    write_replay(tmp_path / "replays" / "nested", replay=replay, name="nested.crd")
    (tmp_path / "replays" / "ignore.txt").write_text("x", encoding="utf-8")

    result = _run_zig_replay_list(["--base-dir", str(tmp_path)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "replay mode version ticks duration score kills modified" in result.stdout
    assert "modified_ns" not in result.stdout
    assert "alpha.crd" in result.stdout
    assert "nested/nested.crd" in result.stdout
    assert "zeta.crd" in result.stdout
    assert "survival" in result.stdout
    assert replay.header.game_version in result.stdout
    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", result.stdout) is not None
    assert "count=3 parsed=3 errors=0" in result.stdout
    assert f"replays_dir={tmp_path / 'replays'}" in result.stdout


def test_zig_replay_list_keeps_listing_when_replay_is_invalid(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    write_replay(tmp_path / "replays", replay=replay, name="ok.crd")
    broken = tmp_path / "replays" / "broken.crd"
    broken.parent.mkdir(parents=True, exist_ok=True)
    broken.write_bytes(b"not-a-replay")

    result = _run_zig_replay_list(["--base-dir", str(tmp_path)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "ok.crd" in result.stdout
    assert "broken.crd invalid - - - - -" in result.stdout
    assert "warning: broken.crd:" in result.stdout
    assert "count=2 parsed=1 errors=1" in result.stdout


def test_zig_replay_list_sorts_in_reverse_chronological_order(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    old_path = write_replay(tmp_path / "replays", replay=replay, name="old.crd")
    mid_path = write_replay(tmp_path / "replays", replay=replay, name="mid.crd")
    new_path = write_replay(tmp_path / "replays", replay=replay, name="new.crd")
    os.utime(old_path, (1_000, 1_000))
    os.utime(mid_path, (2_000, 2_000))
    os.utime(new_path, (3_000, 3_000))

    result = _run_zig_replay_list(["--base-dir", str(tmp_path)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert result.stdout.find("new.crd") < result.stdout.find("mid.crd") < result.stdout.find("old.crd")


def test_zig_replay_list_mode_collapses_quest_level_and_players(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.QUESTS, ticks=1, player_count=2, quest_level="3.10")
    write_replay(tmp_path / "replays", replay=replay, name="quest.crd")

    result = _run_zig_replay_list(["--base-dir", str(tmp_path)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "quest 3.10 2p" in result.stdout


def test_zig_replay_list_uses_header_claimed_stats(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay = msgspec.structs.replace(
        replay,
        header=msgspec.structs.replace(
            replay.header,
            claimed_stats=ReplayClaimedStatsSnapshot(
                complete=True,
                ticks=2,
                elapsed_ms=33,
                score_xp=1234,
                kills=56,
                most_used_weapon_id=WeaponId.PISTOL,
                shots_fired=10,
                shots_hit=8,
            ),
        ),
    )
    write_replay(tmp_path / "replays", replay=replay, name="claimed.crd")

    result = _run_zig_replay_list(["--base-dir", str(tmp_path)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert re.search(r"claimed\.crd survival \S+ 2 0\.0s 1234 56 ", result.stdout) is not None


def test_zig_replay_list_reports_when_no_replays_found(tmp_path: Path) -> None:
    result = _run_zig_replay_list(["--base-dir", str(tmp_path)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert f"no replay files found under {tmp_path / 'replays'}" in result.stdout


def _run_zig_replay_list(args: list[str]) -> subprocess.CompletedProcess[str]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    return dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "replay", "list", *args],
        cwd=dbg_record._REPO_ROOT,
    )
