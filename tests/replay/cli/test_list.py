from __future__ import annotations

import os
import re
from pathlib import Path

import msgspec
from click import unstyle
from typer.testing import CliRunner

from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.replay import ReplayClaimedStatsSnapshot
from crimson.replay.checkpoints import dump_checkpoints_file, load_checkpoints_file
from crimson.weapons import WeaponId

from ._helpers import build_replay, write_checkpoint_sidecar, write_replay


def test_replay_list_shows_replays_under_base_dir(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    write_replay(tmp_path / "replays", replay=replay, name="zeta.crd")
    write_replay(tmp_path / "replays", replay=replay, name="alpha.crd")
    write_replay(tmp_path / "replays" / "nested", replay=replay, name="nested.crd")
    (tmp_path / "replays" / "ignore.txt").write_text("x", encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "list", "--base-dir", str(tmp_path), "--no-color"],
    )

    assert result.exit_code == 0, result.output
    assert "replay" in result.output
    assert "mode" in result.output
    assert "version" in result.output
    assert "score" in result.output
    assert "kills" in result.output
    assert "alpha.crd" in result.output
    assert "nested/nested.crd" in result.output
    assert "zeta.crd" in result.output
    assert "survival" in result.output
    assert replay.header.game_version in result.output
    assert "count=3 parsed=3 errors=0" in result.output
    assert f"replays_dir={tmp_path / 'replays'}" in result.output


def test_replay_list_keeps_listing_when_replay_is_invalid(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    write_replay(tmp_path / "replays", replay=replay, name="ok.crd")
    broken = tmp_path / "replays" / "broken.crd"
    broken.parent.mkdir(parents=True, exist_ok=True)
    broken.write_bytes(b"not-a-replay")
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "list", "--base-dir", str(tmp_path), "--no-color"],
    )

    assert result.exit_code == 0, result.output
    assert "ok.crd" in result.output
    assert "broken.crd" in result.output
    assert "invalid" in result.output
    assert "warning: broken.crd:" in result.output
    assert "count=2 parsed=1 errors=1" in result.output
    assert f"replays_dir={tmp_path / 'replays'}" in result.output


def test_replay_list_sorts_in_reverse_chronological_order(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    old_path = write_replay(tmp_path / "replays", replay=replay, name="old.crd")
    mid_path = write_replay(tmp_path / "replays", replay=replay, name="mid.crd")
    new_path = write_replay(tmp_path / "replays", replay=replay, name="new.crd")
    os.utime(old_path, (1_000, 1_000))
    os.utime(mid_path, (2_000, 2_000))
    os.utime(new_path, (3_000, 3_000))
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "list", "--base-dir", str(tmp_path), "--no-color"],
    )

    assert result.exit_code == 0, result.output
    output = unstyle(result.output)
    assert output.find("new.crd") < output.find("mid.crd") < output.find("old.crd")


def test_replay_list_mode_collapses_quest_level_and_players(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.QUESTS, ticks=1, player_count=2, quest_level="3.10")
    write_replay(tmp_path / "replays", replay=replay, name="quest.crd")
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "list", "--base-dir", str(tmp_path), "--no-color"],
    )

    assert result.exit_code == 0, result.output
    assert "quest 3.10 2p" in unstyle(result.output)


def test_replay_list_uses_header_claimed_stats_even_when_sidecar_exists(tmp_path: Path) -> None:
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
    replay_path = write_replay(tmp_path / "replays", replay=replay, name="stats.crd")
    sidecar_path = write_checkpoint_sidecar(replay_path, replay)
    payload = load_checkpoints_file(sidecar_path)
    assert payload.checkpoints
    payload = msgspec.structs.replace(
        payload,
        checkpoints=[msgspec.structs.replace(payload.checkpoints[0], tick_index=99, score_xp=42, kills=7)],
    )
    dump_checkpoints_file(sidecar_path, payload)
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "list", "--base-dir", str(tmp_path), "--no-color"],
    )

    assert result.exit_code == 0, result.output
    output = unstyle(result.output)
    assert re.search(r"stats\.crd\s+survival\s+\S+\s+2\s+0\.0s\s+1234\s+56\s+", output) is not None


def test_replay_list_uses_header_claimed_stats_without_sidecar(tmp_path: Path) -> None:
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
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "list", "--base-dir", str(tmp_path), "--no-color"],
    )

    assert result.exit_code == 0, result.output
    output = unstyle(result.output)
    assert re.search(r"claimed\.crd\s+survival\s+\S+\s+2\s+0\.0s\s+1234\s+56\s+", output) is not None


def test_replay_list_reports_when_no_replays_found(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "list", "--base-dir", str(tmp_path), "--no-color"],
    )

    assert result.exit_code == 0, result.output
    assert f"no replay files found under {tmp_path / 'replays'}" in result.output
