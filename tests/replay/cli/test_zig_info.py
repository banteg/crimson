from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, cast

from typer.testing import CliRunner

import crimson.dbg.record as dbg_record
from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.sim.input_providers import PerkMenuOpenCommand, PerkPickCommand

from ._helpers import (
    build_replay,
    build_typo_submit_replay,
    inject_tick_commands,
    write_current_bad_tick_player_count_replay,
    write_current_missing_perk_choice_replay,
    write_current_string_quest_level_replay,
    write_current_typo_event_replay,
    write_current_unknown_command_replay,
    write_legacy_out_of_order_event_replay,
    write_replay,
)


def test_zig_replay_info_matches_python_json_payload_on_simple_replay(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    python_payload = _run_python_replay_info(
        [str(replay_path), "--format", "json"],
    )
    zig_payload = _run_zig_replay_info(
        [str(replay_path), "--format", "json"],
    )

    assert zig_payload == python_payload


def test_zig_replay_info_matches_python_human_output_on_simple_replay(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_result = _run_python_replay_info_process([str(replay_path)])
    zig_result = _run_zig_replay_info_process([str(replay_path)])

    assert zig_result.returncode == 0, dbg_record._command_detail(zig_result)
    assert zig_result.stdout == python_result.output


def test_zig_replay_info_matches_python_json_payload_on_quest_replay(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.QUESTS, ticks=3, quest_level="1.1")
    replay_path = write_replay(tmp_path, replay=replay, name="quest.crd")
    python_payload = _run_python_replay_info(
        [str(replay_path), "--format", "json"],
    )
    zig_payload = _run_zig_replay_info(
        [str(replay_path), "--format", "json"],
    )

    assert zig_payload == python_payload


def test_zig_replay_info_accepts_current_string_quest_level(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.QUESTS, ticks=2, quest_level="1.1")
    replay_path = write_current_string_quest_level_replay(
        tmp_path,
        replay=replay,
        name="quest-string-level.crd",
        quest_level="1.1",
    )

    zig_payload = _run_zig_replay_info([str(replay_path), "--format", "json"])

    summary = cast("dict[str, Any]", zig_payload["summary"])
    assert summary["game_mode_id"] == int(GameMode.QUESTS)
    assert summary["ticks_simulated"] == 2


def test_zig_replay_info_respects_python_max_ticks_contract(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_payload = _run_python_replay_info(
        [str(replay_path), "--format", "json", "--max-ticks", "2"],
    )
    zig_payload = _run_zig_replay_info(
        [str(replay_path), "--format", "json", "--max-ticks", "2"],
    )

    assert zig_payload == python_payload
    summary = cast("dict[str, Any]", zig_payload["summary"])
    assert summary["ticks_simulated"] == 2


def test_zig_replay_info_matches_python_supported_mode_breadth(tmp_path: Path) -> None:
    cases = [
        ("survival.crd", build_replay(mode=GameMode.SURVIVAL, ticks=2)),
        ("rush.crd", build_replay(mode=GameMode.RUSH, ticks=2)),
        ("quest.crd", build_replay(mode=GameMode.QUESTS, ticks=2, seed=101, quest_level="1.1")),
        ("tutorial.crd", build_replay(mode=GameMode.TUTORIAL, ticks=2)),
    ]

    for filename, replay in cases:
        replay_path = write_replay(tmp_path, replay=replay, name=filename)
        python_payload = _run_python_replay_info(
            [str(replay_path), "--format", "json"],
        )
        zig_payload = _run_zig_replay_info(
            [str(replay_path), "--format", "json"],
        )

        assert zig_payload == python_payload


def test_zig_replay_info_matches_python_verbose_human_player_filter_output(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1, player_count=2)
    inject_tick_commands(
        replay,
        0,
        [
            PerkMenuOpenCommand(player_index=0),
            PerkMenuOpenCommand(player_index=1),
        ],
    )
    replay_path = write_replay(tmp_path, replay=replay, name="survival-2p.crd")
    args = [
        str(replay_path),
        "--verbose",
        "--player-index",
        "1",
    ]

    python_result = _run_python_replay_info_process(args)
    zig_result = _run_zig_replay_info_process(args)

    assert zig_result.returncode == 0, dbg_record._command_detail(zig_result)
    assert zig_result.stdout == python_result.output


def test_zig_replay_info_matches_python_verbose_player_filter_payload(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1, player_count=2)
    inject_tick_commands(
        replay,
        0,
        [
            PerkMenuOpenCommand(player_index=0),
            PerkMenuOpenCommand(player_index=1),
        ],
    )
    replay_path = write_replay(tmp_path, replay=replay, name="survival-2p.crd")

    python_payload = _run_python_replay_info(
        [
            str(replay_path),
            "--format",
            "json",
            "--verbose",
            "--player-index",
            "1",
        ],
    )
    zig_payload = _run_zig_replay_info(
        [
            str(replay_path),
            "--format",
            "json",
            "--verbose",
            "--player-index",
            "1",
        ],
    )

    assert zig_payload == python_payload


def test_zig_replay_info_matches_python_verbose_rush_command_payload(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.RUSH, ticks=1)
    inject_tick_commands(replay, 0, [PerkMenuOpenCommand(player_index=0)])
    replay_path = write_replay(tmp_path, replay=replay, name="rush.crd")

    python_payload = _run_python_replay_info(
        [
            str(replay_path),
            "--format",
            "json",
            "--verbose",
        ],
    )
    zig_payload = _run_zig_replay_info(
        [
            str(replay_path),
            "--format",
            "json",
            "--verbose",
        ],
    )

    assert zig_payload == python_payload


def test_zig_replay_info_matches_python_verbose_typo_command_payload(tmp_path: Path) -> None:
    replay = build_typo_submit_replay(word="go")
    replay_path = write_replay(tmp_path, replay=replay, name="typo.crd")

    python_payload = _run_python_replay_info(
        [
            str(replay_path),
            "--format",
            "json",
            "--verbose",
        ],
    )
    zig_payload = _run_zig_replay_info(
        [
            str(replay_path),
            "--format",
            "json",
            "--verbose",
        ],
    )

    assert zig_payload == python_payload
    summary = cast("dict[str, Any]", zig_payload["summary"])
    counts = cast("dict[str, int]", summary["event_counts_by_kind"])
    assert counts["typo_char"] == 2
    assert counts["typo_submit"] == 1
    timeline = cast("list[dict[str, Any]]", zig_payload["timeline"])
    command_events = [event for event in timeline if event["kind"] in {"typo_char", "typo_submit"}]
    assert [event["detail"] for event in command_events] == [
        "p0 typed 'g'",
        "p0 typed 'o'",
        "p0 typo submit",
    ]


def test_zig_replay_info_stale_perk_pick_is_noop(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    inject_tick_commands(replay, 0, [PerkPickCommand(player_index=0, choice_index=0)])
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_payload = _run_python_replay_info([str(replay_path), "--format", "json"])
    zig_payload = _run_zig_replay_info([str(replay_path), "--format", "json"])

    assert zig_payload == python_payload


def test_zig_replay_info_writes_json_out_like_python(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    json_out = tmp_path / "reports" / "info.json"

    result = _run_zig_replay_info_process(
        [str(replay_path), "--format", "json", "--json-out", str(json_out)],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    stdout_payload = json.loads(result.stdout)
    file_payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert file_payload == stdout_payload


def test_zig_replay_info_reports_tick_player_count_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_bad_tick_player_count_replay(
        tmp_path,
        replay=replay,
        name="bad-tick-player-count.crd",
    )

    result = _run_zig_replay_info_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay info failed: replay tick 0 has 0 players, expected 1" in result.stderr
    assert "canonical wire shape" not in result.stderr


def test_zig_replay_info_reports_event_shape_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_missing_perk_choice_replay(
        tmp_path,
        replay=replay,
        name="missing-perk-choice.crd",
    )

    result = _run_zig_replay_info_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay info failed: replay event perk_pick missing choice_index: tick=0 event_index=0" in result.stderr
    assert "canonical wire shape" not in result.stderr


def test_zig_replay_info_reports_event_ordering_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_legacy_out_of_order_event_replay(tmp_path, replay=replay, name="event-order.crd")

    result = _run_zig_replay_info_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay info failed: replay events are not ordered in canonical tick order: "
        "tick=1 follows tick=2 (event_index=1, event=perk_menu_open)"
    ) in result.stderr
    assert "replay info collector" not in result.stderr


def test_zig_replay_info_reports_event_kind_detail(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_typo_event_replay(tmp_path, replay=replay, name="event-kind.crd")

    result = _run_zig_replay_info_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        "replay info failed: replay event kind invalid for game mode: "
        "event=typo_char tick=0 event_index=0 game_mode=survival"
    ) in result.stderr
    assert "replay info collector" not in result.stderr


def test_zig_replay_info_reports_unknown_command_as_replay_failure(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_unknown_command_replay(tmp_path, replay=replay, name="unknown-command.crd")

    result = _run_zig_replay_info_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay info failed: replay events include an unknown command kind" in result.stderr
    assert "replay info collector" not in result.stderr


def test_zig_replay_info_rejects_non_crd_extension(tmp_path: Path) -> None:
    replay_path = tmp_path / "survival.txt"
    replay_path.write_bytes(b"not checked before extension validation")

    result = _run_zig_replay_info_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay info failed: replay file must use .crd extension" in result.stderr


def _run_python_replay_info(args: list[str]) -> dict[str, object]:
    result = _run_python_replay_info_process(args)
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _run_python_replay_info_process(args: list[str]):
    runner = CliRunner()
    return runner.invoke(app, ["replay", "info", *args])


def _run_zig_replay_info(args: list[str]) -> dict[str, object]:
    info_run = _run_zig_replay_info_process(args)
    assert info_run.returncode == 0, dbg_record._command_detail(info_run)
    return json.loads(info_run.stdout)


def _run_zig_replay_info_process(args: list[str]) -> subprocess.CompletedProcess[str]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    return dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "replay", "info", *args],
        cwd=dbg_record._REPO_ROOT,
    )
