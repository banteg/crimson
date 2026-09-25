from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
from typer.testing import CliRunner

import crimson.dbg.record as dbg_record
from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.replay import Replay
from crimson.sim.input_providers import PerkMenuOpenCommand, PerkPickCommand
from crimson.sim.run_spec import RunSpec

from ._helpers import (
    build_replay,
    build_typo_submit_replay,
    record_bot_replay,
    with_tick_commands,
    write_current_bad_event_player_index_replay,
    write_current_bad_tick_player_count_replay,
    write_current_typo_event_replay,
    write_current_unknown_command_replay,
    write_replay,
)


@pytest.fixture(scope="module")
def perk_replay() -> Replay:
    return record_bot_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0xBEEF), pick_perk=True)


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


def test_zig_replay_info_accepts_relative_base_dir(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    write_replay(tmp_path / "replays", replay=replay, name="relative.crd")
    relative_base = os.path.relpath(tmp_path, dbg_record._REPO_ROOT)

    zig_payload = _run_zig_replay_info(
        ["relative.crd", "--base-dir", relative_base, "--format", "json"],
    )

    assert zig_payload["status"] == "ok"
    assert zig_payload["replay"] == f"{relative_base}/replays/relative.crd"
    summary = cast("dict[str, Any]", zig_payload["summary"])
    assert summary["ticks_simulated"] == 2


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
        ("quest-dynamic.crd", build_replay(mode=GameMode.QUESTS, ticks=2, quest_level="2.5", player_count=3)),
        ("typo.crd", build_typo_submit_replay(word="go")),
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


def test_zig_replay_info_matches_python_output_for_played_run(tmp_path: Path, perk_replay: Replay) -> None:
    replay_path = write_replay(tmp_path, replay=perk_replay, name="perk.crd")

    python_result = _run_python_replay_info_process([str(replay_path)])
    zig_result = _run_zig_replay_info_process([str(replay_path)])
    assert zig_result.returncode == 0, dbg_record._command_detail(zig_result)
    assert zig_result.stdout == python_result.output
    assert _run_zig_replay_info([str(replay_path), "--format", "json"]) == _run_python_replay_info(
        [str(replay_path), "--format", "json"],
    )

    # Verbose creature-death events time kills differently (hit vs. kill
    # count), so compare the remaining verbose timeline.
    verbose_args = [str(replay_path), "--verbose", "--format", "json"]
    zig_timeline = _timeline_without_creature_deaths(_run_zig_replay_info(verbose_args))
    python_timeline = _timeline_without_creature_deaths(_run_python_replay_info(verbose_args))
    assert zig_timeline == python_timeline
    kinds = [event["kind"] for event in zig_timeline]
    assert kinds.count("perk_menu_open") == 1
    assert kinds.count("perk_pick") == 1


def _timeline_without_creature_deaths(payload: dict[str, object]) -> list[dict[str, Any]]:
    timeline = cast("list[dict[str, Any]]", payload["timeline"])
    return [event for event in timeline if event["kind"] != "creature_deaths"]


def test_zig_replay_info_matches_python_verbose_player_filter_payload(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2, player_count=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival-2p.crd")
    args = [str(replay_path), "--verbose", "--player-index", "1"]

    python_result = _run_python_replay_info_process(args)
    zig_result = _run_zig_replay_info_process(args)

    assert zig_result.returncode == 0, dbg_record._command_detail(zig_result)
    assert zig_result.stdout == python_result.output
    assert _run_zig_replay_info([*args, "--format", "json"]) == _run_python_replay_info([*args, "--format", "json"])


def test_zig_replay_info_matches_python_invalid_player_filter_errors(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1, player_count=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival-2p.crd")

    for player_index in ("-1", "2"):
        args = [str(replay_path), "--player-index", player_index]
        python_result = _run_python_replay_info_process(args)
        zig_result = _run_zig_replay_info_process(args)

        assert python_result.exit_code == 1
        assert zig_result.returncode == 1
        assert zig_result.stdout == ""
        assert zig_result.stderr == python_result.output


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


def test_zig_replay_info_rejects_illegal_perk_commands_like_python(tmp_path: Path) -> None:
    cases = [
        with_tick_commands(build_replay(mode=GameMode.SURVIVAL, ticks=1), 0, [PerkPickCommand(player_index=0, choice_index=0)]),
        with_tick_commands(build_replay(mode=GameMode.RUSH, ticks=2), 1, [PerkMenuOpenCommand(player_index=0)]),
    ]
    for index, replay in enumerate(cases):
        replay_path = write_replay(tmp_path, replay=replay, name=f"illegal-{index}.crd")
        args = [str(replay_path), "--format", "json"]

        python_result = _run_python_replay_info_process(args)
        zig_result = _run_zig_replay_info_process(args)

        assert python_result.exit_code == 1
        assert zig_result.returncode == 1
        assert zig_result.stdout == ""
        assert zig_result.stderr == python_result.output
        assert "without a pending perk" in zig_result.stderr


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


@pytest.mark.parametrize(
    ("writer", "detail"),
    [
        (write_current_bad_tick_player_count_replay, "ticks[0] has 0 player inputs, expected 1"),
        (write_current_bad_event_player_index_replay, "ticks[0].commands[0].player_index 1 is outside 0..0"),
        (write_current_typo_event_replay, "ticks[0].commands[0] Typ-o commands require game_mode_id=TYPO"),
    ],
)
def test_zig_replay_info_reports_invalid_replay_detail_like_python(tmp_path: Path, writer, detail: str) -> None:
    replay_path = writer(tmp_path, replay=build_replay(mode=GameMode.SURVIVAL, ticks=1), name="invalid.crd")
    args = [str(replay_path), "--format", "json"]

    python_result = _run_python_replay_info_process(args)
    zig_result = _run_zig_replay_info_process(args)

    assert zig_result.returncode == 1
    assert zig_result.stdout == ""
    assert zig_result.stderr == f"replay info failed: {detail}\n"
    assert zig_result.stderr == python_result.output


def test_zig_replay_info_reports_unknown_command_as_replay_failure(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_current_unknown_command_replay(tmp_path, replay=replay, name="unknown-command.crd")

    result = _run_zig_replay_info_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "replay info failed: ticks[0].commands[0] has unknown type 'network_ping'\n"


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
