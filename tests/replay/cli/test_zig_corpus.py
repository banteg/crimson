from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

import pytest

import crimson.dbg.record as dbg_record
from crimson.game_modes import GameMode
from crimson.replay import Replay
from crimson.sim.input_providers import PerkMenuOpenCommand, PerkPickCommand

from ._helpers import (
    build_replay,
    build_typo_submit_replay,
    inject_tick_commands,
    write_checkpoint_sidecar,
    write_current_bad_event_player_index_replay,
    write_current_bad_tick_player_count_replay,
    write_current_missing_perk_choice_replay,
    write_current_missing_quest_level_replay,
    write_current_typo_event_replay,
    write_current_unknown_command_replay,
    write_replay,
)

_STALE_FAILURE_MARKERS = (
    "canonical wire shape",
    "native runtime limitation",
    "not ported",
)


@dataclass(frozen=True)
class MaterializedReplay:
    path: Path
    replay: Replay | None


@dataclass(frozen=True)
class ReplayCorpusCase:
    case_id: str
    game_mode: Literal["survival", "rush", "quests", "typo", "tutorial"]
    category: Literal["valid", "invalid"]
    coverage: frozenset[str]
    materialize: Callable[[Path], MaterializedReplay]


def test_zig_replay_corpus_manifest_names_completion_contract_breadth() -> None:
    valid_modes = {case.game_mode for case in _VALID_CORPUS}
    coverage = set().union(*(case.coverage for case in _VALID_CORPUS), *(case.coverage for case in _INVALID_CORPUS))

    assert valid_modes == {"survival", "rush", "quests", "typo", "tutorial"}
    assert {"verbose-events", "multi-player", "invalid-input"} <= coverage
    assert all(case.case_id for case in (*_VALID_CORPUS, *_INVALID_CORPUS))


def test_zig_replay_corpus_runs_core_native_commands(tmp_path: Path, zig_bin: Path) -> None:
    del zig_bin
    materialized = _materialize_cases(tmp_path / "valid", _VALID_CORPUS)

    for case, sample in materialized:
        verify_payload = _run_zig_json(["replay", "verify", str(sample.path), "--format", "json"])
        info_args = ["replay", "info", str(sample.path), "--format", "json"]
        if "verbose-events" in case.coverage:
            info_args.append("--verbose")
        info_payload = _run_zig_json(info_args)
        benchmark_payload = _run_zig_json(
            [
                "replay",
                "benchmark",
                str(sample.path),
                "--runs",
                "1",
                "--warmup-runs",
                "0",
                "--format",
                "json",
            ],
        )

        assert verify_payload["status"] == "ok", case.case_id
        assert info_payload["status"] == "ok", case.case_id
        assert benchmark_payload["status"] == "ok", case.case_id


def test_zig_replay_corpus_runs_checkpoint_commands(tmp_path: Path, zig_bin: Path) -> None:
    del zig_bin
    materialized = _materialize_cases(tmp_path / "valid", _VALID_CORPUS)

    for case, sample in materialized:
        assert sample.replay is not None
        sidecar = write_checkpoint_sidecar(sample.path, sample.replay)
        sidecar_copy = sample.path.with_name(f"{sample.path.stem}.copy.crd.chk")
        shutil.copyfile(sidecar, sidecar_copy)

        verify_payload = _run_zig_json(
            [
                "replay",
                "verify-checkpoints",
                str(sample.path),
                "--checkpoints",
                str(sidecar),
                "--format",
                "json",
            ],
        )
        diff_payload = _run_zig_json(
            [
                "replay",
                "diff-checkpoints",
                str(sidecar),
                str(sidecar_copy),
                "--format",
                "json",
            ],
        )

        assert verify_payload["status"] == "ok", case.case_id
        assert verify_payload["command"] == "verify-checkpoints", case.case_id
        assert diff_payload["status"] == "ok", case.case_id
        assert diff_payload["command"] == "diff-checkpoints", case.case_id


def test_zig_replay_corpus_list_covers_valid_and_invalid_inputs(tmp_path: Path, zig_bin: Path) -> None:
    del zig_bin
    replays_dir = tmp_path / "replays"
    valid_samples = _materialize_cases(replays_dir, _VALID_CORPUS)
    invalid_samples = _materialize_cases(replays_dir, _INVALID_CORPUS)

    payload = _run_zig_json(["replay", "list", "--base-dir", str(tmp_path), "--format", "json"])

    summary = cast("dict[str, int]", payload["summary"])
    rows = cast("list[dict[str, object]]", payload["rows"])
    assert summary == {
        "count": len(valid_samples) + len(invalid_samples),
        "parsed": len(valid_samples),
        "errors": len(invalid_samples),
    }
    assert {row["replay"] for row in rows} == {sample.path.name for _, sample in (*valid_samples, *invalid_samples)}
    for case, sample in valid_samples:
        row = next(row for row in rows if row["replay"] == sample.path.name)
        mode_prefix = "quest" if case.game_mode == "quests" else case.game_mode
        assert row["mode"].startswith(mode_prefix)
        assert row["parse_error"] is None
    for _, sample in invalid_samples:
        row = next(row for row in rows if row["replay"] == sample.path.name)
        assert row["mode"] == "invalid"
        assert row["parse_error"]
        _assert_no_stale_failure_marker(str(row["parse_error"]))


@pytest.mark.parametrize("command", ["verify", "info", "benchmark"])
def test_zig_replay_corpus_invalid_inputs_have_current_failure_wording(
    tmp_path: Path,
    zig_bin: Path,
    command: str,
) -> None:
    del zig_bin
    materialized = _materialize_cases(tmp_path / command, _INVALID_CORPUS)

    for case, sample in materialized:
        args = ["replay", command, str(sample.path)]
        if command in {"verify", "info"}:
            args += ["--format", "json"]
        else:
            args += ["--runs", "1", "--warmup-runs", "0"]
        result = _run_zig(args)

        assert result.returncode == 1, case.case_id
        assert result.stdout == "", case.case_id
        assert result.stderr, case.case_id
        _assert_no_stale_failure_marker(result.stderr)


@pytest.fixture(scope="module")
def zig_bin() -> Path:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)
    return dbg_record._ZIG_BIN


def _materialize_cases(
    root: Path,
    cases: tuple[ReplayCorpusCase, ...],
) -> list[tuple[ReplayCorpusCase, MaterializedReplay]]:
    root.mkdir(parents=True, exist_ok=True)
    return [(case, case.materialize(root)) for case in cases]


def _run_zig(args: list[str]) -> subprocess.CompletedProcess[str]:
    return dbg_record._run_process([str(dbg_record._ZIG_BIN), *args], cwd=dbg_record._REPO_ROOT)


def _run_zig_json(args: list[str]) -> dict[str, object]:
    result = _run_zig(args)
    assert result.returncode == 0, dbg_record._command_detail(result)
    return json.loads(result.stdout)


def _assert_no_stale_failure_marker(output: str) -> None:
    lowered = output.lower()
    for marker in _STALE_FAILURE_MARKERS:
        assert marker not in lowered


def _survival(root: Path) -> MaterializedReplay:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=4)
    return MaterializedReplay(write_replay(root, replay=replay, name="corpus-survival.crd"), replay)


def _rush(root: Path) -> MaterializedReplay:
    replay = build_replay(mode=GameMode.RUSH, ticks=16)
    inject_tick_commands(replay, 0, [PerkMenuOpenCommand(player_index=0)])
    inject_tick_commands(replay, 1, [PerkPickCommand(player_index=0, choice_index=0)])
    return MaterializedReplay(write_replay(root, replay=replay, name="corpus-rush-events.crd"), replay)


def _quest(root: Path) -> MaterializedReplay:
    replay = build_replay(mode=GameMode.QUESTS, ticks=16, seed=101, quest_level="1.1")
    return MaterializedReplay(write_replay(root, replay=replay, name="corpus-quest-1.1.crd"), replay)


def _typo(root: Path) -> MaterializedReplay:
    replay = build_typo_submit_replay(word="go")
    return MaterializedReplay(write_replay(root, replay=replay, name="corpus-typo-submit.crd"), replay)


def _tutorial(root: Path) -> MaterializedReplay:
    replay = build_replay(mode=GameMode.TUTORIAL, ticks=4)
    return MaterializedReplay(write_replay(root, replay=replay, name="corpus-tutorial.crd"), replay)


def _multiplayer_verbose(root: Path) -> MaterializedReplay:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2, player_count=2)
    inject_tick_commands(
        replay,
        0,
        [
            PerkMenuOpenCommand(player_index=0),
            PerkMenuOpenCommand(player_index=1),
        ],
    )
    return MaterializedReplay(write_replay(root, replay=replay, name="corpus-survival-2p-events.crd"), replay)


def _bad_tick_player_count(root: Path) -> MaterializedReplay:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    return MaterializedReplay(
        write_current_bad_tick_player_count_replay(root, replay=replay, name="invalid-bad-tick-player-count.crd"),
        None,
    )


def _unknown_command(root: Path) -> MaterializedReplay:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    return MaterializedReplay(
        write_current_unknown_command_replay(root, replay=replay, name="invalid-unknown-command.crd"),
        None,
    )


def _missing_perk_choice(root: Path) -> MaterializedReplay:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    return MaterializedReplay(
        write_current_missing_perk_choice_replay(root, replay=replay, name="invalid-missing-perk-choice.crd"),
        None,
    )


def _bad_event_player_index(root: Path) -> MaterializedReplay:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    return MaterializedReplay(
        write_current_bad_event_player_index_replay(root, replay=replay, name="invalid-event-player-index.crd"),
        None,
    )


def _bad_event_kind(root: Path) -> MaterializedReplay:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    return MaterializedReplay(
        write_current_typo_event_replay(root, replay=replay, name="invalid-event-kind.crd"),
        None,
    )


def _missing_quest_level(root: Path) -> MaterializedReplay:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    return MaterializedReplay(
        write_current_missing_quest_level_replay(root, replay=replay, name="invalid-missing-quest-level.crd"),
        None,
    )


_VALID_CORPUS: tuple[ReplayCorpusCase, ...] = (
    ReplayCorpusCase("survival", "survival", "valid", frozenset({"mode"}), _survival),
    ReplayCorpusCase("rush-with-events", "rush", "valid", frozenset({"mode", "verbose-events"}), _rush),
    ReplayCorpusCase("quest-1.1", "quests", "valid", frozenset({"mode"}), _quest),
    ReplayCorpusCase("typo-submit", "typo", "valid", frozenset({"mode", "verbose-events"}), _typo),
    ReplayCorpusCase("tutorial", "tutorial", "valid", frozenset({"mode"}), _tutorial),
    ReplayCorpusCase(
        "survival-2p-verbose-events",
        "survival",
        "valid",
        frozenset({"multi-player", "verbose-events"}),
        _multiplayer_verbose,
    ),
)

_INVALID_CORPUS: tuple[ReplayCorpusCase, ...] = (
    ReplayCorpusCase(
        "bad-tick-player-count",
        "survival",
        "invalid",
        frozenset({"invalid-input"}),
        _bad_tick_player_count,
    ),
    ReplayCorpusCase("unknown-command", "survival", "invalid", frozenset({"invalid-input"}), _unknown_command),
    ReplayCorpusCase(
        "missing-perk-choice",
        "survival",
        "invalid",
        frozenset({"invalid-input"}),
        _missing_perk_choice,
    ),
    ReplayCorpusCase(
        "bad-event-player-index",
        "survival",
        "invalid",
        frozenset({"invalid-input"}),
        _bad_event_player_index,
    ),
    ReplayCorpusCase("bad-event-kind", "survival", "invalid", frozenset({"invalid-input"}), _bad_event_kind),
    ReplayCorpusCase(
        "missing-quest-level",
        "quests",
        "invalid",
        frozenset({"invalid-input"}),
        _missing_quest_level,
    ),
)
