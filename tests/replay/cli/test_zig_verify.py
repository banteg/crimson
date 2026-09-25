from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
from pathlib import Path

import msgspec
import pytest
import zstandard as zstd
from typer.testing import CliRunner

import crimson.dbg.record as dbg_record
from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.replay import Replay, ReplayRecorder, encode_replay_payload
from crimson.replay.driver.playback_driver import build_verify_playback_driver
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    GameCommand,
    PerkMenuOpenCommand,
    PerkPickCommand,
    TypoCharCommand,
    TypoSubmitCommand,
)
from crimson.sim.run_result import RunOutcome, RunResult
from crimson.sim.run_spec import RunSpec, RunStatus
from grim.geom import Vec2
from tests.support.replay_runner_helpers import finish_replay

from ._helpers import (
    build_replay,
    build_typo_submit_replay,
    record_bot_replay,
    with_idle_ticks,
    with_tick_commands,
    write_current_bad_event_player_index_replay,
    write_current_bad_tick_player_count_replay,
    write_current_missing_perk_choice_replay,
    write_current_missing_quest_level_replay,
    write_current_mode_player_count_replay,
    write_current_typo_event_replay,
    write_current_unknown_command_replay,
    write_payload_bytes,
    write_replay,
)


@pytest.fixture(scope="module")
def zig_bin() -> Path:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)
    return dbg_record._ZIG_BIN


@pytest.fixture(scope="module")
def perk_replay() -> Replay:
    return record_bot_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0xBEEF), pick_perk=True)


@pytest.fixture(scope="module")
def quest_completed_replay() -> Replay:
    return record_bot_replay(RunSpec(game_mode_id=GameMode.QUESTS, seed=0xBEEF, quest_level=QuestLevel.parse("1.1")))


@pytest.fixture(scope="module")
def survival_death_replay() -> Replay:
    return record_bot_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0xBEEF), fire=False)


_SHORT_REPLAYS = {
    "survival": lambda: build_replay(mode=GameMode.SURVIVAL, ticks=3),
    "rush": lambda: build_replay(mode=GameMode.RUSH, ticks=16),
    "quest": lambda: build_replay(mode=GameMode.QUESTS, ticks=3, seed=101, quest_level="1.1"),
    "typo": lambda: build_typo_submit_replay(word="reload"),
    "tutorial": lambda: build_replay(mode=GameMode.TUTORIAL, ticks=3),
    "survival-2p": lambda: build_replay(mode=GameMode.SURVIVAL, ticks=3, player_count=2),
    "rush-3p": lambda: build_replay(mode=GameMode.RUSH, ticks=3, player_count=3),
    "quest-4p": lambda: build_replay(mode=GameMode.QUESTS, ticks=3, player_count=4, quest_level="2.5"),
}


@pytest.mark.parametrize("case", sorted(_SHORT_REPLAYS))
def test_zig_replay_verify_matches_python_for_every_mode(tmp_path: Path, zig_bin: Path, case: str) -> None:
    replay_path = write_replay(tmp_path, replay=_SHORT_REPLAYS[case](), name=f"{case}.crd")

    payload = _assert_verify_matches_python(zig_bin, [str(replay_path), "--format", "json"], exit_code=0)

    assert payload["status"] == "ok"
    assert payload["mismatched_fields"] == []
    assert payload["result"] == payload["recorded"]


@pytest.mark.parametrize(
    ("fixture_name", "outcome"),
    [
        ("perk_replay", RunOutcome.INCOMPLETE),
        ("quest_completed_replay", RunOutcome.QUEST_COMPLETED),
        ("survival_death_replay", RunOutcome.DEATH),
    ],
)
def test_zig_replay_verify_derives_python_results_for_played_runs(
    tmp_path: Path,
    zig_bin: Path,
    request: pytest.FixtureRequest,
    fixture_name: str,
    outcome: RunOutcome,
) -> None:
    replay = request.getfixturevalue(fixture_name)
    replay_path = write_replay(tmp_path, replay=replay, name=f"{fixture_name}.crd")

    payload = _run_zig_json(zig_bin, [str(replay_path), "--format", "json"])

    assert payload["status"] == "ok"
    assert payload["result"] == _json_result(replay.result)
    assert payload["result"]["outcome"] == outcome
    assert payload["ticks"] == payload["ticks_simulated"] == len(replay.ticks)


def test_zig_replay_verify_result_equals_python_simulation(tmp_path: Path, zig_bin: Path, perk_replay: Replay) -> None:
    replay_path = write_replay(tmp_path, replay=perk_replay, name="perk.crd")
    assert any(isinstance(command, PerkPickCommand) for tick in perk_replay.ticks for command in tick.commands)

    payload = _run_zig_json(zig_bin, [str(replay_path), "--format", "json"])

    python_result = build_verify_playback_driver(perk_replay).run()
    assert payload["result"] == _json_result(python_result)
    assert payload["result"]["players"][0]["shots_fired"] > 0


@pytest.mark.parametrize(
    "outcome",
    [RunOutcome.DEATH, RunOutcome.INCOMPLETE],
)
def test_zig_replay_verify_ends_runs_like_python_in_every_mode(tmp_path: Path, zig_bin: Path, outcome: RunOutcome) -> None:
    for mode, quest_level in ((GameMode.RUSH, None), (GameMode.TYPO, None), (GameMode.QUESTS, QuestLevel(1, 1))):
        max_ticks = 6000 if outcome == RunOutcome.DEATH else 120
        run = RunSpec(game_mode_id=mode, seed=0xBEEF, quest_level=quest_level)
        replay = record_bot_replay(run, fire=False, max_ticks=max_ticks)
        assert replay.result.outcome == outcome
        replay_path = write_replay(tmp_path, replay=replay, name=f"{mode.name.lower()}-{outcome}.crd")

        payload = _run_zig_json(zig_bin, [str(replay_path), "--format", "json"])

        assert payload["status"] == "ok", mode
        assert payload["result"] == _json_result(replay.result), mode


_RUN_VARIANTS = {
    "survival-demo": RunSpec(game_mode_id=GameMode.SURVIVAL, seed=19, demo=True),
    "quest-demo": RunSpec(game_mode_id=GameMode.QUESTS, seed=19, quest_level=QuestLevel(1, 3), demo=True),
    "tutorial-demo": RunSpec(game_mode_id=GameMode.TUTORIAL, seed=19, demo=True),
    "survival-hardcore-low-detail": RunSpec(
        game_mode_id=GameMode.SURVIVAL,
        seed=19,
        hardcore=True,
        detail_preset=1,
        violence_disabled=1,
    ),
    "survival-preserve-bugs-status": RunSpec(
        game_mode_id=GameMode.SURVIVAL,
        seed=19,
        preserve_bugs=True,
        status=RunStatus(
            quest_unlock_index=30,
            quest_unlock_index_full=35,
            weapon_usage_counts=tuple((index * 37) % 11 for index in range(53)),
        ),
    ),
    "quest-hardcore-retry-2p": RunSpec(
        game_mode_id=GameMode.QUESTS,
        seed=19,
        quest_level=QuestLevel(3, 7),
        player_count=2,
        hardcore=True,
        quest_fail_retry_count=3,
    ),
    "rush-2p": RunSpec(game_mode_id=GameMode.RUSH, seed=19, player_count=2),
    "typo-dictionary": RunSpec(
        game_mode_id=GameMode.TYPO,
        seed=19,
        typo_dictionary_words=("amber", "zinc", "two words"),
        typo_highscore_names=("Alpha", "Bravo"),
    ),
}


@pytest.mark.parametrize("case", sorted(_RUN_VARIANTS))
def test_zig_replay_verify_matches_python_for_run_spec_variants(tmp_path: Path, zig_bin: Path, case: str) -> None:
    replay = record_bot_replay(_RUN_VARIANTS[case], max_ticks=600)
    replay_path = write_replay(tmp_path, replay=replay, name=f"{case}.crd")

    payload = _run_zig_json(zig_bin, [str(replay_path), "--format", "json"])

    assert payload["status"] == "ok"
    assert payload["result"] == _json_result(replay.result)


def _typo_replay(
    tick_commands: list[GameCommand],
    *,
    ticks: int = 2,
    typo_dictionary_words: tuple[str, ...] = (),
    typo_highscore_names: tuple[str, ...] = (),
) -> Replay:
    """A Typ-o run (seed 1) whose last tick carries `tick_commands`."""

    run = RunSpec(
        game_mode_id=GameMode.TYPO,
        seed=1,
        typo_dictionary_words=typo_dictionary_words,
        typo_highscore_names=typo_highscore_names,
    )
    recorder = ReplayRecorder(run)
    idle = [PlayerInput(aim=Vec2(512.0, 512.0))]
    for _ in range(ticks - 1):
        recorder.record_tick(idle)
    recorder.record_tick(idle, commands=tick_commands)
    return finish_replay(recorder)


def _typed(word: str) -> list[GameCommand]:
    return [TypoCharCommand(player_index=0, ch=ch) for ch in word]


def test_zig_replay_verify_matches_python_typo_submit_semantics(tmp_path: Path, zig_bin: Path) -> None:
    submit = TypoSubmitCommand(player_index=0)
    cases = {
        # A creature named "reload" is a target, not the reload word.
        "creature-named-reload": (
            _typo_replay([*_typed("reload"), submit], typo_dictionary_words=("reload",)),
            (1, 1),
        ),
        # A later non-matching submit cancels the pending shot.
        "submit-cancels-pending-shot": (
            _typo_replay([*_typed("a"), submit, *_typed("b"), submit], typo_dictionary_words=("a",)),
            (2, 1),
        ),
    }

    for case, (replay, (shots_fired, shots_hit)) in cases.items():
        player = replay.result.players[0]
        assert (player.shots_fired, player.shots_hit) == (shots_fired, shots_hit), case
        replay_path = write_replay(tmp_path, replay=replay, name=f"{case}.crd")

        payload = _assert_verify_matches_python(zig_bin, [str(replay_path), "--format", "json"], exit_code=0)

        assert payload["status"] == "ok", case


def test_zig_replay_verify_keeps_long_highscore_names_in_the_pool(tmp_path: Path, zig_bin: Path) -> None:
    replay = _typo_replay(
        [],
        ticks=600,
        typo_highscore_names=("Alpha", "B" * 20, "Cy", "E" * 31, "Dee.Dee"),
    )
    replay_path = write_replay(tmp_path, replay=replay, name="typo-long-names.crd")

    payload = _run_zig_json(zig_bin, [str(replay_path), "--format", "json"])

    assert payload["status"] == "ok"
    assert payload["result"] == _json_result(replay.result)


def test_zig_replay_verify_rejects_invalid_typo_name_sources_like_python(tmp_path: Path, zig_bin: Path) -> None:
    payload = msgspec.msgpack.decode(encode_replay_payload(_typo_replay([], ticks=1)))
    cases = {
        "word-too-long": ("typo_dictionary_words", ["ok", "x" * 16], "run.typo_dictionary_words[1] must be 1..15 printable ASCII characters"),
        "word-not-ascii": ("typo_dictionary_words", ["héllo"], "run.typo_dictionary_words[0] must be 1..15 printable ASCII characters"),
        "too-many-words": ("typo_dictionary_words", ["w"] * 2049, "run.typo_dictionary_words has 2049 entries, expected at most 2048"),
        "name-too-long": ("typo_highscore_names", ["A" * 32], "run.typo_highscore_names[0] must be 1..31 ASCII letters or '.'"),
        "name-with-digit": ("typo_highscore_names", ["Ok", "R2D2"], "run.typo_highscore_names[1] must be 1..31 ASCII letters or '.'"),
        "too-many-names": ("typo_highscore_names", ["Name"] * 513, "run.typo_highscore_names has 513 entries, expected at most 512"),
    }

    for case, (field, values, detail) in cases.items():
        payload["run"][field] = values
        replay_path = write_payload_bytes(tmp_path, payload=msgspec.msgpack.encode(payload), name=f"{case}.crd")
        payload["run"][field] = []

        python_result = _run_python_verify([str(replay_path), "--format", "json"])
        zig_result = _run_zig(zig_bin, [str(replay_path), "--format", "json"])

        assert python_result.exit_code == 1, case
        assert zig_result.returncode == 1, case
        assert zig_result.stderr == f"replay verification failed: {detail}\n", case
        assert zig_result.stderr == python_result.output, case


def test_zig_replay_verify_matches_python_human_output(
    tmp_path: Path,
    zig_bin: Path,
    quest_completed_replay: Replay,
) -> None:
    cases = [
        write_replay(tmp_path, replay=build_replay(mode=GameMode.SURVIVAL, ticks=3), name="survival.crd"),
        write_replay(tmp_path, replay=quest_completed_replay, name="quest.crd"),
    ]
    for replay_path in cases:
        python_result = _run_python_verify([str(replay_path)])
        zig_result = _run_zig(zig_bin, [str(replay_path)])

        assert python_result.exit_code == 0, python_result.output
        assert zig_result.returncode == 0, dbg_record._command_detail(zig_result)
        assert zig_result.stdout == python_result.output
    assert "quest_final_ms=" in zig_result.stdout


def test_zig_replay_verify_reports_partial_prefix_like_python(tmp_path: Path, zig_bin: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    tampered = msgspec.structs.replace(replay, result=msgspec.structs.replace(replay.result, kills=9))
    replay_path = write_replay(tmp_path, replay=tampered, name="survival.crd")

    payload = _assert_verify_matches_python(
        zig_bin,
        [str(replay_path), "--format", "json", "--max-ticks", "2"],
        exit_code=0,
    )

    assert payload["status"] == "partial"
    assert payload["ticks"] == 3
    assert payload["ticks_simulated"] == 2
    assert payload["mismatched_fields"] == []
    assert payload["result"]["outcome"] == "incomplete"

    beyond = _run_zig(zig_bin, [str(replay_path), "--format", "json", "--max-ticks", "9"])
    assert beyond.returncode == 3, dbg_record._command_detail(beyond)
    assert json.loads(beyond.stdout)["status"] == "result_mismatch"


def test_zig_replay_verify_reports_result_mismatches_like_python(
    tmp_path: Path,
    zig_bin: Path,
    quest_completed_replay: Replay,
) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    player = msgspec.structs.replace(replay.result.players[0], health=50.0, shots_fired=4)
    tampered = msgspec.structs.replace(
        replay,
        result=msgspec.structs.replace(replay.result, outcome=RunOutcome.DEATH, kills=4, players=(player,)),
    )
    survival_path = write_replay(tmp_path, replay=tampered, name="survival-bad.crd")
    quest = msgspec.structs.replace(
        quest_completed_replay,
        result=msgspec.structs.replace(
            quest_completed_replay.result,
            quest_final_ms=int(quest_completed_replay.result.quest_final_ms or 0) + 1,
        ),
    )
    quest_path = write_replay(tmp_path, replay=quest, name="quest-bad.crd")

    survival_payload = _assert_verify_matches_python(zig_bin, [str(survival_path), "--format", "json"], exit_code=3)
    quest_payload = _assert_verify_matches_python(zig_bin, [str(quest_path), "--format", "json"], exit_code=3)

    assert survival_payload["status"] == "result_mismatch"
    assert survival_payload["mismatched_fields"] == [
        "outcome",
        "kills",
        "players[0].health",
        "players[0].shots_fired",
    ]
    assert survival_payload["recorded"]["players"][0]["health"] == 50.0
    assert quest_payload["mismatched_fields"] == ["quest_final_ms"]

    python_human = _run_python_verify([str(survival_path)])
    zig_human = _run_zig(zig_bin, [str(survival_path)])
    assert zig_human.returncode == 3
    assert zig_human.stdout == python_human.output
    assert "; mismatches=outcome,kills,players[0].health,players[0].shots_fired" in zig_human.stdout


def test_zig_replay_verify_reports_payload_hash_and_game_version(tmp_path: Path, zig_bin: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    payload = _run_zig_json(zig_bin, [str(replay_path), "--format", "json"])

    raw_payload = zstd.ZstdDecompressor().decompress(replay_path.read_bytes())
    assert payload["payload_sha256"] == hashlib.sha256(raw_payload).hexdigest()
    assert payload["game_version"] == replay.game_version
    assert payload["schema_version"] == 3


def _health_bytes(value: float) -> bytes:
    return b"\xa6health\xcb" + struct.pack(">d", value)


_NON_CANONICAL = {
    "int-for-float": (_health_bytes(100.0), b"\xa6health\x64"),
    "float32": (_health_bytes(100.0), b"\xa6health\xca" + struct.pack(">f", 100.0)),
    "inexact-f32": (_health_bytes(100.0), _health_bytes(100.1)),
    "non-minimal-uint": (b"\xacplayer_count\x01", b"\xacplayer_count\xcc\x01"),
    "non-minimal-int": (b"\xacplayer_count\x01", b"\xacplayer_count\xd0\x01"),
    "non-minimal-str": (b"\xa4seed", b"\xd9\x04seed"),
    "reordered-keys": (b"\xa8hardcore\xc2\xadpreserve_bugs\xc2", b"\xadpreserve_bugs\xc2\xa8hardcore\xc2"),
    "duplicate-key": (b"\xa4demo\xc2", b"\xa8hardcore\xc2"),
    "missing-key": (b"\x8d\xacgame_mode_id\x01", b"\x8c\xacgame_mode_id\x01", b"\xa4demo\xc2", b""),
    "extra-key": (b"\x8d\xacgame_mode_id\x01", b"\x8e\xacgame_mode_id\x01", b"\xa4demo\xc2", b"\xa4demo\xc2\xa5extra\x00"),
    "reordered-command-keys": (
        b"\xa4type\xa9typo_char\xacplayer_index\x00",
        b"\xacplayer_index\x00\xa4type\xa9typo_char",
    ),
}


@pytest.mark.parametrize("case", sorted(_NON_CANONICAL))
def test_zig_replay_verify_rejects_non_canonical_payloads(tmp_path: Path, zig_bin: Path, case: str) -> None:
    replay = build_typo_submit_replay(word="go") if "command" in case else build_replay(mode=GameMode.SURVIVAL, ticks=2)
    payload = encode_replay_payload(replay)
    replacements = _NON_CANONICAL[case]
    for old, new in zip(replacements[::2], replacements[1::2], strict=True):
        assert old in payload, case
        payload = payload.replace(old, new, 1)
    replay_path = write_payload_bytes(tmp_path, payload=payload, name=f"{case}.crd")

    zig_result = _run_zig(zig_bin, [str(replay_path), "--format", "json"])
    python_result = _run_python_verify([str(replay_path), "--format", "json"])

    assert python_result.exit_code == 1, python_result.output
    assert zig_result.returncode == 1, dbg_record._command_detail(zig_result)
    assert zig_result.stdout == ""
    assert zig_result.stderr.startswith("replay verification failed: ")


def test_zig_replay_verify_rejects_trailing_payload_bytes(tmp_path: Path, zig_bin: Path) -> None:
    payload = encode_replay_payload(build_replay(mode=GameMode.SURVIVAL, ticks=1)) + b"\xc0"
    replay_path = write_payload_bytes(tmp_path, payload=payload, name="trailing.crd")

    result = _run_zig(zig_bin, [str(replay_path)])

    assert result.returncode == 1
    assert "replay verification failed: invalid replay payload: trailing bytes" in result.stderr


def test_zig_replay_verify_reports_validation_errors_like_python(tmp_path: Path, zig_bin: Path) -> None:
    survival = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    old_format = encode_replay_payload(survival).replace(b"\xaeformat_version\x14", b"\xaeformat_version\x13", 1)
    cases = {
        "typo-event": (
            write_current_typo_event_replay(tmp_path, replay=survival, name="typo-event.crd"),
            "ticks[0].commands[0] Typ-o commands require game_mode_id=TYPO",
        ),
        "player-index": (
            write_current_bad_event_player_index_replay(tmp_path, replay=survival, name="player-index.crd"),
            "ticks[0].commands[0].player_index 1 is outside 0..0",
        ),
        "tick-players": (
            write_current_bad_tick_player_count_replay(tmp_path, replay=survival, name="tick-players.crd"),
            "ticks[0] has 0 player inputs, expected 1",
        ),
        "missing-quest-level": (
            write_current_missing_quest_level_replay(tmp_path, replay=survival, name="missing-quest-level.crd"),
            "run.quest_level must be set for quests and only for quests",
        ),
        "typo-multiplayer": (
            write_current_mode_player_count_replay(
                tmp_path,
                replay=survival,
                name="typo-multiplayer.crd",
                mode=GameMode.TYPO,
                player_count=2,
            ),
            "typo replays require player_count == 1",
        ),
        "old-format": (
            write_payload_bytes(tmp_path, payload=old_format, name="old-format.crd"),
            "unsupported replay format version: 19",
        ),
    }

    for case, (replay_path, detail) in cases.items():
        python_result = _run_python_verify([str(replay_path), "--format", "json"])
        zig_result = _run_zig(zig_bin, [str(replay_path), "--format", "json"])

        assert python_result.exit_code == 1, case
        assert zig_result.returncode == 1, case
        assert zig_result.stdout == "", case
        assert zig_result.stderr == f"replay verification failed: {detail}\n", case
        assert zig_result.stderr == python_result.output, case


def test_zig_replay_verify_rejects_malformed_commands(tmp_path: Path, zig_bin: Path) -> None:
    survival = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    for replay_path in (
        write_current_unknown_command_replay(tmp_path, replay=survival, name="unknown-command.crd"),
        write_current_missing_perk_choice_replay(tmp_path, replay=survival, name="missing-choice.crd"),
    ):
        python_result = _run_python_verify([str(replay_path), "--format", "json"])
        zig_result = _run_zig(zig_bin, [str(replay_path), "--format", "json"])

        assert python_result.exit_code == 1
        assert zig_result.returncode == 1
        assert zig_result.stdout == ""
        assert zig_result.stderr.startswith("replay verification failed: ticks[0].commands[0]")


def test_zig_replay_verify_rejects_illegal_perk_commands_like_python(
    tmp_path: Path,
    zig_bin: Path,
    perk_replay: Replay,
) -> None:
    pick_tick = next(index for index, tick in enumerate(perk_replay.ticks) if tick.commands)
    cases = {
        "pick-without-pending": (
            with_tick_commands(
                build_replay(mode=GameMode.SURVIVAL, ticks=2),
                1,
                [PerkPickCommand(player_index=0, choice_index=0)],
            ),
            "tick 1: perk_pick without a pending perk",
        ),
        "menu-open-in-rush": (
            with_tick_commands(build_replay(mode=GameMode.RUSH, ticks=1), 0, [PerkMenuOpenCommand(player_index=0)]),
            "tick 0: perk_menu_open without a pending perk",
        ),
        "unoffered-choice": (
            with_tick_commands(
                perk_replay,
                pick_tick,
                [PerkMenuOpenCommand(player_index=0), PerkPickCommand(player_index=0, choice_index=6)],
            ),
            f"tick {pick_tick}: perk_pick choice_index=6 is not an offered choice",
        ),
        "second-pick": (
            with_tick_commands(
                perk_replay,
                pick_tick,
                [*perk_replay.ticks[pick_tick].commands, PerkPickCommand(player_index=0, choice_index=0)],
            ),
            f"tick {pick_tick}: perk_pick without a pending perk",
        ),
    }

    for case, (replay, detail) in cases.items():
        replay_path = write_replay(tmp_path, replay=replay, name=f"{case}.crd")
        python_result = _run_python_verify([str(replay_path), "--format", "json"])
        zig_result = _run_zig(zig_bin, [str(replay_path), "--format", "json"])

        assert python_result.exit_code == 1, case
        assert zig_result.returncode == 1, case
        assert zig_result.stderr == f"replay verification failed: {detail}\n", case
        assert zig_result.stderr == python_result.output, case


def test_zig_replay_verify_rejects_ticks_after_the_run_ended(
    tmp_path: Path,
    zig_bin: Path,
    survival_death_replay: Replay,
) -> None:
    replay_path = write_replay(tmp_path, replay=with_idle_ticks(survival_death_replay, 2), name="after-end.crd")
    last_tick = len(survival_death_replay.ticks) - 1

    python_result = _run_python_verify([str(replay_path), "--format", "json"])
    zig_result = _run_zig(zig_bin, [str(replay_path), "--format", "json"])

    assert python_result.exit_code == 1
    assert zig_result.returncode == 1
    assert zig_result.stderr == (
        f"replay verification failed: run ended (death) at tick {last_tick} "
        f"but the replay has {last_tick + 3} ticks\n"
    )
    assert zig_result.stderr == python_result.output


def test_zig_replay_verify_writes_json_out_like_python(tmp_path: Path, zig_bin: Path) -> None:
    replay_path = write_replay(tmp_path, replay=build_replay(mode=GameMode.SURVIVAL, ticks=2), name="survival.crd")
    json_out = tmp_path / "reports" / "verify.json"

    result = _run_zig(zig_bin, [str(replay_path), "--format", "json", "--json-out", str(json_out)])

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert json.loads(json_out.read_text(encoding="utf-8")) == json.loads(result.stdout)


def test_zig_replay_verify_accepts_relative_base_dir(tmp_path: Path, zig_bin: Path) -> None:
    write_replay(tmp_path / "replays", replay=build_replay(mode=GameMode.SURVIVAL, ticks=2), name="relative.crd")
    relative_base = os.path.relpath(tmp_path, dbg_record._REPO_ROOT)

    payload = _run_zig_json(zig_bin, ["relative.crd", "--base-dir", relative_base, "--format", "json"])

    assert payload["status"] == "ok"
    assert payload["replay"] == f"{relative_base}/replays/relative.crd"
    assert payload["ticks_simulated"] == 2


def test_zig_replay_verify_rejects_bad_envelopes(tmp_path: Path, zig_bin: Path) -> None:
    txt_path = tmp_path / "survival.txt"
    txt_path.write_bytes(b"not checked before extension validation")
    raw_path = tmp_path / "raw.crd"
    raw_path.write_bytes(encode_replay_payload(build_replay(mode=GameMode.SURVIVAL, ticks=1)))
    cases = {
        txt_path: "replay file must use .crd extension",
        raw_path: "replay must use the zstd envelope",
    }

    for replay_path, detail in cases.items():
        result = _run_zig(zig_bin, [str(replay_path), "--format", "json"])

        assert result.returncode == 1
        assert result.stdout == ""
        assert result.stderr == f"replay verification failed: {detail}\n"


@pytest.mark.parametrize("option", ["--submitted-score", "--lenient-events", "--strict-events"])
def test_zig_replay_verify_rejects_removed_options(tmp_path: Path, zig_bin: Path, option: str) -> None:
    replay_path = write_replay(tmp_path, replay=build_replay(mode=GameMode.SURVIVAL, ticks=1), name="survival.crd")

    result = _run_zig(zig_bin, [str(replay_path), option])

    assert result.returncode == 1
    assert result.stdout == ""
    assert f"invalid replay verify args: {option}" in result.stderr


def _json_result(result: RunResult) -> dict:
    return json.loads(msgspec.json.encode(result))


def _assert_verify_matches_python(zig_bin: Path, args: list[str], *, exit_code: int) -> dict:
    python_result = _run_python_verify(args)
    zig_result = _run_zig(zig_bin, args)

    assert python_result.exit_code == exit_code, python_result.output
    assert zig_result.returncode == exit_code, dbg_record._command_detail(zig_result)
    zig_payload = json.loads(zig_result.stdout)
    assert zig_payload == json.loads(python_result.output)
    return zig_payload


def _run_python_verify(args: list[str]):
    return CliRunner().invoke(app, ["replay", "verify", *args])


def _run_zig_json(zig_bin: Path, args: list[str]) -> dict:
    result = _run_zig(zig_bin, args)
    assert result.returncode == 0, dbg_record._command_detail(result)
    return json.loads(result.stdout)


def _run_zig(zig_bin: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return dbg_record._run_process([str(zig_bin), "replay", "verify", *args], cwd=dbg_record._REPO_ROOT)
