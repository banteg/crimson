from __future__ import annotations

import datetime as dt
import shutil
import subprocess
from pathlib import Path

import msgspec
import pytest

from crimson.game_modes import GameMode
from crimson.persistence import scores5
from crimson.persistence.highscores import HighScoreRecord, read_highscore_records
from crimson.quests.level import QuestLevel
from crimson.weapons import WeaponId


@pytest.fixture(scope="module")
def original_writer(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = Path(__file__).resolve().parents[2]
    # Clang, as the recovered sources build: the stub headers' WINAPI is __stdcall, which GCC rejects.
    cc = shutil.which("clang")
    assert cc is not None
    exe = tmp_path_factory.mktemp("highscore") / "highscore_record_harness"
    subprocess.run(
        [
            cc,
            "-w",
            "-fsigned-char",  # MSVC x86 char
            f"-I{root / 'crimson-core/game/include'}",
            f"-I{root / 'tools/match/include'}",
            f"-I{root / 'third_party/headers'}",
            str(Path(__file__).with_name("highscore_record_harness.c")),
            str(root / "decomp/1.9/crimsonland/highscore/highscore_write_record.cpp"),
            "-o",
            str(exe),
        ],
        check=True,
    )
    return exe


def _raw(
    name: bytes, mode: GameMode, *, elapsed_ms: int = 0, xp: int = 0, stage: tuple[int, int] = (0, 0),
    replay_number: int = 0, flags: int = 0, marker: int = 0,
) -> bytes:
    """A decoded `highscore_record_t`, as the original holds it in memory."""
    return scores5._RECORD.pack(
        name, elapsed_ms, xp, mode, *stage, WeaponId.SHOTGUN, 30, 20, 10, 0x1234,
        replay_number.to_bytes(4, "little"), 22, 43, 10, 26, flags, marker,
    )


def _write(writer: Path, path: Path, *records: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(subprocess.run([writer], input=b"".join(records), capture_output=True, check=True).stdout)


def test_original_tables_import_with_their_keys_and_move_aside(tmp_path: Path, original_writer: Path) -> None:
    root = tmp_path / "scores5"
    _write(
        original_writer,
        root / "survival.hi",
        _raw(b"\xc4\xe9\xff", GameMode.SURVIVAL, elapsed_ms=754_321, xp=98_765, replay_number=3),
        _raw(b"Internet", GameMode.SURVIVAL, xp=5, flags=1),
        _raw(b"Sent", GameMode.SURVIVAL, xp=6, flags=3),
    )
    _write(
        original_writer,
        root / "quest2_7_2.hiBob",
        _raw(b"Pair", GameMode.QUESTS, elapsed_ms=-500, stage=(2, 7), marker=scores5.HARDCORE_MARKER),
    )
    _write(original_writer, root / "typo.hi", _raw(b"Typist", GameMode.TYPO, xp=40))

    assert scores5.import_original_scores(tmp_path) == [root / "quest2_7_2.hiBob", root / "survival.hi", root / "typo.hi"]

    stats = HighScoreRecord(
        most_used_weapon_id=WeaponId.SHOTGUN, shots_fired=30, shots_hit=20, creature_kill_count=10, uni_num=0x1234,
        date=dt.date(2026, 10, 22),
    )
    assert read_highscore_records(tmp_path) == [
        msgspec.structs.replace(
            stats, name="Pair", game_mode_id=GameMode.QUESTS, quest_level=QuestLevel(2, 7), hardcore=True,
            player_count=2, score_list="Bob", run_elapsed_ms=-500,
        ),
        msgspec.structs.replace(
            stats, name="Äéÿ", game_mode_id=GameMode.SURVIVAL, run_elapsed_ms=754_321, score_xp=98_765, replay_number=3,
        ),
        msgspec.structs.replace(stats, name="Sent", game_mode_id=GameMode.SURVIVAL, score_xp=6),
        msgspec.structs.replace(stats, name="Typist", game_mode_id=GameMode.TYPO, score_xp=40),
    ]
    assert sorted(path.name for path in root.iterdir()) == ["imported"]
    assert scores5.import_original_scores(tmp_path) == []


def test_a_table_an_older_client_writes_later_imports_on_the_next_boot(tmp_path: Path, original_writer: Path) -> None:
    root = tmp_path / "scores5"
    for name in (b"First", b"Second"):
        _write(original_writer, root / "rush.hi", _raw(name, GameMode.RUSH, elapsed_ms=1000))
        scores5.import_original_scores(tmp_path)

    assert [record.name for record in read_highscore_records(tmp_path)] == ["First", "Second"]
    assert sorted(path.name for path in (root / "imported").iterdir()) == ["rush.hi", "rush.hi.1"]
