from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from crimson.persistence.highscores import (
    HighScoreRecord,
    append_highscore_records,
    decode_highscore_record,
    highscore_date_week,
    read_highscore_records,
)
from crimson.persistence.scores5 import _RECORD


@pytest.fixture(scope="module")
def score_decoder(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = Path(__file__).resolve().parents[2]
    binary = tmp_path_factory.mktemp("score-contract") / "decode"
    subprocess.run([
        shutil.which("clang++") or "c++", "-std=c++17", "-w",
        f"-I{root / 'crimson-core/game/include'}", f"-I{root / 'tools/match/include'}",
        f"-I{root / 'third_party/headers'}",
        str(Path(__file__).with_name("score_contract_harness.cpp")),
        str(root / "decomp/1.9/crimsonland/highscore/highscore_iso_week.cpp"), "-o", str(binary),
    ], check=True)
    return binary


def test_shared_decoding_corpus(score_decoder: Path) -> None:
    cases = json.loads(Path(__file__).with_name("score_contract.json").read_text())
    lines = [case["line"].encode("utf-8") for case in cases]
    native = subprocess.check_output([score_decoder], input=b"\n".join(lines) + b"\n").decode().splitlines()
    assert len(native) == len(cases)
    for case, line, actual in zip(cases, lines, native, strict=True):
        if not case["valid"]:
            with pytest.raises(ValueError):
                decode_highscore_record(line)
            assert actual == "invalid", case["name"]
            continue
        record = decode_highscore_record(line)
        date = record.date
        level = record.quest_level
        raw = _RECORD.pack(
            record.name.encode("latin-1"), record.run_elapsed_ms, record.score_xp, record.game_mode_id,
            level.major if level else 0, level.minor if level else 0, record.most_used_weapon_id,
            record.shots_fired, record.shots_hit, record.creature_kill_count, record.uni_num,
            record.replay_number.to_bytes(4, "little"), date.day if date else 0,
            highscore_date_week(date.year, date.month, date.day) if date else 0,
            date.month if date else 0, date.year - 2000 if date else 0, 0, 0x75 if record.hardcore else 0,
        )[:-2] + b"\x7c\xff"
        expected = f"{raw.hex()} {record.player_count} {record.score_list.encode('latin-1').hex()} {record.run} {record.import_id}"
        assert actual == expected, case["name"]


def test_invalid_utf8_is_rejected_by_both_readers(score_decoder: Path) -> None:
    for value in (b"\xc0\xa1", b"\xff", b"\xed\xa0\x80"):
        line = b'{"v":1,"name":"' + value + b'"}'
        with pytest.raises(ValueError):
            decode_highscore_record(line)
        assert subprocess.check_output([score_decoder], input=line + b"\n") == b"invalid\n"


@pytest.mark.skipif(os.name == "nt", reason="The desktop WASI adapter currently targets macOS/Linux")
def test_native_and_python_partial_appends_share_the_lock(tmp_path: Path, monkeypatch) -> None:
    root = Path(__file__).resolve().parents[2]
    # Only these generated wasm2c declarations are needed by the actual WASI adapter.
    (tmp_path / "game.h").write_text(
        "#include <stdint.h>\ntypedef uint8_t u8; typedef uint32_t u32;\n"
        "struct w2c_game; struct w2c_wasi__snapshot__preview1;\n",
    )
    binary = tmp_path / "writer"
    subprocess.run([
        shutil.which("clang++") or "c++", "-std=c++17", f"-I{tmp_path}",
        f"-I{root / 'crimson-core/client'}", str(Path(__file__).with_name("wasi_score_writer.cpp")),
        "-o", str(binary),
    ], check=True)
    write = os.write
    monkeypatch.setattr(os, "write", lambda fd, data: write(fd, data[:3]))
    child = subprocess.Popen([binary, tmp_path])
    for i in range(10):
        append_highscore_records(tmp_path, [HighScoreRecord(name=f"python-{i}")])
    assert child.wait(timeout=30) == 0
    assert {r.name for r in read_highscore_records(tmp_path)} == {
        f"{client}-{i}" for client in ("native", "python") for i in range(10)
    }
