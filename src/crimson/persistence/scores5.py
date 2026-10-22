"""Import the original's `scores5/*.hi` tables into `scores.jsonl` (docs/formats/highscores.md).

Each imported file moves to `scores5/imported/`, so a table an older client writes later imports on the next boot.
"""

from __future__ import annotations

import datetime as dt
import re
import struct
from pathlib import Path

from crimson.quests.level import QuestLevel

from ..game_modes import GameMode
from ..weapons import WeaponId
from .highscores import HighScoreRecord, append_highscore_records

SCORES5_DIR_NAME = "scores5"
RECORD_SIZE = 0x48
RECORD_WIRE_SIZE = RECORD_SIZE + 4  # record + checksum
NAME_SIZE = 0x20
HARDCORE_MARKER = 0x75
# `highscore_sync_worker` sets bit 0 on a record received from the internet; bit 1 marks one of local origin.
_RECEIVED_FLAG = 1
_LOCAL_ORIGIN_FLAG = 2

# `highscore_build_path`'s names, the `_<players>` suffix the port added for 3-4 players, and a named list after
# `.hi`; `typo` is the name an earlier port gave Typ-o's table.
_TABLE_NAME = re.compile(
    r"(?:survival|rush|unknown|typo|quest(?:hc)?\d+_\d+)(?:_(?P<players>[2-4]))?\.hi(?P<score_list>.*)",
)

_RECORD = struct.Struct("<32siIBBBBIIII4sBBBBBB2x")
assert _RECORD.size == RECORD_SIZE


def _score_checksum(data: bytes) -> int:
    # highscore_write_record/highscore_read_record sum through `char *`, signed on MSVC x86.
    return sum((idx + 3) * b * 7 for idx, b in enumerate(memoryview(data).cast("b"))) & 0xFFFFFFFF


def _decode_payload(encoded: bytes) -> bytes:
    # highscore_read_record: b += (-6 - ((idx * 5 + 1) * idx))
    return bytes((b - ((idx * 5 + 1) * idx + 6)) & 0xFF for idx, b in enumerate(encoded))


def read_original_records(path: Path, *, player_count: int = 1, score_list: str = "") -> list[HighScoreRecord]:
    """A `.hi` table's own records, as `highscore_read_record` reads them; records received from the internet stay
    out, since the leaderboard serves those now."""
    data = path.read_bytes()
    records: list[HighScoreRecord] = []
    for offset in range(0, len(data) - RECORD_WIRE_SIZE + 1, RECORD_WIRE_SIZE):
        payload = _decode_payload(data[offset : offset + RECORD_SIZE])
        if _score_checksum(payload) != struct.unpack_from("<I", data, offset + RECORD_SIZE)[0]:
            continue
        (
            name, elapsed_ms, xp, mode, major, minor, weapon, fired, hit, kills, uni_num,
            replay_number, day, _week, month, year_offset, flags, marker,
        ) = _RECORD.unpack(payload)
        if flags & _RECEIVED_FLAG and not flags & _LOCAL_ORIGIN_FLAG:
            continue
        records.append(
            HighScoreRecord(
                name=name.split(b"\x00", 1)[0].decode("latin-1"),
                game_mode_id=GameMode(mode),
                quest_level=QuestLevel(major, minor) if major and minor else None,
                hardcore=marker == HARDCORE_MARKER,
                player_count=player_count,
                score_list=score_list,
                run_elapsed_ms=elapsed_ms,
                score_xp=xp,
                most_used_weapon_id=WeaponId(weapon),
                shots_fired=fired,
                shots_hit=hit,
                creature_kill_count=kills,
                uni_num=uni_num,
                date=dt.date(2000 + year_offset, month, day) if day else None,
                replay_number=int.from_bytes(replay_number, "little"),
            ),
        )
    return records


def import_original_scores(base_dir: Path) -> list[Path]:
    """Append the `scores5` tables' records to `scores.jsonl` and move the files aside; returns the imported files."""
    root = base_dir / SCORES5_DIR_NAME
    imported_dir = root / "imported"
    imported: list[Path] = []
    for path in sorted(root.glob("*.hi*")):
        match = _TABLE_NAME.fullmatch(path.name)
        if match is None or not path.is_file():
            continue
        players = match["players"]
        records = read_original_records(path, player_count=int(players) if players else 1, score_list=match["score_list"])
        append_highscore_records(base_dir, records)
        imported_dir.mkdir(exist_ok=True)
        target = imported_dir / path.name
        copy = 1
        while target.exists():
            target = imported_dir / f"{path.name}.{copy}"
            copy += 1
        path.rename(target)
        imported.append(path)
    return imported
