"""The port's high scores: one typed record per line in `scores.jsonl`, shared with the native client.

The original kept a scrambled, checksummed `scores5/*.hi` file per table; `scores5.py` imports those.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Annotated, Any

import msgspec

from crimson.msgspec_types import I32, U32, PlayerCount
from crimson.quests.level import QuestLevel
from grim.config import CrimsonConfig, HighScoreDateMode

from ..game_modes import GameMode
from ..weapons import WeaponId

SCORES_FILE_NAME = "scores.jsonl"
TABLE_MAX = 100

NAME_MAX_EDIT = 0x14  # game_over_screen_update sets ui_text_input maxlen=0x14
UNI_NUM_MASK = 16348 * 16348 - 1


def highscore_date_week(year: int, month: int, day: int) -> int:
    """Port of the native `dateWeek` helper (0x0043a950)."""
    i_var1 = (0x0E - int(month)) // 0x0C
    i_var2 = (int(year) - i_var1) + 0x12C0
    i_var1 = (
        ((i_var2 + ((i_var2 >> 31) & 3)) >> 2)
        - 0x7D2D
        + int(day)
        + ((i_var2 // 400 + (((int(month) + i_var1 * 0x0C) * 0x99 - 0x1C9) // 5 + i_var2 * 0x16D)) - i_var2 // 100)
    )
    i_var2 = ((((i_var1 - i_var1 % 7) + 0x7BFD) % 0x23AB1) % 0x8EAC) % 0x5B5
    i_var1 = i_var2 // 0x5B4
    return ((i_var2 - i_var1) % 0x16D + i_var1) // 7 + 1


def _i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & 0x80000000 else value


def _today() -> dt.date:
    return dt.datetime.now(tz=dt.UTC).astimezone().date()


class ScoreTable(msgspec.Struct, frozen=True):
    """A high score list: `highscore_build_path`'s file in the original, a key on each record here.

    Only quests keep hardcore runs apart; the original filters them by the record's hardcore marker.
    """

    game_mode_id: GameMode
    quest_level: QuestLevel | None = None
    hardcore: bool = False
    player_count: PlayerCount = 1
    score_list: str = ""

    @classmethod
    def for_config(
        cls, config: CrimsonConfig, *, game_mode_id: GameMode | None = None, quest_level: QuestLevel | None = None,
    ) -> ScoreTable:
        """The table a run of the configured (or given) mode saves into: the configured team and selected list."""
        mode = GameMode(config.gameplay.mode) if game_mode_id is None else game_mode_id
        quests = mode == GameMode.QUESTS
        return cls(
            game_mode_id=mode,
            quest_level=(config.gameplay.quest_level if quest_level is None else quest_level) if quests else None,
            hardcore=config.gameplay.hardcore and quests,
            player_count=config.gameplay.player_count,
            score_list=config.profile.named_score_list,
        )

    def stamp(self, record: HighScoreRecord) -> HighScoreRecord:
        """The record as this table saves it: its mode, team and list, and a quest table's level and difficulty."""
        record = msgspec.structs.replace(
            record, game_mode_id=self.game_mode_id, player_count=self.player_count, score_list=self.score_list,
        )
        if self.game_mode_id == GameMode.QUESTS:
            record = msgspec.structs.replace(record, quest_level=self.quest_level, hardcore=self.hardcore)
        else:
            record = msgspec.structs.replace(record, quest_level=None)
        return record

    def holds(self, record: HighScoreRecord) -> bool:
        quests = self.game_mode_id == GameMode.QUESTS
        return (
            record.game_mode_id == self.game_mode_id
            and record.player_count == self.player_count
            and record.score_list == self.score_list
            and (not quests or (record.quest_level == self.quest_level and record.hardcore == self.hardcore))
        )


type ScoreText = Annotated[str, msgspec.Meta(pattern=r"^[\x01-\xff]*$")]
type ScoreName = Annotated[str, msgspec.Meta(max_length=31, pattern=r"^[\x01-\xff]*$")]
type RunId = Annotated[str, msgspec.Meta(pattern=r"^(?:[0-9a-f]{64})?\Z")]
type ImportId = Annotated[str, msgspec.Meta(pattern=r"^(?:[0-9a-f]{64}:[0-9]+)?\Z")]


class HighScoreRecord(msgspec.Struct, kw_only=True, omit_defaults=True, forbid_unknown_fields=True, tag_field="v", tag=1):
    """`highscore_record_t` as the port stores it, with its table and the replay it links."""

    name: ScoreName = ""
    game_mode_id: GameMode = GameMode.DEMO
    quest_level: QuestLevel | None = None
    hardcore: bool = False
    player_count: PlayerCount = 1
    score_list: ScoreName = ""
    run_elapsed_ms: I32 = 0
    score_xp: U32 = 0
    most_used_weapon_id: WeaponId = WeaponId.NONE
    shots_fired: U32 = 0
    shots_hit: U32 = 0
    creature_kill_count: U32 = 0
    uni_num: U32 = 0
    # The local date `highscore_write_record` stamps.
    date: dt.date | None = None
    # The run's replay, `replays/<n>-<mode>.crd` (crimson.replay.library); 0 for none.
    replay_number: U32 = 0
    # The run's id on the leaderboard: its replay's (`replay_run_id`), or the board's for a received record.
    run: RunId = ""
    rules: U32 | None = None
    game_version: ScoreText = ""
    # A record received from the leaderboard: drawn green, never saved.
    received: bool = False
    # Source table digest and byte offset. Retried/concurrent imports keep one logical row.
    import_id: ImportId = ""

    @classmethod
    def blank(cls, *, rand_value: int) -> HighScoreRecord:
        """`highscore_record_init`: an empty record with its random tag."""
        return cls(uni_num=int(rand_value) & UNI_NUM_MASK)

    def copy(self) -> HighScoreRecord:
        return msgspec.structs.replace(self)

    def ensure_date(self, today: dt.date | None = None) -> None:
        if self.date is None:
            self.date = today or _today()


_ENCODER = msgspec.json.Encoder()
_DECODER = msgspec.json.Decoder(HighScoreRecord)


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError(f"duplicate score field: {key}")
        fields[key] = value
    return fields


def decode_highscore_record(line: bytes) -> HighScoreRecord:
    """The shared v1 contract: strict fields, integer tokens, Latin-1 text, and native calendar bounds."""
    # msgspec's typed decoder validates the wire types (including integer tokens and ISO dates).
    try:
        record = _DECODER.decode(line)
    except msgspec.DecodeError as exc:
        raise ValueError(str(exc)) from exc
    fields = json.loads(line, object_pairs_hook=_unique_fields)
    if "v" not in fields:
        raise ValueError("missing score version")
    if record.date is not None and not 2000 <= record.date.year <= 2255:
        raise ValueError("score year must be in 2000..2255")
    if record.received:
        raise ValueError("received scores are not local records")
    if record.game_mode_id != GameMode.QUESTS and record.quest_level is not None:
        raise ValueError("only quest scores have a quest level")
    return record


def scores_path(base_dir: Path) -> Path:
    return base_dir / SCORES_FILE_NAME


def read_highscore_records(base_dir: Path) -> list[HighScoreRecord]:
    """Every saved record; a line that does not decode (a torn write, a newer version's) is skipped."""
    try:
        lines = scores_path(base_dir).read_bytes().splitlines()
    except FileNotFoundError:
        return []
    records: list[HighScoreRecord] = []
    imported: set[str] = set()
    for line in lines:
        try:
            record = decode_highscore_record(line)
        except ValueError:
            continue
        if record.import_id:
            if record.import_id in imported:
                continue
            imported.add(record.import_id)
        records.append(record)
    return records


def append_highscore_records(base_dir: Path, records: list[HighScoreRecord]) -> None:
    """Serialize appends, finish short writes, and acknowledge only flushed records.

    Native desktop writers take the same flock; the browser owns its directory with a Web Lock.
    """
    if not records:
        return
    path = scores_path(base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = b"".join(_ENCODER.encode(record) + b"\n" for record in records)
    for line in payload.splitlines():
        decode_highscore_record(line)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o644)
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        size = os.fstat(fd).st_size
        # A torn last line would swallow this record's start.
        if size:
            os.lseek(fd, size - 1, os.SEEK_SET)
            if os.read(fd, 1) != b"\n":
                payload = b"\n" + payload
        try:
            pending = memoryview(payload)
            while pending:
                written = os.write(fd, pending)
                if written == 0:
                    raise OSError("score write made no progress")
                pending = pending[written:]
            os.fsync(fd)
        except OSError:
            # The lock makes rollback safe; a retry must not duplicate a completed prefix.
            os.ftruncate(fd, size)
            raise
    finally:
        os.close(fd)


def _passes_date_filter(entry: HighScoreRecord, date_mode: HighScoreDateMode, now: dt.date) -> bool:
    if date_mode == HighScoreDateMode.ALL_TIME:
        return True
    date = entry.date
    if date is None or date.year != now.year:
        return False
    match date_mode:
        case HighScoreDateMode.MONTH:
            return date.month == now.month
        case HighScoreDateMode.WEEK:
            return highscore_date_week(date.year, date.month, date.day) == highscore_date_week(
                now.year, now.month, now.day,
            )
        case HighScoreDateMode.DAY:
            return date.day == now.day and date.month == now.month
    return False


def select_highscore_table(
    records: list[HighScoreRecord],
    *,
    game_mode_id: GameMode,
    date_mode: HighScoreDateMode,
    now: dt.date,
) -> list[HighScoreRecord]:
    eligible = [r for r in records if r.game_mode_id == game_mode_id and _passes_date_filter(r, date_mode, now)]
    return sort_highscores(eligible, game_mode_id=game_mode_id)[:TABLE_MAX]


def read_highscore_table(
    base_dir: Path,
    table: ScoreTable,
    *,
    date_mode: HighScoreDateMode = HighScoreDateMode.ALL_TIME,
    now: dt.date | None = None,
) -> list[HighScoreRecord]:
    return select_highscore_table(
        [record for record in read_highscore_records(base_dir) if table.holds(record)],
        game_mode_id=table.game_mode_id,
        date_mode=date_mode,
        now=now or _today(),
    )


def _score_key(record: HighScoreRecord, game_mode_id: GameMode) -> tuple[bool, int]:
    # Native comparators interpret both fields as signed ints. Quest bonuses
    # can legitimately produce a negative final time; zero is an empty entry.
    if game_mode_id in (GameMode.RUSH, GameMode.QUESTS):
        value = record.run_elapsed_ms
    else:
        value = _i32(record.score_xp)
    if game_mode_id == GameMode.QUESTS:
        return value == 0, value
    return False, -value


def sort_highscores(records: list[HighScoreRecord], *, game_mode_id: GameMode) -> list[HighScoreRecord]:
    return sorted(records, key=lambda record: _score_key(record, game_mode_id))


def rank_index(records_sorted: list[HighScoreRecord], record: HighScoreRecord) -> int:
    key = _score_key(record, record.game_mode_id)
    for idx, entry in enumerate(records_sorted):
        if key < _score_key(entry, record.game_mode_id):
            return idx
    return len(records_sorted)


def upsert_highscore_record(
    base_dir: Path,
    table: ScoreTable,
    record: HighScoreRecord,
    *,
    date_mode: HighScoreDateMode = HighScoreDateMode.ALL_TIME,
    now: dt.date | None = None,
) -> tuple[list[HighScoreRecord], int]:
    """Save a qualifying score into `table`; history outside the displayed table stays."""
    now = now or _today()
    shown = read_highscore_table(base_dir, table, date_mode=date_mode, now=now)
    idx = rank_index(shown, record)
    if idx >= TABLE_MAX:
        return shown, idx
    # highscore_save_record strips trailing spaces in place before saving, down to the first character.
    candidate = table.stamp(msgspec.structs.replace(record, name=record.name[:1] + record.name[1:].rstrip(" ")))
    candidate.ensure_date(now)
    append_highscore_records(base_dir, [candidate])
    shown.insert(idx, candidate)
    return shown[:TABLE_MAX], idx
