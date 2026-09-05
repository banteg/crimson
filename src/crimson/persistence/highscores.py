from __future__ import annotations

import datetime as dt
import struct
from pathlib import Path

import msgspec

from crimson.quests.level import QuestLevel
from grim.atomic_write import atomic_write_bytes
from grim.config import CrimsonConfig, HighScoreDateMode
from grim.rand import Crand, CrandLike

from ..game_modes import GameMode
from ..weapons import WeaponId

RECORD_SIZE = 0x48
RECORD_WIRE_SIZE = RECORD_SIZE + 4  # record + checksum
TABLE_MAX = 100

NAME_SIZE = 0x20
NAME_MAX_EDIT = 0x14  # game_over_screen_update sets ui_text_input maxlen=0x14
UNI_NUM_MASK = 16348 * 16348 - 1


def _known_game_mode(value: int) -> GameMode:
    raw = int(value)
    try:
        return GameMode(raw)
    except ValueError:
        return GameMode.DEMO


def _clamp_u32(value: int) -> int:
    return int(value) & 0xFFFFFFFF


def _score_checksum(data: bytes) -> int:
    if len(data) != RECORD_SIZE:
        raise ValueError(f"expected {RECORD_SIZE:#x} bytes, got {len(data):#x}")
    checksum = 0
    for idx, b in enumerate(data):
        checksum = _clamp_u32(checksum + (idx + 3) * int(b) * 7)
    return checksum


def _encode_byte(value: int, idx: int) -> int:
    # highscore_write_record: b += ((idx * 5 + 1) * idx + 6)
    return (int(value) + (idx * 5 + 1) * idx + 6) & 0xFF


def _decode_byte(value: int, idx: int) -> int:
    # highscore_read_record: b += (-6 - ((idx * 5 + 1) * idx))
    return (int(value) - ((idx * 5 + 1) * idx + 6)) & 0xFF


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


def _score_uni_num_from_rand(rand_value: int) -> int:
    return int(rand_value) & UNI_NUM_MASK


class HighScoreRecord(msgspec.Struct):
    data: bytearray

    @classmethod
    def blank(cls, *, rng: CrandLike | None = None, rand_value: int | None = None) -> HighScoreRecord:
        if rng is not None and rand_value is not None:
            raise ValueError("pass either rng or rand_value, not both")
        data = bytearray(RECORD_SIZE)
        data[0x46] = 0x7C
        data[0x47] = 0xFF
        record = cls(data=data)
        if rand_value is None:
            rand_value = (rng if rng is not None else Crand()).rand()
        record.uni_num = _score_uni_num_from_rand(rand_value)
        return record

    @classmethod
    def from_bytes(cls, data: bytes) -> HighScoreRecord:
        if len(data) != RECORD_SIZE:
            raise ValueError(f"expected {RECORD_SIZE:#x} bytes, got {len(data):#x}")
        return cls(data=bytearray(data))

    def copy(self) -> HighScoreRecord:
        return HighScoreRecord(data=bytearray(self.data))

    def name(self) -> str:
        raw = bytes(self.data[:NAME_SIZE])
        return raw.split(b"\x00", 1)[0].decode("latin-1", errors="ignore")

    def set_name(self, value: str) -> None:
        encoded = value.encode("latin-1", errors="ignore")[: NAME_SIZE - 1]
        self.data[:NAME_SIZE] = b"\x00" * NAME_SIZE
        self.data[: len(encoded)] = encoded
        self.data[min(len(encoded), NAME_SIZE - 1)] = 0

    def trim_trailing_spaces(self) -> None:
        # highscore_save_record: strips trailing spaces (0x20) in-place before saving.
        raw = self.data[:NAME_SIZE]
        end = raw.find(0)
        if end < 0:
            end = NAME_SIZE
        i = end - 1
        while i > 0 and raw[i] == 0x20:
            self.data[i] = 0
            i -= 1

    @property
    def survival_elapsed_ms(self) -> int:
        return int(struct.unpack_from("<i", self.data, 0x20)[0])

    @survival_elapsed_ms.setter
    def survival_elapsed_ms(self, value: int) -> None:
        struct.pack_into("<I", self.data, 0x20, int(value) & 0xFFFFFFFF)

    @property
    def score_xp(self) -> int:
        return int(struct.unpack_from("<I", self.data, 0x24)[0])

    @score_xp.setter
    def score_xp(self, value: int) -> None:
        struct.pack_into("<I", self.data, 0x24, int(value) & 0xFFFFFFFF)

    @property
    def game_mode_id(self) -> GameMode:
        return _known_game_mode(int(self.data[0x28]))

    @game_mode_id.setter
    def game_mode_id(self, value: GameMode) -> None:
        self.data[0x28] = int(value) & 0xFF

    @property
    def quest_stage_major(self) -> int:
        return int(self.data[0x29])

    @quest_stage_major.setter
    def quest_stage_major(self, value: int) -> None:
        self.data[0x29] = int(value) & 0xFF

    @property
    def quest_stage_minor(self) -> int:
        return int(self.data[0x2A])

    @quest_stage_minor.setter
    def quest_stage_minor(self, value: int) -> None:
        self.data[0x2A] = int(value) & 0xFF

    @property
    def quest_level(self) -> QuestLevel | None:
        major = int(self.quest_stage_major)
        minor = int(self.quest_stage_minor)
        if major <= 0 or minor <= 0:
            return None
        return QuestLevel(major, minor)

    @quest_level.setter
    def quest_level(self, value: QuestLevel | None) -> None:
        if value is None:
            self.quest_stage_major = 0
            self.quest_stage_minor = 0
            return
        self.quest_stage_major = int(value.major)
        self.quest_stage_minor = int(value.minor)

    @property
    def most_used_weapon_id(self) -> WeaponId:
        return WeaponId(int(self.data[0x2B]))

    @most_used_weapon_id.setter
    def most_used_weapon_id(self, value: WeaponId) -> None:
        self.data[0x2B] = int(WeaponId(value)) & 0xFF

    @property
    def shots_fired(self) -> int:
        return int(struct.unpack_from("<I", self.data, 0x2C)[0])

    @shots_fired.setter
    def shots_fired(self, value: int) -> None:
        struct.pack_into("<I", self.data, 0x2C, int(value) & 0xFFFFFFFF)

    @property
    def shots_hit(self) -> int:
        return int(struct.unpack_from("<I", self.data, 0x30)[0])

    @shots_hit.setter
    def shots_hit(self, value: int) -> None:
        struct.pack_into("<I", self.data, 0x30, int(value) & 0xFFFFFFFF)

    @property
    def creature_kill_count(self) -> int:
        return int(struct.unpack_from("<I", self.data, 0x34)[0])

    @creature_kill_count.setter
    def creature_kill_count(self, value: int) -> None:
        struct.pack_into("<I", self.data, 0x34, int(value) & 0xFFFFFFFF)

    @property
    def uni_num(self) -> int:
        return int(struct.unpack_from("<I", self.data, 0x38)[0])

    @uni_num.setter
    def uni_num(self, value: int) -> None:
        struct.pack_into("<I", self.data, 0x38, int(value) & 0xFFFFFFFF)

    @property
    def reserved(self) -> int:
        return int(struct.unpack_from("<I", self.data, 0x3C)[0])

    @reserved.setter
    def reserved(self, value: int) -> None:
        struct.pack_into("<I", self.data, 0x3C, int(value) & 0xFFFFFFFF)

    @property
    def day(self) -> int:
        return int(self.data[0x40])

    @property
    def date_week(self) -> int:
        return int(self.data[0x41])

    @date_week.setter
    def date_week(self, value: int) -> None:
        self.data[0x41] = int(value) & 0xFF

    @property
    def month(self) -> int:
        return int(self.data[0x42])

    @property
    def year_offset(self) -> int:
        return int(self.data[0x43])

    @property
    def flags(self) -> int:
        return int(self.data[0x44])

    @flags.setter
    def flags(self, value: int) -> None:
        self.data[0x44] = int(value) & 0xFF

    @property
    def hardcore_marker(self) -> int:
        return int(self.data[0x45])

    @hardcore_marker.setter
    def hardcore_marker(self, value: int) -> None:
        self.data[0x45] = int(value) & 0xFF

    def ensure_date_fields(self, now: dt.date | None = None) -> None:
        if int(self.data[0x40]) != 0:
            return
        if now is None:
            now = dt.datetime.now(tz=dt.UTC).astimezone().date()
        self.data[0x40] = int(now.day) & 0xFF
        self.data[0x42] = int(now.month) & 0xFF
        self.data[0x43] = int(now.year - 2000) & 0xFF
        self.date_week = highscore_date_week(now.year, now.month, now.day)


def scores_dir_for_base_dir(base_dir: Path) -> Path:
    # Original uses CreateDirectoryA("scores5") relative to cwd.
    return base_dir / "scores5"


def _with_player_count_suffix(path: Path, *, player_count: int) -> Path:
    count = int(player_count)
    if count <= 1:
        return path
    # Native only supports 1P/2P. Our port supports up to 4 players; keep separate leaderboards.
    count = max(2, min(4, count))
    if path.suffix.lower() != ".hi":
        return path
    return path.with_name(f"{path.stem}_{count}{path.suffix}")


def _scores_path_for_mode_root(
    *,
    root: Path,
    game_mode_id: GameMode,
    hardcore: bool,
    quest_stage_major: int,
    quest_stage_minor: int,
) -> Path:
    mode = _known_game_mode(int(game_mode_id))
    match mode:
        case GameMode.SURVIVAL:
            return root / "survival.hi"
        case GameMode.RUSH:
            return root / "rush.hi"
        case GameMode.TYPO:
            return root / "typo.hi"
        case GameMode.QUESTS:
            # Native `highscore_build_path` uses `questhc*.hi` when hardcore is OFF,
            # and `quest*.hi` when hardcore is ON.
            prefix = "quest" if bool(hardcore) else "questhc"
            major = int(quest_stage_major)
            minor = int(quest_stage_minor)
            return root / f"{prefix}{major}_{minor}.hi"
        case _:
            return root / "unknown.hi"


def scores_path_for_mode(
    base_dir: Path,
    game_mode_id: GameMode,
    *,
    hardcore: bool = False,
    quest_stage_major: int = 0,
    quest_stage_minor: int = 0,
    player_count: int = 1,
) -> Path:
    root = scores_dir_for_base_dir(base_dir)
    path = _scores_path_for_mode_root(
        root=root,
        game_mode_id=game_mode_id,
        hardcore=bool(hardcore),
        quest_stage_major=int(quest_stage_major),
        quest_stage_minor=int(quest_stage_minor),
    )
    return _with_player_count_suffix(path, player_count=int(player_count))


def scores_path_for_config(
    base_dir: Path,
    config: CrimsonConfig,
    *,
    quest_stage_major: int = 0,
    quest_stage_minor: int = 0,
) -> Path:
    mode = _known_game_mode(config.gameplay.mode)
    root = scores_dir_for_base_dir(base_dir)
    match mode:
        case GameMode.QUESTS:
            hardcore = config.gameplay.hardcore
            if int(quest_stage_major) == 0 and int(quest_stage_minor) == 0:
                level = config.gameplay.quest_level
                if level is not None:
                    quest_stage_major = int(level.major)
                    quest_stage_minor = int(level.minor)
            path = _scores_path_for_mode_root(
                root=root,
                game_mode_id=mode,
                hardcore=bool(hardcore),
                quest_stage_major=int(quest_stage_major),
                quest_stage_minor=int(quest_stage_minor),
            )
        case _:
            path = _scores_path_for_mode_root(
                root=root,
                game_mode_id=mode,
                hardcore=config.gameplay.hardcore,
                quest_stage_major=int(quest_stage_major),
                quest_stage_minor=int(quest_stage_minor),
            )

    return _with_player_count_suffix(path, player_count=config.gameplay.player_count)


def decode_record_payload(encoded: bytes) -> bytes:
    if len(encoded) != RECORD_SIZE:
        raise ValueError(f"expected {RECORD_SIZE:#x} bytes, got {len(encoded):#x}")
    out = bytearray(encoded)
    for idx in range(RECORD_SIZE):
        out[idx] = _decode_byte(out[idx], idx)
    return bytes(out)


def encode_record_payload(decoded: bytes) -> bytes:
    if len(decoded) != RECORD_SIZE:
        raise ValueError(f"expected {RECORD_SIZE:#x} bytes, got {len(decoded):#x}")
    out = bytearray(decoded)
    for idx in range(RECORD_SIZE):
        out[idx] = _encode_byte(out[idx], idx)
    return bytes(out)


def read_highscore_records(path: Path) -> list[HighScoreRecord]:
    if not path.is_file():
        return []
    records: list[HighScoreRecord] = []
    with path.open("rb") as fp:
        while True:
            blob = fp.read(RECORD_WIRE_SIZE)
            if not blob:
                break
            if len(blob) != RECORD_WIRE_SIZE:
                break
            payload = blob[:RECORD_SIZE]
            stored_checksum = int(struct.unpack_from("<I", blob, RECORD_SIZE)[0])
            decoded = decode_record_payload(payload)
            computed = _score_checksum(decoded)
            if computed != stored_checksum:
                continue
            records.append(HighScoreRecord.from_bytes(decoded))
    return records


def write_highscore_records(path: Path, records: list[HighScoreRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = bytearray()
    for record in records:
        record = record.copy()
        record.trim_trailing_spaces()
        record.ensure_date_fields()
        encoded = encode_record_payload(bytes(record.data))
        checksum = _score_checksum(bytes(record.data))
        payload.extend(encoded)
        payload.extend(struct.pack("<I", checksum))
    atomic_write_bytes(path, bytes(payload))


def _passes_date_filter(entry: HighScoreRecord, date_mode: HighScoreDateMode, now: dt.date) -> bool:
    if date_mode == HighScoreDateMode.ALL_TIME:
        return True
    if entry.day == 0 or entry.month == 0 or 2000 + entry.year_offset != now.year:
        return False
    match date_mode:
        case HighScoreDateMode.MONTH:
            return entry.month == now.month
        case HighScoreDateMode.WEEK:
            return entry.date_week == highscore_date_week(now.year, now.month, now.day)
        case HighScoreDateMode.DAY:
            return entry.day == now.day and entry.month == now.month
    return False


def _select_highscore_table(
    records: list[HighScoreRecord], *, game_mode_id: GameMode, date_mode: HighScoreDateMode, now: dt.date,
) -> list[HighScoreRecord]:
    eligible = [r for r in records if r.game_mode_id == game_mode_id and _passes_date_filter(r, date_mode, now)]
    return sort_highscores(eligible, game_mode_id=game_mode_id)[:TABLE_MAX]


def read_highscore_table(
    path: Path, *, game_mode_id: GameMode, date_mode: HighScoreDateMode = HighScoreDateMode.ALL_TIME,
    now: dt.date | None = None,
) -> list[HighScoreRecord]:
    return _select_highscore_table(
        read_highscore_records(path), game_mode_id=game_mode_id, date_mode=date_mode,
        now=now or dt.datetime.now(tz=dt.UTC).astimezone().date(),
    )


def _score_key(record: HighScoreRecord, game_mode_id: GameMode) -> tuple[bool, int]:
    # Native comparators interpret both wire fields as signed ints. Quest bonuses
    # can legitimately produce a negative final time; zero is an empty entry.
    offset = 0x20 if game_mode_id in (GameMode.RUSH, GameMode.QUESTS) else 0x24
    value = struct.unpack_from("<i", record.data, offset)[0]
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
    path: Path, record: HighScoreRecord, *, date_mode: HighScoreDateMode = HighScoreDateMode.ALL_TIME,
    now: dt.date | None = None,
) -> tuple[list[HighScoreRecord], int]:
    """Save a qualifying score without discarding history outside the displayed table."""
    now = now or dt.datetime.now(tz=dt.UTC).astimezone().date()
    history = read_highscore_records(path)
    table = _select_highscore_table(history, game_mode_id=record.game_mode_id, date_mode=date_mode, now=now)
    idx = rank_index(table, record)
    if idx >= TABLE_MAX:
        return table, idx
    candidate = record.copy()
    candidate.trim_trailing_spaces()
    candidate.ensure_date_fields(now)
    history.append(candidate)
    write_highscore_records(path, history)
    table.insert(idx, candidate)
    return table[:TABLE_MAX], idx
