from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
from pathlib import Path
import struct

from grim.config import CrimsonConfig


RECORD_SIZE = 0x48
RECORD_WIRE_SIZE = RECORD_SIZE + 4  # record + checksum
TABLE_MAX = 100

NAME_SIZE = 0x20
NAME_MAX_EDIT = 0x14  # game_over_screen_update sets ui_text_input maxlen=0x14


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


def highscore_date_checksum(year: int, month: int, day: int) -> int:
    """Port of `highscore_date_checksum` (0x0043a950)."""
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


@dataclass(slots=True)
class HighScoreRecord:
    data: bytearray

    @classmethod
    def blank(cls) -> HighScoreRecord:
        data = bytearray(RECORD_SIZE)
        data[0x46] = 0x7C
        data[0x47] = 0xFF
        return cls(data=data)

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
            raw[i] = 0
            i -= 1

    @property
    def survival_elapsed_ms(self) -> int:
        return int(struct.unpack_from("<I", self.data, 0x20)[0])

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
    def game_mode_id(self) -> int:
        return int(self.data[0x28])

    @game_mode_id.setter
    def game_mode_id(self, value: int) -> None:
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
    def most_used_weapon_id(self) -> int:
        return int(self.data[0x2B])

    @most_used_weapon_id.setter
    def most_used_weapon_id(self, value: int) -> None:
        self.data[0x2B] = int(value) & 0xFF

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
    def reserved0(self) -> int:
        return int(struct.unpack_from("<I", self.data, 0x38)[0])

    @reserved0.setter
    def reserved0(self, value: int) -> None:
        struct.pack_into("<I", self.data, 0x38, int(value) & 0xFFFFFFFF)

    @property
    def day(self) -> int:
        return int(self.data[0x40])

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
    def full_version_marker(self) -> int:
        return int(self.data[0x45])

    @full_version_marker.setter
    def full_version_marker(self, value: int) -> None:
        self.data[0x45] = int(value) & 0xFF

    def ensure_date_fields(self, now: dt.date | None = None) -> None:
        if int(self.data[0x40]) != 0:
            return
        if now is None:
            now = dt.date.today()
        self.data[0x40] = int(now.day) & 0xFF
        self.data[0x42] = int(now.month) & 0xFF
        self.data[0x43] = int(now.year - 2000) & 0xFF
        self.data[0x41] = int(highscore_date_checksum(now.year, now.month, now.day)) & 0xFF


def scores_dir_for_base_dir(base_dir: Path) -> Path:
    # Original uses CreateDirectoryA("scores5") relative to cwd.
    return base_dir / "scores5"


def _maybe_migrate_alt_quest_scores_file(path: Path, alt: Path) -> None:
    """Copy an alternate quest score file into the expected naming scheme (once).

    The classic game uses the underscore format (e.g. questhc1_1.hi). Some ports used
    zero-padded numbers without separators (e.g. questhc0101.hi).
    """

    if path.is_file():
        return
    if not alt.is_file():
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(alt.read_bytes())
    except Exception:
        return


def scores_path_for_mode(
    base_dir: Path,
    game_mode_id: int,
    *,
    hardcore: bool = False,
    quest_stage_major: int = 0,
    quest_stage_minor: int = 0,
) -> Path:
    root = scores_dir_for_base_dir(base_dir)
    mode = int(game_mode_id)
    if mode == 1:
        return root / "survival.hi"
    if mode == 2:
        return root / "rush.hi"
    if mode == 4:
        return root / "typo.hi"
    if mode == 3:
        # Native `highscore_build_path` uses `questhc*.hi` when hardcore is OFF,
        # and `quest*.hi` when hardcore is ON.
        prefix = "quest" if hardcore else "questhc"
        major = int(quest_stage_major)
        minor = int(quest_stage_minor)
        path = root / f"{prefix}{major}_{minor}.hi"
        alt = root / f"{prefix}{major:02d}{minor:02d}.hi"
        _maybe_migrate_alt_quest_scores_file(path, alt)
        return path
    return root / "unknown.hi"


def scores_path_for_config(base_dir: Path, config: CrimsonConfig, *, quest_stage_major: int = 0, quest_stage_minor: int = 0) -> Path:
    mode = int(config.data.get("game_mode", 1))
    root = scores_dir_for_base_dir(base_dir)
    if mode == 1:
        return root / "survival.hi"
    if mode == 2:
        return root / "rush.hi"
    if mode == 4:
        return root / "typo.hi"
    if mode == 3:
        hardcore = bool(int(config.data.get("hardcore_flag", 0) or 0))
        if int(quest_stage_major) == 0 and int(quest_stage_minor) == 0:
            major = int(config.data.get("quest_stage_major", 0) or 0)
            minor = int(config.data.get("quest_stage_minor", 0) or 0)
            if major == 0 and minor == 0:
                level = config.data.get("quest_level")
                if isinstance(level, str):
                    try:
                        major_text, minor_text = level.split(".", 1)
                        major = int(major_text)
                        minor = int(minor_text)
                    except Exception:
                        major = 0
                        minor = 0
            quest_stage_major = major
            quest_stage_minor = minor
        # Native `highscore_build_path` uses `questhc*.hi` when hardcore is OFF,
        # and `quest*.hi` when hardcore is ON.
        prefix = "quest" if hardcore else "questhc"
        major = int(quest_stage_major)
        minor = int(quest_stage_minor)
        path = root / f"{prefix}{major}_{minor}.hi"
        alt = root / f"{prefix}{major:02d}{minor:02d}.hi"
        _maybe_migrate_alt_quest_scores_file(path, alt)
        return path
    return root / "unknown.hi"


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
    with path.open("wb") as fp:
        for record in records:
            record = record.copy()
            record.trim_trailing_spaces()
            record.ensure_date_fields()
            encoded = encode_record_payload(bytes(record.data))
            checksum = _score_checksum(bytes(record.data))
            fp.write(encoded)
            fp.write(struct.pack("<I", checksum))


def read_highscore_table(path: Path, *, game_mode_id: int) -> list[HighScoreRecord]:
    records = read_highscore_records(path)
    records = [r for r in records if int(r.game_mode_id) == int(game_mode_id)]
    return sort_highscores(records, game_mode_id=game_mode_id)[:TABLE_MAX]


def sort_highscores(records: list[HighScoreRecord], *, game_mode_id: int) -> list[HighScoreRecord]:
    mode = int(game_mode_id)
    if mode == 2:
        return sorted(records, key=lambda r: int(r.survival_elapsed_ms), reverse=True)
    if mode == 3:
        def _quest_key(r: HighScoreRecord) -> tuple[int, int]:
            value = int(r.survival_elapsed_ms)
            if value == 0:
                return (1, 0)
            return (0, value)
        return sorted(records, key=_quest_key)
    return sorted(records, key=lambda r: int(r.score_xp), reverse=True)


def rank_index(records_sorted: list[HighScoreRecord], record: HighScoreRecord) -> int:
    mode = int(record.game_mode_id)
    if mode == 2:
        score = int(record.survival_elapsed_ms)
        for idx, entry in enumerate(records_sorted):
            if score > int(entry.survival_elapsed_ms):
                return idx
        return len(records_sorted)
    if mode == 3:
        score = int(record.survival_elapsed_ms)
        for idx, entry in enumerate(records_sorted):
            other = int(entry.survival_elapsed_ms)
            if other == 0:
                return idx
            if score < other:
                return idx
        return len(records_sorted)
    score = int(record.score_xp)
    for idx, entry in enumerate(records_sorted):
        if score > int(entry.score_xp):
            return idx
    return len(records_sorted)


def upsert_highscore_record(path: Path, record: HighScoreRecord) -> tuple[list[HighScoreRecord], int]:
    """Save `record` into the mode table, returning (sorted_records, rank_index)."""
    records_sorted = read_highscore_table(path, game_mode_id=record.game_mode_id)
    idx = rank_index(records_sorted, record)
    if idx >= TABLE_MAX:
        return records_sorted, idx
    updated = list(records_sorted)
    updated.insert(idx, record.copy())
    updated = updated[:TABLE_MAX]
    write_highscore_records(path, updated)
    return updated, idx
