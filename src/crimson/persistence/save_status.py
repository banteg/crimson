from __future__ import annotations

from pathlib import Path
from typing import Annotated, Final

import msgspec
from construct import Array, Bytes, Int16ul, Int32ul, Struct

from grim.atomic_write import atomic_write_bytes

from ..game_modes import GameMode
from ..weapon_usage import (
    WEAPON_USAGE_SLOT_COUNT,
    ZERO_WEAPON_USAGE_COUNTS,
    WeaponUsageCounts,
    weapon_usage_slot_for_weapon_id,
)

GAME_CFG_NAME = "game.cfg"

BLOB_SIZE = 0x268
FILE_SIZE = BLOB_SIZE + 4

WEAPON_USAGE_COUNT = WEAPON_USAGE_SLOT_COUNT

# Quest play count length inferred from known trailing fields in the blob (0xD8..0x244).
QUEST_PLAY_COUNT = 91

RESERVED_SEED_WORDS_BYTE_SIZE = 0x10

type QuestPlayCounts = Annotated[
    tuple[int, ...],
    msgspec.Meta(min_length=QUEST_PLAY_COUNT, max_length=QUEST_PLAY_COUNT),
]

_ZERO_QUEST_PLAY_COUNTS: Final[QuestPlayCounts] = tuple(0 for _ in range(QUEST_PLAY_COUNT))
_ZERO_RESERVED_SEED_WORDS: Final[bytes] = b"\x00" * RESERVED_SEED_WORDS_BYTE_SIZE
_STATUS_FIELD_NAMES: Final[frozenset[str]] = frozenset(
    {
        "quest_unlock_index",
        "quest_unlock_index_full",
        "weapon_usage_counts",
        "quest_play_counts",
        "mode_play_survival",
        "mode_play_rush",
        "mode_play_typo",
        "mode_play_other",
        "play_time_ms",
        "reserved_seed_words",
    },
)

GAME_STATUS_STRUCT = Struct(
    "quest_unlock_index" / Int16ul,
    "quest_unlock_index_full" / Int16ul,
    "weapon_usage_counts" / Array(WEAPON_USAGE_COUNT, Int32ul),
    "quest_play_counts" / Array(QUEST_PLAY_COUNT, Int32ul),
    "mode_play_survival" / Int32ul,
    "mode_play_rush" / Int32ul,
    "mode_play_typo" / Int32ul,
    "mode_play_other" / Int32ul,
    "play_time_ms" / Int32ul,
    "reserved_seed_words" / Bytes(RESERVED_SEED_WORDS_BYTE_SIZE),
)

GAME_CFG_STRUCT = Struct(
    "encoded" / Bytes(BLOB_SIZE),
    "checksum" / Int32ul,
)


class GameStatusData(msgspec.Struct, forbid_unknown_fields=True):
    quest_unlock_index: int = 0
    quest_unlock_index_full: int = 0
    weapon_usage_counts: WeaponUsageCounts = msgspec.field(default_factory=lambda: ZERO_WEAPON_USAGE_COUNTS)
    quest_play_counts: QuestPlayCounts = msgspec.field(default_factory=lambda: _ZERO_QUEST_PLAY_COUNTS)
    mode_play_survival: int = 0
    mode_play_rush: int = 0
    mode_play_typo: int = 0
    mode_play_other: int = 0
    play_time_ms: int = 0
    reserved_seed_words: bytes = _ZERO_RESERVED_SEED_WORDS


class GameStatus(GameStatusData, kw_only=True):
    path: Path
    dirty: bool = False

    def __setattr__(self, name: str, value: object) -> None:
        mark_dirty = name in _STATUS_FIELD_NAMES
        current = _MISSING
        if mark_dirty:
            try:
                current = object.__getattribute__(self, name)
            except AttributeError:
                pass
        super().__setattr__(name, value)
        if mark_dirty and current is not _MISSING and current != value:
            super().__setattr__("dirty", True)

    @classmethod
    def from_data(cls, *, path: Path, data: GameStatusData, dirty: bool = False) -> GameStatus:
        return cls(
            path=path,
            dirty=dirty,
            quest_unlock_index=data.quest_unlock_index,
            quest_unlock_index_full=data.quest_unlock_index_full,
            weapon_usage_counts=tuple(data.weapon_usage_counts),
            quest_play_counts=tuple(data.quest_play_counts),
            mode_play_survival=data.mode_play_survival,
            mode_play_rush=data.mode_play_rush,
            mode_play_typo=data.mode_play_typo,
            mode_play_other=data.mode_play_other,
            play_time_ms=data.play_time_ms,
            reserved_seed_words=bytes(data.reserved_seed_words),
        )

    def as_data(self) -> GameStatusData:
        return GameStatusData(
            quest_unlock_index=self.quest_unlock_index,
            quest_unlock_index_full=self.quest_unlock_index_full,
            weapon_usage_counts=tuple(self.weapon_usage_counts),
            quest_play_counts=tuple(self.quest_play_counts),
            mode_play_survival=self.mode_play_survival,
            mode_play_rush=self.mode_play_rush,
            mode_play_typo=self.mode_play_typo,
            mode_play_other=self.mode_play_other,
            play_time_ms=self.play_time_ms,
            reserved_seed_words=bytes(self.reserved_seed_words),
        )

    def mode_play_count_for_mode(self, game_mode: GameMode) -> int:
        return getattr(self, _mode_count_field_for_mode(game_mode))

    def increment_mode_play_count_for_mode(self, game_mode: GameMode, delta: int = 1) -> int:
        field = _mode_count_field_for_mode(game_mode)
        value = (getattr(self, field) + int(delta)) & 0xFFFFFFFF
        setattr(self, field, value)
        return value

    def weapon_usage_count_slot(self, slot: int) -> int:
        slot_idx = _require_index(slot, size=WEAPON_USAGE_COUNT, field="weapon_usage_slot")
        return int(self.weapon_usage_counts[slot_idx])

    def increment_weapon_usage_slot(self, slot: int, delta: int = 1) -> int:
        slot_idx = _require_index(slot, size=WEAPON_USAGE_COUNT, field="weapon_usage_slot")
        counts = list(self.weapon_usage_counts)
        counts[slot_idx] = (counts[slot_idx] + int(delta)) & 0xFFFFFFFF
        self.weapon_usage_counts = tuple(counts)
        return counts[slot_idx]

    def weapon_usage_count_for_weapon_id(self, weapon_id: int) -> int:
        slot = weapon_usage_slot_for_weapon_id(weapon_id)
        if slot is None:
            return 0
        return self.weapon_usage_count_slot(slot)

    def increment_weapon_usage_for_weapon_id(self, weapon_id: int, delta: int = 1) -> int | None:
        slot = weapon_usage_slot_for_weapon_id(weapon_id)
        if slot is None:
            return None
        return self.increment_weapon_usage_slot(slot, delta=delta)

    def quest_play_count(self, index: int) -> int:
        quest_idx = _require_index(index, size=QUEST_PLAY_COUNT, field="quest_play_count")
        return int(self.quest_play_counts[quest_idx])

    def increment_quest_play_count(self, index: int, delta: int = 1) -> int:
        quest_idx = _require_index(index, size=QUEST_PLAY_COUNT, field="quest_play_count")
        counts = list(self.quest_play_counts)
        counts[quest_idx] = (counts[quest_idx] + int(delta)) & 0xFFFFFFFF
        self.quest_play_counts = tuple(counts)
        return counts[quest_idx]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        save_status(self.path, self)
        self.dirty = False

    def save_if_dirty(self) -> None:
        if self.dirty:
            self.save()


class _Missing:
    pass


_MISSING: Final = _Missing()


def _mode_count_field_for_mode(game_mode: GameMode) -> str:
    mode = game_mode if isinstance(game_mode, GameMode) else GameMode(int(game_mode))
    match mode:
        case GameMode.SURVIVAL:
            return "mode_play_survival"
        case GameMode.RUSH:
            return "mode_play_rush"
        case GameMode.TYPO:
            return "mode_play_typo"
        case _:
            return "mode_play_other"


def _require_index(index: int, *, size: int, field: str) -> int:
    idx = int(index)
    if 0 <= idx < int(size):
        return idx
    raise IndexError(f"{field} out of range: {idx}")


def _status_blob_dict(data: GameStatusData) -> dict[str, object]:
    return {
        "quest_unlock_index": data.quest_unlock_index,
        "quest_unlock_index_full": data.quest_unlock_index_full,
        "weapon_usage_counts": list(data.weapon_usage_counts),
        "quest_play_counts": list(data.quest_play_counts),
        "mode_play_survival": data.mode_play_survival,
        "mode_play_rush": data.mode_play_rush,
        "mode_play_typo": data.mode_play_typo,
        "mode_play_other": data.mode_play_other,
        "play_time_ms": data.play_time_ms,
        "reserved_seed_words": bytes(data.reserved_seed_words),
    }


def default_status_data() -> GameStatusData:
    return GameStatusData()


def parse_status_blob(decoded: bytes) -> GameStatusData:
    if len(decoded) != BLOB_SIZE:
        raise ValueError(f"expected decoded blob of {BLOB_SIZE:#x} bytes, got {len(decoded):#x}")
    raw = GAME_STATUS_STRUCT.parse(decoded)
    return GameStatusData(
        quest_unlock_index=int(raw["quest_unlock_index"]),
        quest_unlock_index_full=int(raw["quest_unlock_index_full"]),
        weapon_usage_counts=tuple(int(value) for value in raw["weapon_usage_counts"]),
        quest_play_counts=tuple(int(value) for value in raw["quest_play_counts"]),
        mode_play_survival=int(raw["mode_play_survival"]),
        mode_play_rush=int(raw["mode_play_rush"]),
        mode_play_typo=int(raw["mode_play_typo"]),
        mode_play_other=int(raw["mode_play_other"]),
        play_time_ms=int(raw["play_time_ms"]),
        reserved_seed_words=bytes(raw["reserved_seed_words"]),
    )


def build_status_blob(data: GameStatusData) -> bytes:
    return GAME_STATUS_STRUCT.build(_status_blob_dict(data))


def to_s8(value: int) -> int:
    value &= 0xFF
    return value - 0x100 if value & 0x80 else value


def index_poly(idx: int) -> int:
    i = to_s8(idx)
    return ((i * 7 + 0x0F) * i + 0x03) * i


def decode_blob(encoded: bytes) -> bytes:
    if len(encoded) != BLOB_SIZE:
        raise ValueError(f"decoded blob must be {BLOB_SIZE:#x} bytes, got {len(encoded):#x}")
    decoded = bytearray(encoded)
    for i in range(BLOB_SIZE):
        decoded[i] = (decoded[i] - 0x6F - index_poly(i)) & 0xFF
    return bytes(decoded)


def encode_blob(decoded: bytes) -> bytes:
    if len(decoded) != BLOB_SIZE:
        raise ValueError(f"decoded blob must be {BLOB_SIZE:#x} bytes, got {len(decoded):#x}")
    encoded = bytearray(decoded)
    for i in range(BLOB_SIZE):
        encoded[i] = (encoded[i] + 0x6F + index_poly(i)) & 0xFF
    return bytes(encoded)


def compute_checksum(decoded: bytes) -> int:
    acc = 0
    u = 0
    for i, b in enumerate(decoded):
        c = to_s8(b)
        i_var5 = (c * 7 + i) * c + u
        acc = (acc + 0x0D + i_var5) & 0xFFFFFFFF
        u += 0x6F
    return acc


def load_status(path: Path) -> GameStatus:
    raw = path.read_bytes()
    if len(raw) != FILE_SIZE:
        raise ValueError(f"expected {FILE_SIZE:#x} bytes, got {len(raw):#x}")
    parsed = GAME_CFG_STRUCT.parse(raw)
    encoded = bytes(parsed["encoded"])
    stored_checksum = int(parsed["checksum"])
    decoded = decode_blob(encoded)
    computed = compute_checksum(decoded)
    if stored_checksum != computed:
        raise ValueError("checksum mismatch")
    return GameStatus.from_data(path=path, data=parse_status_blob(decoded), dirty=False)


def save_status(path: Path, status: GameStatusData | GameStatus) -> None:
    decoded = build_status_blob(status.as_data() if isinstance(status, GameStatus) else status)
    checksum = compute_checksum(decoded)
    encoded = encode_blob(decoded)
    atomic_write_bytes(path, GAME_CFG_STRUCT.build({"encoded": encoded, "checksum": checksum}))


def ensure_game_status(base_dir: Path) -> GameStatus:
    path = base_dir / GAME_CFG_NAME
    if path.exists():
        return load_status(path)
    status = GameStatus.from_data(path=path, data=default_status_data(), dirty=False)
    status.save()
    return status


def hash_status_data(status: GameStatusData) -> str:
    import hashlib

    return hashlib.sha256(build_status_blob(status)).hexdigest()


__all__ = [
    "BLOB_SIZE",
    "FILE_SIZE",
    "GAME_CFG_NAME",
    "GAME_CFG_STRUCT",
    "GAME_STATUS_STRUCT",
    "QUEST_PLAY_COUNT",
    "RESERVED_SEED_WORDS_BYTE_SIZE",
    "WEAPON_USAGE_COUNT",
    "GameStatus",
    "GameStatusData",
    "QuestPlayCounts",
    "build_status_blob",
    "compute_checksum",
    "decode_blob",
    "default_status_data",
    "encode_blob",
    "ensure_game_status",
    "hash_status_data",
    "load_status",
    "parse_status_blob",
    "save_status",
]
