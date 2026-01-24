from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from construct import Array, Bytes, Int16ul, Int32ul, Struct

GAME_CFG_NAME = "game.cfg"

BLOB_SIZE = 0x268
FILE_SIZE = BLOB_SIZE + 4

WEAPON_USAGE_COUNT = 53

# Quest play count length inferred from known trailing fields in the blob (0xD8..0x244).
QUEST_PLAY_COUNT = 91

MODE_COUNT_ORDER = (
    ("survival", "mode_play_survival"),
    ("rush", "mode_play_rush"),
    ("typo", "mode_play_typo"),
    ("other", "mode_play_other"),
)

UNKNOWN_TAIL_SIZE = 0x10

GAME_STATUS_STRUCT = Struct(
    "quest_unlock_index" / Int16ul,
    "quest_unlock_index_full" / Int16ul,
    "weapon_usage_counts" / Array(WEAPON_USAGE_COUNT, Int32ul),
    "quest_play_counts" / Array(QUEST_PLAY_COUNT, Int32ul),
    "mode_play_survival" / Int32ul,
    "mode_play_rush" / Int32ul,
    "mode_play_typo" / Int32ul,
    "mode_play_other" / Int32ul,
    "game_sequence_id" / Int32ul,
    "unknown_tail" / Bytes(UNKNOWN_TAIL_SIZE),
)

GAME_CFG_STRUCT = Struct(
    "encoded" / Bytes(BLOB_SIZE),
    "checksum" / Int32ul,
)


@dataclass(slots=True)
class StatusBlob:
    decoded: bytes
    checksum: int
    checksum_expected: int

    @property
    def checksum_valid(self) -> bool:
        return (self.checksum & 0xFFFFFFFF) == (self.checksum_expected & 0xFFFFFFFF)


@dataclass(slots=True)
class GameStatus:
    path: Path
    data: dict
    dirty: bool = False

    @property
    def quest_unlock_index(self) -> int:
        return int(self.data["quest_unlock_index"])

    @quest_unlock_index.setter
    def quest_unlock_index(self, value: int) -> None:
        self.data["quest_unlock_index"] = int(value) & 0xFFFF
        self.dirty = True

    @property
    def quest_unlock_index_full(self) -> int:
        return int(self.data["quest_unlock_index_full"])

    @quest_unlock_index_full.setter
    def quest_unlock_index_full(self, value: int) -> None:
        self.data["quest_unlock_index_full"] = int(value) & 0xFFFF
        self.dirty = True

    @property
    def game_sequence_id(self) -> int:
        return int(self.data["game_sequence_id"])

    @game_sequence_id.setter
    def game_sequence_id(self, value: int) -> None:
        self.data["game_sequence_id"] = int(value) & 0xFFFFFFFF
        self.dirty = True

    def mode_play_count(self, name: str) -> int:
        for mode_name, field in MODE_COUNT_ORDER:
            if mode_name == name:
                return int(self.data[field])
        raise KeyError(f"unknown mode: {name}")

    def increment_mode_play_count(self, name: str, delta: int = 1) -> int:
        for mode_name, field in MODE_COUNT_ORDER:
            if mode_name == name:
                value = (int(self.data[field]) + int(delta)) & 0xFFFFFFFF
                self.data[field] = value
                self.dirty = True
                return value
        raise KeyError(f"unknown mode: {name}")

    def weapon_usage_count(self, weapon_id: int) -> int:
        weapon_id = int(weapon_id)
        if not (0 <= weapon_id < WEAPON_USAGE_COUNT):
            raise IndexError(f"weapon_id out of range: {weapon_id}")
        return int(self.data["weapon_usage_counts"][weapon_id])

    def increment_weapon_usage(self, weapon_id: int, delta: int = 1) -> int:
        weapon_id = int(weapon_id)
        if not (0 <= weapon_id < WEAPON_USAGE_COUNT):
            raise IndexError(f"weapon_id out of range: {weapon_id}")
        counts = self.data["weapon_usage_counts"]
        value = (int(counts[weapon_id]) + int(delta)) & 0xFFFFFFFF
        counts[weapon_id] = value
        self.dirty = True
        return value

    def quest_play_count(self, index: int) -> int:
        index = int(index)
        if not (0 <= index < QUEST_PLAY_COUNT):
            raise IndexError(f"quest index out of range: {index}")
        return int(self.data["quest_play_counts"][index])

    def increment_quest_play_count(self, index: int, delta: int = 1) -> int:
        index = int(index)
        if not (0 <= index < QUEST_PLAY_COUNT):
            raise IndexError(f"quest index out of range: {index}")
        counts = self.data["quest_play_counts"]
        value = (int(counts[index]) + int(delta)) & 0xFFFFFFFF
        counts[index] = value
        self.dirty = True
        return value

    def unknown_tail(self) -> bytes:
        return bytes(self.data["unknown_tail"])

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        decoded = build_status_blob(self.data)
        save_status(self.path, decoded)
        self.dirty = False

    def save_if_dirty(self) -> None:
        if self.dirty:
            self.save()


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


def load_status(path: Path) -> StatusBlob:
    raw = path.read_bytes()
    if len(raw) != FILE_SIZE:
        raise ValueError(f"expected {FILE_SIZE:#x} bytes, got {len(raw):#x}")
    parsed = GAME_CFG_STRUCT.parse(raw)
    encoded = bytes(parsed["encoded"])
    stored_checksum = int(parsed["checksum"])
    decoded = decode_blob(encoded)
    computed = compute_checksum(decoded)
    return StatusBlob(decoded=decoded, checksum=stored_checksum, checksum_expected=computed)


def save_status(path: Path, decoded: bytes) -> None:
    checksum = compute_checksum(decoded)
    encoded = encode_blob(decoded)
    path.write_bytes(GAME_CFG_STRUCT.build({"encoded": encoded, "checksum": checksum}))


def parse_status_blob(decoded: bytes) -> dict:
    if len(decoded) != BLOB_SIZE:
        raise ValueError(f"expected decoded blob of {BLOB_SIZE:#x} bytes, got {len(decoded):#x}")
    return GAME_STATUS_STRUCT.parse(decoded)


def build_status_blob(data: dict) -> bytes:
    decoded = GAME_STATUS_STRUCT.build(data)
    if len(decoded) != BLOB_SIZE:
        raise ValueError(f"expected decoded blob of {BLOB_SIZE:#x} bytes, got {len(decoded):#x}")
    return decoded


def default_status_data() -> dict:
    return parse_status_blob(bytes(BLOB_SIZE))


def default_status_blob() -> bytes:
    return bytes(BLOB_SIZE)


def ensure_game_status(base_dir: Path) -> GameStatus:
    path = base_dir / GAME_CFG_NAME
    if path.exists():
        try:
            blob = load_status(path)
            if not blob.checksum_valid:
                raise ValueError("checksum mismatch")
            data = parse_status_blob(blob.decoded)
        except Exception:
            data = default_status_data()
            decoded = build_status_blob(data)
            save_status(path, decoded)
        return GameStatus(path=path, data=data, dirty=False)
    data = default_status_data()
    decoded = build_status_blob(data)
    save_status(path, decoded)
    return GameStatus(path=path, data=data, dirty=False)
