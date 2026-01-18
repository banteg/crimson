from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

BLOB_SIZE = 0x268
FILE_SIZE = BLOB_SIZE + 4

OFFSET_QUEST_UNLOCK = 0x0
OFFSET_WEAPON_USAGE = 0x4
WEAPON_USAGE_COUNT = 53
OFFSET_QUEST_PLAY_COUNTS = 0xD8
OFFSET_MODE_PLAY_COUNTS = 0x244
OFFSET_GAME_SEQUENCE_ID = 0x254

# Quest play count length inferred from known trailing fields in the blob.
QUEST_PLAY_COUNT = (OFFSET_MODE_PLAY_COUNTS - OFFSET_QUEST_PLAY_COUNTS) // 4

MODE_COUNT_ORDER = (
    ("survival", OFFSET_MODE_PLAY_COUNTS),
    ("rush", OFFSET_MODE_PLAY_COUNTS + 4),
    ("typo", OFFSET_MODE_PLAY_COUNTS + 8),
    ("other", OFFSET_MODE_PLAY_COUNTS + 12),
)


@dataclass
class StatusBlob:
    decoded: bytearray
    checksum: int
    checksum_expected: int

    @property
    def checksum_valid(self) -> bool:
        return (self.checksum & 0xFFFFFFFF) == (self.checksum_expected & 0xFFFFFFFF)


def to_s8(value: int) -> int:
    value &= 0xFF
    return value - 0x100 if value & 0x80 else value


def index_poly(idx: int) -> int:
    i = to_s8(idx)
    return ((i * 7 + 0x0F) * i + 0x03) * i


def decode_blob(encoded: bytes) -> bytearray:
    if len(encoded) != BLOB_SIZE:
        raise ValueError(f"decoded blob must be {BLOB_SIZE:#x} bytes, got {len(encoded):#x}")
    decoded = bytearray(encoded)
    for i in range(BLOB_SIZE):
        decoded[i] = (decoded[i] - 0x6F - index_poly(i)) & 0xFF
    return decoded


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
    data = path.read_bytes()
    if len(data) != FILE_SIZE:
        raise ValueError(f"expected {FILE_SIZE:#x} bytes, got {len(data):#x}")
    encoded = data[:BLOB_SIZE]
    stored_checksum = struct.unpack_from("<I", data, BLOB_SIZE)[0]
    decoded = decode_blob(encoded)
    computed = compute_checksum(decoded)
    return StatusBlob(decoded=decoded, checksum=stored_checksum, checksum_expected=computed)


def save_status(path: Path, decoded: bytes) -> None:
    checksum = compute_checksum(decoded)
    encoded = encode_blob(decoded)
    payload = encoded + struct.pack("<I", checksum)
    path.write_bytes(payload)


def read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def write_u16(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", buf, offset, value & 0xFFFF)


def read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def write_u32(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buf, offset, value & 0xFFFFFFFF)


def extract_fields(decoded: bytes) -> dict:
    quest_unlock_index = read_u16(decoded, OFFSET_QUEST_UNLOCK)
    quest_unlock_index_full = read_u16(decoded, OFFSET_QUEST_UNLOCK + 2)
    weapon_usage = list(
        struct.unpack_from("<" + "I" * WEAPON_USAGE_COUNT, decoded, OFFSET_WEAPON_USAGE)
    )
    quest_play_counts = list(
        struct.unpack_from("<" + "I" * QUEST_PLAY_COUNT, decoded, OFFSET_QUEST_PLAY_COUNTS)
    )
    mode_counts = {
        name: read_u32(decoded, offset) for name, offset in MODE_COUNT_ORDER
    }
    game_sequence_id = read_u32(decoded, OFFSET_GAME_SEQUENCE_ID)
    tail_offset = OFFSET_GAME_SEQUENCE_ID + 4
    unknown_tail = decoded[tail_offset:]
    return {
        "quest_unlock_index": quest_unlock_index,
        "quest_unlock_index_full": quest_unlock_index_full,
        "weapon_usage_counts": weapon_usage,
        "quest_play_counts": quest_play_counts,
        "mode_play_counts": mode_counts,
        "game_sequence_id": game_sequence_id,
        "unknown_tail_hex": unknown_tail.hex(),
    }


def apply_updates(decoded: bytearray, updates: dict) -> None:
    if "quest_unlock_index" in updates:
        write_u16(decoded, OFFSET_QUEST_UNLOCK, int(updates["quest_unlock_index"]))
    if "quest_unlock_index_full" in updates:
        write_u16(decoded, OFFSET_QUEST_UNLOCK + 2, int(updates["quest_unlock_index_full"]))
    if "game_sequence_id" in updates:
        write_u32(decoded, OFFSET_GAME_SEQUENCE_ID, int(updates["game_sequence_id"]))

    weapon_updates = updates.get("weapon_usage_counts", {})
    for key, value in weapon_updates.items():
        idx = int(key)
        if not (0 <= idx < WEAPON_USAGE_COUNT):
            raise ValueError(f"weapon_usage index out of range: {idx}")
        write_u32(decoded, OFFSET_WEAPON_USAGE + idx * 4, int(value))

    quest_updates = updates.get("quest_play_counts", {})
    for key, value in quest_updates.items():
        idx = int(key)
        if not (0 <= idx < QUEST_PLAY_COUNT):
            raise ValueError(f"quest_play_counts index out of range: {idx}")
        write_u32(decoded, OFFSET_QUEST_PLAY_COUNTS + idx * 4, int(value))

    mode_updates = updates.get("mode_play_counts", {})
    for key, value in mode_updates.items():
        key = str(key)
        matched = False
        for name, offset in MODE_COUNT_ORDER:
            if key == name:
                write_u32(decoded, offset, int(value))
                matched = True
                break
        if not matched:
            raise ValueError(f"unknown mode_play_counts key: {key}")


def parse_kv_pairs(pairs: Iterable[str]) -> dict:
    updates: dict[str, dict | int] = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"invalid --set entry (expected key=value): {pair}")
        key, value = pair.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key.startswith("weapon_usage."):
            idx = key.split(".", 1)[1]
            updates.setdefault("weapon_usage_counts", {})[idx] = int(value, 0)
        elif key.startswith("quest_play."):
            idx = key.split(".", 1)[1]
            updates.setdefault("quest_play_counts", {})[idx] = int(value, 0)
        elif key.startswith("mode_play."):
            mode = key.split(".", 1)[1]
            updates.setdefault("mode_play_counts", {})[mode] = int(value, 0)
        elif key in {"quest_unlock_index", "quest_unlock_index_full", "game_sequence_id"}:
            updates[key] = int(value, 0)
        else:
            raise ValueError(f"unknown key: {key}")
    return updates


def cmd_info(args: argparse.Namespace) -> int:
    blob = load_status(args.path)
    fields = extract_fields(blob.decoded)
    print(f"Path: {args.path}")
    print(f"Checksum: 0x{blob.checksum:08x} (computed 0x{blob.checksum_expected:08x})")
    print(f"Checksum valid: {blob.checksum_valid}")
    print(f"Quest unlock index: {fields['quest_unlock_index']}")
    print(f"Quest unlock index (full): {fields['quest_unlock_index_full']}")
    print(f"Game sequence id: {fields['game_sequence_id']}")
    print("Mode play counts:")
    for name, _ in MODE_COUNT_ORDER:
        print(f"  {name}: {fields['mode_play_counts'][name]}")
    nonzero_weapons = [
        (idx, count) for idx, count in enumerate(fields["weapon_usage_counts"]) if count
    ]
    nonzero_weapons.sort(key=lambda item: item[1], reverse=True)
    if nonzero_weapons:
        print("Top weapon usage counts:")
        for idx, count in nonzero_weapons[:10]:
            print(f"  weapon {idx}: {count}")
    nonzero_quests = [
        (idx, count) for idx, count in enumerate(fields["quest_play_counts"]) if count
    ]
    if nonzero_quests:
        print(f"Quest play counts (nonzero): {len(nonzero_quests)} entries")
    if args.json:
        payload = {
            "checksum": blob.checksum,
            "checksum_expected": blob.checksum_expected,
            "checksum_valid": blob.checksum_valid,
            **fields,
        }
        args.json.write_text(json.dumps(payload, indent=2) + "\n")
    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    blob = load_status(args.path)
    if not blob.checksum_valid:
        raise SystemExit("checksum mismatch; refusing to decode")
    if args.out:
        args.out.write_bytes(blob.decoded)
    if args.json:
        payload = {
            "checksum": blob.checksum,
            "checksum_expected": blob.checksum_expected,
            "checksum_valid": blob.checksum_valid,
            **extract_fields(blob.decoded),
        }
        args.json.write_text(json.dumps(payload, indent=2) + "\n")
    return 0


def cmd_encode(args: argparse.Namespace) -> int:
    decoded = args.path.read_bytes()
    if len(decoded) != BLOB_SIZE:
        raise SystemExit(f"decoded blob must be {BLOB_SIZE:#x} bytes")
    save_status(args.out, decoded)
    return 0


def cmd_set(args: argparse.Namespace) -> int:
    blob = load_status(args.path)
    updates: dict = {}
    if args.json:
        updates.update(json.loads(args.json.read_text()))
    if args.set:
        updates.update(parse_kv_pairs(args.set))
    if not updates:
        raise SystemExit("no updates provided")
    decoded = blob.decoded
    apply_updates(decoded, updates)
    out_path = args.out or args.path
    save_status(out_path, decoded)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Decode/edit Crimsonland game.cfg status file")
    sub = parser.add_subparsers(dest="command", required=True)

    info = sub.add_parser("info", help="Print status summary")
    info.add_argument("path", type=Path, help="game.cfg path")
    info.add_argument("--json", type=Path, help="write decoded fields to JSON")
    info.set_defaults(func=cmd_info)

    decode = sub.add_parser("decode", help="Decode game.cfg to raw blob")
    decode.add_argument("path", type=Path, help="game.cfg path")
    decode.add_argument("--out", type=Path, help="write decoded blob to file")
    decode.add_argument("--json", type=Path, help="write decoded fields to JSON")
    decode.set_defaults(func=cmd_decode)

    encode = sub.add_parser("encode", help="Encode decoded blob into game.cfg")
    encode.add_argument("path", type=Path, help="decoded blob (0x268 bytes)")
    encode.add_argument("--out", type=Path, required=True, help="output game.cfg path")
    encode.set_defaults(func=cmd_encode)

    set_cmd = sub.add_parser("set", help="Edit known fields and rewrite game.cfg")
    set_cmd.add_argument("path", type=Path, help="game.cfg path")
    set_cmd.add_argument("--out", type=Path, help="output path (defaults to in-place)")
    set_cmd.add_argument(
        "--set",
        action="append",
        default=[],
        help=(
            "key=value updates (repeatable). Keys: quest_unlock_index, "
            "quest_unlock_index_full, game_sequence_id, weapon_usage.<id>, "
            "quest_play.<index>, mode_play.<survival|rush|typo|other>"
        ),
    )
    set_cmd.add_argument("--json", type=Path, help="JSON file containing updates")
    set_cmd.set_defaults(func=cmd_set)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
