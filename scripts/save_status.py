from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

from crimson.save_status import (
    BLOB_SIZE,
    MODE_COUNT_ORDER,
    QUEST_PLAY_COUNT,
    WEAPON_USAGE_COUNT,
    build_status_blob,
    load_status,
    parse_status_blob,
    save_status,
)


def extract_fields(decoded: bytes) -> dict:
    data = parse_status_blob(decoded)
    mode_counts = {name: int(data[field]) for name, field in MODE_COUNT_ORDER}
    weapon_usage = [int(value) for value in data["weapon_usage_counts"]]
    quest_play_counts = [int(value) for value in data["quest_play_counts"]]
    unknown_tail = bytes(data["unknown_tail"])
    return {
        "quest_unlock_index": int(data["quest_unlock_index"]),
        "quest_unlock_index_full": int(data["quest_unlock_index_full"]),
        "weapon_usage_counts": weapon_usage,
        "quest_play_counts": quest_play_counts,
        "mode_play_counts": mode_counts,
        "game_sequence_id": int(data["game_sequence_id"]),
        "unknown_tail_hex": unknown_tail.hex(),
    }


def apply_updates(data: dict, updates: dict) -> None:
    if "quest_unlock_index" in updates:
        data["quest_unlock_index"] = int(updates["quest_unlock_index"]) & 0xFFFF
    if "quest_unlock_index_full" in updates:
        data["quest_unlock_index_full"] = int(updates["quest_unlock_index_full"]) & 0xFFFF
    if "game_sequence_id" in updates:
        data["game_sequence_id"] = int(updates["game_sequence_id"]) & 0xFFFFFFFF

    weapon_updates = updates.get("weapon_usage_counts", {})
    for key, value in weapon_updates.items():
        idx = int(key)
        if not (0 <= idx < WEAPON_USAGE_COUNT):
            raise ValueError(f"weapon_usage index out of range: {idx}")
        data["weapon_usage_counts"][idx] = int(value) & 0xFFFFFFFF

    quest_updates = updates.get("quest_play_counts", {})
    for key, value in quest_updates.items():
        idx = int(key)
        if not (0 <= idx < QUEST_PLAY_COUNT):
            raise ValueError(f"quest_play_counts index out of range: {idx}")
        data["quest_play_counts"][idx] = int(value) & 0xFFFFFFFF

    mode_updates = updates.get("mode_play_counts", {})
    mode_fields = {name: field for name, field in MODE_COUNT_ORDER}
    for key, value in mode_updates.items():
        key = str(key)
        field = mode_fields.get(key)
        if field is None:
            raise ValueError(f"unknown mode_play_counts key: {key}")
        data[field] = int(value) & 0xFFFFFFFF


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
    data = parse_status_blob(blob.decoded)
    apply_updates(data, updates)
    out_path = args.out or args.path
    save_status(out_path, build_status_blob(data))
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
