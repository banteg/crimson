from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from crimson.demo_trial import DEMO_QUEST_GRACE_TIME_MS, DEMO_TOTAL_PLAY_TIME_MS, demo_trial_overlay_info


def _iter_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def _as_int(value: object | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value).strip(), 0)
    except Exception:
        return None


def validate_demo_trial_overlay_events(events: list[dict], *, source: str) -> list[str]:
    errors: list[str] = []
    for idx, evt in enumerate(events):
        kind = evt.get("event") or evt.get("kind")
        if kind != "demo_trial_overlay_render":
            continue

        mode_id = _as_int(evt.get("mode_id"))
        used_ms = _as_int(evt.get("game_sequence_id_ms"))
        grace_ms = _as_int(evt.get("demo_trial_elapsed_ms"))
        quest_major = _as_int(evt.get("quest_stage_major"))
        quest_minor = _as_int(evt.get("quest_stage_minor"))
        tier_locked = evt.get("tier_locked")
        remaining_ms = _as_int(evt.get("remaining_ms"))

        if mode_id is None:
            errors.append(f"{source}:{idx}: missing mode_id")
            continue
        if used_ms is None:
            errors.append(f"{source}:{idx}: missing game_sequence_id_ms")
            continue
        if grace_ms is None:
            errors.append(f"{source}:{idx}: missing demo_trial_elapsed_ms")
            continue
        if quest_major is None or quest_minor is None:
            errors.append(f"{source}:{idx}: missing quest_stage_major/minor")
            continue

        info = demo_trial_overlay_info(
            demo_build=True,
            game_mode_id=mode_id,
            global_playtime_ms=used_ms,
            quest_grace_elapsed_ms=grace_ms,
            quest_stage_major=quest_major,
            quest_stage_minor=quest_minor,
        )
        if not info.visible:
            errors.append(f"{source}:{idx}: expected overlay visible, got visible={info.visible} kind={info.kind}")

        if remaining_ms is not None and int(remaining_ms) != int(info.remaining_ms):
            errors.append(
                f"{source}:{idx}: remaining_ms mismatch: log={remaining_ms} expected={info.remaining_ms} kind={info.kind}"
            )

        expected_tier_locked = (mode_id == 3) and (quest_major > 1 or quest_minor > 10)
        if isinstance(tier_locked, bool) and tier_locked != expected_tier_locked:
            errors.append(f"{source}:{idx}: tier_locked mismatch: log={tier_locked} expected={expected_tier_locked}")

        if isinstance(tier_locked, bool):
            if info.kind == "quest_tier_limit" and not tier_locked:
                errors.append(f"{source}:{idx}: kind={info.kind} but tier_locked=false")
            if tier_locked and info.kind == "quest_grace_left":
                errors.append(f"{source}:{idx}: kind={info.kind} but tier_locked=true")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate demo trial overlay trace JSONL against the Python model.")
    parser.add_argument("log", type=Path, help="Raw trace JSONL or reduced facts.jsonl to validate")
    parser.add_argument("--samples", type=int, default=0, help="Print N representative overlay events")
    args = parser.parse_args(argv)

    rows = _iter_jsonl(args.log)
    kinds = Counter((row.get("event") or row.get("kind") or "unknown") for row in rows if isinstance(row, dict))
    errors = validate_demo_trial_overlay_events(rows, source=str(args.log))

    if args.samples > 0:
        samples: list[tuple[int, dict]] = []
        for idx, row in enumerate(rows):
            kind = row.get("event") or row.get("kind")
            if kind == "demo_trial_overlay_render":
                samples.append((idx, row))
        if samples:
            print(f"Samples: {min(args.samples, len(samples))} / {len(samples)}")
            for idx, evt in samples[: args.samples]:
                mode_id = _as_int(evt.get("mode_id"))
                used_ms = _as_int(evt.get("game_sequence_id_ms"))
                grace_ms = _as_int(evt.get("demo_trial_elapsed_ms"))
                quest_major = _as_int(evt.get("quest_stage_major"))
                quest_minor = _as_int(evt.get("quest_stage_minor"))
                if (
                    mode_id is None
                    or used_ms is None
                    or grace_ms is None
                    or quest_major is None
                    or quest_minor is None
                ):
                    continue

                info = demo_trial_overlay_info(
                    demo_build=True,
                    game_mode_id=mode_id,
                    global_playtime_ms=used_ms,
                    quest_grace_elapsed_ms=grace_ms,
                    quest_stage_major=quest_major,
                    quest_stage_minor=quest_minor,
                )
                sample = {
                    "idx": idx,
                    "mode_id": mode_id,
                    "quest_stage_major": quest_major,
                    "quest_stage_minor": quest_minor,
                    "game_sequence_id_ms": used_ms,
                    "demo_trial_elapsed_ms": grace_ms,
                    "remaining_ms": _as_int(evt.get("remaining_ms")),
                    "tier_locked": evt.get("tier_locked"),
                    "expected": {
                        "visible": info.visible,
                        "kind": info.kind,
                        "remaining_ms": info.remaining_ms,
                        "remaining_label": info.remaining_label,
                    },
                }
                print(json.dumps(sample))

    overlay_events = int(kinds.get("demo_trial_overlay_render", 0))
    print(f"{args.log}: demo_trial_overlay_render events: {overlay_events}")
    print(f"Expected constants: total_ms={DEMO_TOTAL_PLAY_TIME_MS} grace_ms={DEMO_QUEST_GRACE_TIME_MS}")

    if not errors:
        print("OK")
        return 0

    print(f"ERRORS: {len(errors)}")
    for item in errors[:40]:
        print(item)
    if len(errors) > 40:
        print(f"... ({len(errors) - 40} more)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
