from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import msgspec


@dataclass(frozen=True)
class BuildEvent:
    raw: dict[str, Any]
    builder: dict[str, Any]
    meta: dict[str, Any] | None
    config: dict[str, Any] | None
    entry_count: int | None
    entries: list[dict[str, Any]] | None
    ts: str | None


class QuestBuildRow(msgspec.Struct, forbid_unknown_fields=True):
    key: str
    title: str
    ts: str | None
    builder_name: Any
    builder_va: Any
    entry_count: int | None
    entries_truncated: Any
    time_limit_ms: Any
    terrain_id: Any
    start_weapon_id: Any
    unlock_perk_id: Any
    unlock_weapon_id: Any
    hardcore: Any
    player_count: Any
    spawn_ids: list[str] | None
    spawn_id_counts: dict[str, int] | None
    min_trigger_ms: int | None
    max_trigger_ms: int | None


class QuestBuildSummary(msgspec.Struct, forbid_unknown_fields=True):
    source_logs: list[str]
    event_count: int
    unique_keys: int
    missing_levels: list[str]
    duplicates: dict[str, int]
    runs: list[QuestBuildRow]
    expected: dict[str, dict[str, Any]]


def iter_jsonl(paths: Iterable[Path]) -> Iterable[dict[str, Any]]:
    for path in paths:
        if not path.exists():
            continue
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
                    yield obj


def parse_build_events(paths: Iterable[Path]) -> list[BuildEvent]:
    events: list[BuildEvent] = []
    for obj in iter_jsonl(paths):
        if obj.get("event") != "quest_build":
            continue
        builder = obj.get("builder") or {}
        if not isinstance(builder, dict):
            builder = {}
        meta = obj.get("meta")
        if not isinstance(meta, dict):
            meta = None
        config = obj.get("config")
        if not isinstance(config, dict):
            config = None
        entries = obj.get("entries")
        if not isinstance(entries, list):
            entries = None
        entry_count = obj.get("entry_count")
        if isinstance(entry_count, float):
            entry_count = int(entry_count)
        if not isinstance(entry_count, int):
            entry_count = None
        events.append(
            BuildEvent(
                raw=obj,
                builder=builder,
                meta=meta,
                config=config,
                entry_count=entry_count,
                entries=entries,
                ts=obj.get("ts"),
            ),
        )
    return events


def stage_key(event: BuildEvent) -> str | None:
    level = event.builder.get("level")
    if isinstance(level, str) and level:
        return level
    meta = event.meta or {}
    tier = meta.get("tier")
    quest_index = meta.get("quest_index")
    if isinstance(tier, int) and isinstance(quest_index, int):
        return f"{tier}.{quest_index}"
    return None


def stage_title(event: BuildEvent) -> str | None:
    title = event.builder.get("title")
    if isinstance(title, str) and title:
        return title
    meta = event.meta or {}
    name = meta.get("name")
    if isinstance(name, str) and name:
        return name
    return None


def summarize_entries(entries: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    if not entries:
        return None
    spawn_counts: Counter[int] = Counter()
    min_trigger = None
    max_trigger = None
    min_x = None
    max_x = None
    min_y = None
    max_y = None
    min_heading = None
    max_heading = None

    for entry in entries:
        spawn_id = entry.get("spawn_id")
        if isinstance(spawn_id, int):
            spawn_counts[spawn_id] += 1
        trigger = entry.get("trigger_ms")
        if isinstance(trigger, (int, float)):
            value = int(trigger)
            min_trigger = value if min_trigger is None else min(min_trigger, value)
            max_trigger = value if max_trigger is None else max(max_trigger, value)
        x = entry.get("x")
        y = entry.get("y")
        heading = entry.get("heading")
        if isinstance(x, (int, float)):
            min_x = x if min_x is None else min(min_x, x)
            max_x = x if max_x is None else max(max_x, x)
        if isinstance(y, (int, float)):
            min_y = y if min_y is None else min(min_y, y)
            max_y = y if max_y is None else max(max_y, y)
        if isinstance(heading, (int, float)):
            min_heading = heading if min_heading is None else min(min_heading, heading)
            max_heading = heading if max_heading is None else max(max_heading, heading)

    return {
        "entry_total": len(entries),
        "spawn_id_counts": {
            f"0x{spawn_id:02x}": count for spawn_id, count in sorted(spawn_counts.items())
        },
        "spawn_ids": [f"0x{spawn_id:02x}" for spawn_id in sorted(spawn_counts)],
        "min_trigger_ms": min_trigger,
        "max_trigger_ms": max_trigger,
        "min_x": min_x,
        "max_x": max_x,
        "min_y": min_y,
        "max_y": max_y,
        "min_heading": min_heading,
        "max_heading": max_heading,
    }


def load_expected_levels() -> dict[str, dict[str, Any]]:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))
    try:
        from crimson.quests import tier1, tier2, tier3, tier4, tier5
    except ImportError:
        return {}
    quests = [*tier1.QUESTS, *tier2.QUESTS, *tier3.QUESTS, *tier4.QUESTS, *tier5.QUESTS]
    expected: dict[str, dict[str, Any]] = {}
    for quest in quests:
        expected[quest.level] = {
            "title": quest.title,
            "builder_address": quest.builder_address,
        }
    return expected


def build_rows(events: list[BuildEvent]) -> list[QuestBuildRow]:
    rows: list[QuestBuildRow] = []
    for event in events:
        key = stage_key(event) or event.builder.get("name") or "unknown"
        title = stage_title(event) or "unknown"
        meta = event.meta or {}
        builder = event.builder
        config = event.config or {}
        summary = summarize_entries(event.entries)
        rows.append(
            QuestBuildRow(
                key=str(key),
                title=str(title),
                ts=event.ts,
                builder_name=builder.get("name"),
                builder_va=builder.get("va"),
                entry_count=event.entry_count,
                entries_truncated=event.raw.get("entries_truncated"),
                time_limit_ms=meta.get("time_limit_ms"),
                terrain_id=meta.get("terrain_id"),
                start_weapon_id=meta.get("start_weapon_id"),
                unlock_perk_id=meta.get("unlock_perk_id"),
                unlock_weapon_id=meta.get("unlock_weapon_id"),
                hardcore=config.get("hardcore"),
                player_count=config.get("player_count"),
                spawn_ids=(None if summary is None else summary.get("spawn_ids")),
                spawn_id_counts=(None if summary is None else summary.get("spawn_id_counts")),
                min_trigger_ms=(None if summary is None else summary.get("min_trigger_ms")),
                max_trigger_ms=(None if summary is None else summary.get("max_trigger_ms")),
            ),
        )
    return rows


def write_json(path: Path, payload: QuestBuildSummary) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(msgspec.json.encode(payload))


def write_csv(path: Path, rows: list[QuestBuildRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "key",
        "title",
        "ts",
        "builder_name",
        "builder_va",
        "entry_count",
        "entries_truncated",
        "time_limit_ms",
        "terrain_id",
        "start_weapon_id",
        "unlock_perk_id",
        "unlock_weapon_id",
        "hardcore",
        "player_count",
        "spawn_ids",
        "min_trigger_ms",
        "max_trigger_ms",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            spawn_ids = None if row.spawn_ids is None else ";".join(row.spawn_ids)
            writer.writerow(
                {
                    "key": row.key,
                    "title": row.title,
                    "ts": row.ts,
                    "builder_name": row.builder_name,
                    "builder_va": row.builder_va,
                    "entry_count": row.entry_count,
                    "entries_truncated": row.entries_truncated,
                    "time_limit_ms": row.time_limit_ms,
                    "terrain_id": row.terrain_id,
                    "start_weapon_id": row.start_weapon_id,
                    "unlock_perk_id": row.unlock_perk_id,
                    "unlock_weapon_id": row.unlock_weapon_id,
                    "hardcore": row.hardcore,
                    "player_count": row.player_count,
                    "spawn_ids": spawn_ids,
                    "min_trigger_ms": row.min_trigger_ms,
                    "max_trigger_ms": row.max_trigger_ms,
                },
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Reduce quest build JSONL logs into summaries.")
    parser.add_argument(
        "--log",
        dest="logs",
        action="append",
        type=Path,
        help="JSONL log path (repeatable).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("analysis/frida"),
        help="Output directory (default: analysis/frida).",
    )
    args = parser.parse_args()

    logs = args.logs or [Path("artifacts/frida/share/crimsonland_quest_builds.jsonl")]
    events = parse_build_events(logs)
    rows = build_rows(events)

    grouped: dict[str, list[QuestBuildRow]] = defaultdict(list)
    for row in rows:
        grouped[row.key].append(row)

    expected = load_expected_levels()
    missing = [level for level in sorted(expected) if level not in grouped]
    duplicates = {key: len(values) for key, values in grouped.items() if len(values) > 1}

    summary = QuestBuildSummary(
        source_logs=[str(path) for path in logs],
        event_count=len(events),
        unique_keys=len(grouped),
        missing_levels=list(missing),
        duplicates={str(key): int(value) for key, value in duplicates.items()},
        runs=rows,
        expected=expected,
    )

    out_dir: Path = args.out_dir
    write_json(out_dir / "quest_builds_summary.json", summary)
    write_csv(out_dir / "quest_builds_summary.csv", rows)

    print(f"Wrote {out_dir / 'quest_builds_summary.json'}")
    print(f"Wrote {out_dir / 'quest_builds_summary.csv'}")
    if missing:
        print(f"Missing {len(missing)} expected levels.")
    if duplicates:
        print(f"Duplicate runs: {len(duplicates)}")


if __name__ == "__main__":
    main()
