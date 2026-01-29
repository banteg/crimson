from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class _Session:
    start_event: dict | None = None
    ui_ready_event: dict | None = None
    demo_starts: list[dict] = field(default_factory=list)


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


def summarize_idle_threshold(rows: list[dict]) -> list[_Session]:
    sessions: list[_Session] = []
    current: _Session | None = None

    for row in rows:
        raw_event = row.get("event") or row.get("kind")
        if raw_event is None:
            continue
        event = str(raw_event)
        if event.startswith("demo_idle_threshold_"):
            event = event.removeprefix("demo_idle_threshold_")

        if event not in ("start", "ui_ready", "demo_mode_start"):
            continue

        if event == "start" or current is None:
            current = _Session()
            sessions.append(current)
            if event == "start":
                current.start_event = row

        if event == "ui_ready":
            current.ui_ready_event = row
        elif event == "demo_mode_start":
            current.demo_starts.append(row)

    return sessions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize demo idle threshold trace JSONL.")
    parser.add_argument("log", type=Path, help="Raw demo_idle_threshold_trace.jsonl to summarize")
    parser.add_argument(
        "--print-events",
        action="store_true",
        help="Print representative JSON for ui_ready and demo_mode_start events",
    )
    args = parser.parse_args(argv)

    rows = _iter_jsonl(args.log)
    sessions = summarize_idle_threshold(rows)

    print(f"{args.log}: sessions={len(sessions)}")
    for idx, sess in enumerate(sessions):
        if not sess.demo_starts:
            print(f"session[{idx}]: demo_mode_start: 0")
            continue

        evt = sess.demo_starts[0]
        dt_ui = _as_int(evt.get("dt_since_ui_ready_ms"))
        dt_start = _as_int(evt.get("dt_since_start_ms"))

        dt_best = dt_ui if dt_ui is not None else dt_start
        kind = "dt_since_ui_ready_ms" if dt_ui is not None else "dt_since_start_ms"

        print(f"session[{idx}]: demo_mode_start: {len(sess.demo_starts)}")
        print(f"session[{idx}]: idle_threshold_ms: {dt_best} ({kind})")
        if args.print_events:
            if sess.ui_ready_event is not None:
                print(f"session[{idx}]: ui_ready: {json.dumps(sess.ui_ready_event)}")
            print(f"session[{idx}]: demo_mode_start: {json.dumps(evt)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
