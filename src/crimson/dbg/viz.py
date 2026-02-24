from __future__ import annotations

import html
from pathlib import Path

from .diff import diff_traces
from .policy import ParityPolicy
from .schema import TickRecord
from .trace import TraceReader

_ENTITY_KINDS = ("creatures", "projectiles", "secondary_projectiles", "bonuses")


def _as_object_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    out: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(key, str):
            out[key] = item
    return out


def _as_object_list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def _entity_counts(row: TickRecord | None) -> dict[str, int]:
    if row is None:
        return {kind: 0 for kind in _ENTITY_KINDS}
    entity_samples = _as_object_dict(row.channels.get("entity_samples"))
    if entity_samples is None:
        return {kind: 0 for kind in _ENTITY_KINDS}
    return {kind: len(_as_object_list(entity_samples.get(kind))) for kind in _ENTITY_KINDS}


def _checkpoint_value(row: TickRecord | None, key: str) -> object:
    if row is None:
        return None
    checkpoint = _as_object_dict(row.channels.get("checkpoint"))
    if checkpoint is None:
        return None
    return checkpoint.get(key)


def _score_value(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _timeline_rows(
    *,
    golden_trace: Path,
    candidate_trace: Path,
    tick_start: int,
    tick_end: int,
) -> list[dict[str, object]]:
    with TraceReader(Path(golden_trace)) as expected, TraceReader(Path(candidate_trace)) as candidate:
        expected_rows = {
            int(row.tick_index): row
            for row in expected.iter_ticks(tick_start=tick_start, tick_end=tick_end)
        }
        candidate_rows = {
            int(row.tick_index): row
            for row in candidate.iter_ticks(tick_start=tick_start, tick_end=tick_end)
        }

    all_ticks = sorted(set(expected_rows) | set(candidate_rows))
    out: list[dict[str, object]] = []
    for tick in all_ticks:
        expected_row = expected_rows.get(tick)
        candidate_row = candidate_rows.get(tick)
        expected_counts = _entity_counts(expected_row)
        candidate_counts = _entity_counts(candidate_row)
        expected_score = _score_value(_checkpoint_value(expected_row, "score_xp"))
        candidate_score = _score_value(_checkpoint_value(candidate_row, "score_xp"))
        expected_kills = _score_value(_checkpoint_value(expected_row, "kills"))
        candidate_kills = _score_value(_checkpoint_value(candidate_row, "kills"))
        diverged = bool(
            expected_score != candidate_score
            or expected_kills != candidate_kills
            or expected_counts != candidate_counts,
        )
        out.append(
            {
                "tick_index": int(tick),
                "diverged": diverged,
                "expected_score_xp": int(expected_score),
                "candidate_score_xp": int(candidate_score),
                "expected_kills": int(expected_kills),
                "candidate_kills": int(candidate_kills),
                "expected_entities": expected_counts,
                "candidate_entities": candidate_counts,
            },
        )
    return out


def _default_focus_tick(
    *,
    golden_trace: Path,
    candidate_trace: Path,
    policy: ParityPolicy,
) -> int:
    report = diff_traces(
        expected_trace_path=Path(golden_trace),
        actual_trace_path=Path(candidate_trace),
        policy=policy,
    )
    if report.mismatch is not None:
        return int(report.mismatch.tick_index)
    if report.tick_start is not None:
        return int(report.tick_start)
    with TraceReader(Path(golden_trace)) as trace:
        first_tick = trace.footer.first_tick
        if first_tick is not None:
            return int(first_tick)
    return 0


def _render_html(*, payload: dict[str, object]) -> str:
    rows_obj = payload.get("rows")
    rows = list(rows_obj) if isinstance(rows_obj, list) else []
    body_rows: list[str] = []
    focus_tick = payload.get("focus_tick")
    for item in rows:
        row = _as_object_dict(item) or {}
        tick = row.get("tick_index")
        expected_entities = _as_object_dict(row.get("expected_entities")) or {}
        candidate_entities = _as_object_dict(row.get("candidate_entities")) or {}
        classes: list[str] = []
        if bool(row.get("diverged")):
            classes.append("diverged")
        if tick == focus_tick:
            classes.append("focus")
        class_attr = f' class="{" ".join(classes)}"' if classes else ""
        body_rows.append(
            "<tr"
            + class_attr
            + ">"
            + f"<td>{html.escape(str(tick))}</td>"
            + f"<td>{html.escape(str(row.get('expected_score_xp')))}</td>"
            + f"<td>{html.escape(str(row.get('candidate_score_xp')))}</td>"
            + f"<td>{html.escape(str(row.get('expected_kills')))}</td>"
            + f"<td>{html.escape(str(row.get('candidate_kills')))}</td>"
            + f"<td>{html.escape(str(expected_entities.get('creatures')))}</td>"
            + f"<td>{html.escape(str(candidate_entities.get('creatures')))}</td>"
            + f"<td>{html.escape(str(expected_entities.get('projectiles')))}</td>"
            + f"<td>{html.escape(str(candidate_entities.get('projectiles')))}</td>"
            + "</tr>",
        )

    golden_text = html.escape(str(payload.get("golden_trace")))
    candidate_text = html.escape(str(payload.get("candidate_trace")))
    focus_text = html.escape(str(payload.get("focus_tick")))
    start_text = html.escape(str(payload.get("tick_start")))
    end_text = html.escape(str(payload.get("tick_end")))
    rows_html = "\n".join(body_rows)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="utf-8" />\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1" />\n'
        "  <title>Crimson Debug Viz</title>\n"
        "  <style>\n"
        "    :root { --bg: #f4f6f8; --fg: #1d2a35; --muted: #4f5d6b; --line: #d9e1e8; --focus: #ffe39f; --div: #ffd7d7; }\n"
        '    body { margin: 0; font-family: "IBM Plex Sans", "Segoe UI", sans-serif; background: var(--bg); color: var(--fg); }\n'
        "    .wrap { max-width: 1100px; margin: 0 auto; padding: 24px 16px 40px; }\n"
        "    .meta { display: grid; gap: 6px; margin-bottom: 14px; color: var(--muted); font-size: 14px; }\n"
        "    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid var(--line); }\n"
        "    th, td { border-bottom: 1px solid var(--line); padding: 8px; text-align: right; font-size: 13px; }\n"
        "    th:first-child, td:first-child { text-align: left; }\n"
        "    tr.diverged { background: var(--div); }\n"
        "    tr.focus { outline: 2px solid #d18f00; outline-offset: -2px; background: var(--focus); }\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        '  <div class="wrap">\n'
        "    <h1>Crimson Debug Viz</h1>\n"
        '    <div class="meta">\n'
        f"      <div>Golden: {golden_text}</div>\n"
        f"      <div>Candidate: {candidate_text}</div>\n"
        f"      <div>Focus tick: {focus_text} | Window: {start_text}..{end_text}</div>\n"
        "    </div>\n"
        "    <table>\n"
        "      <thead>\n"
        "        <tr>\n"
        "          <th>Tick</th>\n"
        "          <th>G Score</th>\n"
        "          <th>C Score</th>\n"
        "          <th>G Kills</th>\n"
        "          <th>C Kills</th>\n"
        "          <th>G Creatures</th>\n"
        "          <th>C Creatures</th>\n"
        "          <th>G Projectiles</th>\n"
        "          <th>C Projectiles</th>\n"
        "        </tr>\n"
        "      </thead>\n"
        "      <tbody>\n"
        f"{rows_html}\n"
        "      </tbody>\n"
        "    </table>\n"
        "  </div>\n"
        "</body>\n"
        "</html>\n"
    )


def write_viz_html(
    *,
    golden_trace: Path,
    candidate_trace: Path,
    policy: ParityPolicy,
    tick: int | None = None,
    window_before: int = 64,
    window_after: int = 64,
    out_path: Path,
) -> dict[str, object]:
    focus_tick = (
        int(tick)
        if tick is not None
        else _default_focus_tick(
            golden_trace=Path(golden_trace),
            candidate_trace=Path(candidate_trace),
            policy=policy,
        )
    )
    left = int(focus_tick) - max(0, int(window_before))
    right = int(focus_tick) + max(0, int(window_after))
    rows = _timeline_rows(
        golden_trace=Path(golden_trace),
        candidate_trace=Path(candidate_trace),
        tick_start=left,
        tick_end=right,
    )
    payload: dict[str, object] = {
        "golden_trace": str(golden_trace),
        "candidate_trace": str(candidate_trace),
        "focus_tick": int(focus_tick),
        "tick_start": int(left),
        "tick_end": int(right),
        "row_count": int(len(rows)),
        "rows": rows,
    }
    html_text = _render_html(payload=payload)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_text, encoding="utf-8")
    payload["html_path"] = str(out)
    return payload
