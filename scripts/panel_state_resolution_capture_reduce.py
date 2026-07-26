#!/usr/bin/env python3
"""
Reduce panel_state_resolution_capture_*.jsonl files into a compact triage summary.

Defaults:
  input glob: artifacts/frida/share/panel_state_resolution_capture_*.jsonl
  json out:   analysis/frida/panel_state_resolution_capture_summary.json
  md out:     analysis/frida/panel_state_resolution_capture_report.md
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import msgspec

RESOLUTION_RE = re.compile(r"_(\d+)x(\d+)_")
DEFAULT_INPUT_GLOB = "artifacts/frida/share/panel_state_resolution_capture_*.jsonl"
DEFAULT_JSON_OUT = Path("analysis/frida/panel_state_resolution_capture_summary.json")
DEFAULT_MD_OUT = Path("analysis/frida/panel_state_resolution_capture_report.md")


def _now_iso() -> str:
    import datetime as _dt

    return _dt.datetime.now(tz=_dt.UTC).isoformat()


def _as_int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        txt = v.strip()
        if not txt:
            return None
        try:
            if txt.startswith(("0x", "0X")):
                return int(txt, 16)
            return int(txt, 10)
        except ValueError:
            return None
    return None


def _resolution_key_from_obj(obj: dict[str, Any]) -> str | None:
    res = obj.get("resolution")
    if not isinstance(res, dict):
        return None
    w = _as_int(res.get("w"))
    h = _as_int(res.get("h"))
    if w is None or h is None:
        return None
    return f"{w}x{h}"


def _resolution_key_from_name(path: Path) -> str | None:
    m = RESOLUTION_RE.search(path.name)
    if not m:
        return None
    return f"{int(m.group(1))}x{int(m.group(2))}"


def _state_label_key(state_id: int | None, label: str | None) -> str:
    sid = "?" if state_id is None else str(state_id)
    if label:
        return f"{sid}:{label}"
    return sid


def _line_count(path: Path) -> int:
    n = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for _ in fh:
            n += 1
    return n


class StateResult(msgspec.Struct, forbid_unknown_fields=True):
    target_state: int | None
    target_label: str | None
    result: str
    frames: int
    unique_panel_count: int
    unique_text_count: int
    panel_duplicates: int
    text_duplicates: int


class FileSummary(msgspec.Struct, forbid_unknown_fields=True):
    path: str
    size_bytes: int
    line_count: int
    run_id: str | None
    resolution: str | None
    event_counts: dict[str, int]
    state_results: list[StateResult]
    has_sweep_done: bool
    output_files: dict[str, str]
    config_max_unique_texts: int | None
    text_rows: int
    text_rows_with_replacement_char: int
    status: str
    notes: list[str]

class StateResultOverview(msgspec.Struct, forbid_unknown_fields=True):
    states_total: int
    result_counts: dict[str, int]
    non_captured_states: list[str]
    zero_signal_captured_states: list[str]
    max_unique_text_count_seen: int


class PrimaryResolutionSummary(msgspec.Struct, forbid_unknown_fields=True):
    path: str
    status: str
    line_count: int
    size_bytes: int
    state_overview: StateResultOverview
    notes: list[str]


class RunSummary(msgspec.Struct, forbid_unknown_fields=True):
    run_id: str
    status: str
    files: list[FileSummary]
    expected_output_files: dict[str, str]
    resolutions: list[str]
    primary_by_resolution: dict[str, PrimaryResolutionSummary]


class BestResolutionSummary(msgspec.Struct, forbid_unknown_fields=True):
    run_id: str
    status: str
    path: str | None
    line_count: int
    size_bytes: int
    state_overview: StateResultOverview | None


class PanelStateResolutionSummary(msgspec.Struct, forbid_unknown_fields=True):
    generated_at: str
    input_glob: str
    files_scanned: int
    runs_detected: int
    file_status_counts: dict[str, int]
    runs: list[RunSummary]
    best_by_resolution: dict[str, BestResolutionSummary]


def _normalize_state_result(obj: dict[str, Any]) -> StateResult:
    return StateResult(
        target_state=_as_int(obj.get("target_state")),
        target_label=(obj.get("target_label") if isinstance(obj.get("target_label"), str) else None),
        result=str(obj.get("result") or ""),
        frames=(_as_int(obj.get("frames")) or 0),
        unique_panel_count=(_as_int(obj.get("unique_panel_count")) or 0),
        unique_text_count=(_as_int(obj.get("unique_text_count")) or 0),
        panel_duplicates=(_as_int(obj.get("panel_duplicates")) or 0),
        text_duplicates=(_as_int(obj.get("text_duplicates")) or 0),
    )


def _parse_file(path: Path) -> FileSummary:
    event_counts: Counter[str] = Counter()
    run_id_counts: Counter[str] = Counter()
    resolution_counts: Counter[str] = Counter()
    state_results: list[StateResult] = []
    sweep_done_results: list[StateResult] = []
    has_sweep_done = False
    output_files: dict[str, str] = {}
    config_max_unique_texts: int | None = None
    text_rows = 0
    text_rows_with_replacement_char = 0

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                event_counts["json_error"] += 1
                continue

            evt = obj.get("event")
            if isinstance(evt, str):
                event_counts[evt] += 1

            rid = obj.get("run_id")
            if isinstance(rid, str):
                run_id_counts[rid] += 1

            res_key = _resolution_key_from_obj(obj)
            if res_key is not None:
                resolution_counts[res_key] += 1

            if evt == "start":
                cfg = obj.get("config")
                if isinstance(cfg, dict):
                    max_text = _as_int(cfg.get("maxUniqueTextsPerState"))
                    if max_text is not None and max_text > 0:
                        config_max_unique_texts = max_text

            if evt == "panel_text":
                text_rows += 1
                txt = obj.get("text")
                if isinstance(txt, str) and "\ufffd" in txt:
                    text_rows_with_replacement_char += 1

            if evt == "state_result":
                state_results.append(_normalize_state_result(obj))

            if evt == "sweep_done":
                has_sweep_done = True
                maybe = obj.get("results")
                if isinstance(maybe, list):
                    sweep_done_results = [
                        _normalize_state_result(row)
                        for row in maybe
                        if isinstance(row, dict)
                    ]
                outs = obj.get("output_files")
                if isinstance(outs, dict):
                    output_files = {
                        str(k): str(v)
                        for k, v in outs.items()
                        if isinstance(k, str) and isinstance(v, str)
                    }

    if not state_results and sweep_done_results:
        state_results = sweep_done_results

    run_id: str | None = None
    if run_id_counts:
        run_id = run_id_counts.most_common(1)[0][0]

    resolution = _resolution_key_from_name(path)
    if resolution is None and resolution_counts:
        resolution = resolution_counts.most_common(1)[0][0]

    result_counts = Counter(row.result for row in state_results)
    captured_count = int(result_counts.get("captured", 0))
    non_captured = [row for row in state_results if row.result != "captured"]
    zero_signal_states = [
        row
        for row in state_results
        if row.result == "captured"
        and int(row.frames) == 0
        and int(row.unique_panel_count) == 0
        and int(row.unique_text_count) == 0
    ]
    max_unique_text = config_max_unique_texts if config_max_unique_texts is not None else 1800
    maxed_text_states = [
        row
        for row in state_results
        if int(row.unique_text_count) >= max_unique_text
    ]

    notes: list[str] = []
    event_keys = set(event_counts)
    if (not has_sweep_done) and event_keys.issubset({"start", "boot_detected"}):
        notes.append("startup-handoff-only")
    if not has_sweep_done and "sweep_begin" in event_keys:
        notes.append("sweep-began-without-sweep_done")
    if int(event_counts.get("error", 0)) > 0:
        notes.append(f"error-events:{int(event_counts['error'])}")
    if zero_signal_states:
        notes.append(f"zero-signal-captured-states:{len(zero_signal_states)}")
    if maxed_text_states:
        notes.append(f"max-unique-text-cap-states:{len(maxed_text_states)}")
    if text_rows > 0 and text_rows_with_replacement_char > 0:
        notes.append(f"text-rows-with-replacement-char:{text_rows_with_replacement_char}/{text_rows}")

    status: str
    if not has_sweep_done or not state_results:
        status = "partial"
    elif non_captured or zero_signal_states:
        status = "degraded"
    elif captured_count == len(state_results):
        status = "complete"
    else:
        status = "degraded"

    return FileSummary(
        path=str(path),
        size_bytes=int(path.stat().st_size),
        line_count=_line_count(path),
        run_id=run_id,
        resolution=resolution,
        event_counts={k: int(v) for k, v in sorted(event_counts.items(), key=lambda kv: kv[0])},
        state_results=state_results,
        has_sweep_done=has_sweep_done,
        output_files=output_files,
        config_max_unique_texts=config_max_unique_texts,
        text_rows=text_rows,
        text_rows_with_replacement_char=text_rows_with_replacement_char,
        status=status,
        notes=notes,
    )


def _status_rank(status: str) -> int:
    if status == "complete":
        return 3
    if status == "degraded":
        return 2
    return 1


def _primary_file_for_resolution(files: list[FileSummary], resolution: str) -> FileSummary | None:
    candidates = [f for f in files if f.resolution == resolution]
    if not candidates:
        return None
    candidates.sort(
        key=lambda f: (
            _status_rank(f.status),
            1 if f.has_sweep_done else 0,
            len(f.state_results),
            f.line_count,
            f.size_bytes,
        ),
        reverse=True,
    )
    return candidates[0]


def _state_result_overview(state_results: list[StateResult]) -> StateResultOverview:
    result_counts = Counter(str(row.result) for row in state_results)
    non_captured = [
        _state_label_key(row.target_state, row.target_label)
        for row in state_results
        if row.result != "captured"
    ]
    zero_signal = [
        _state_label_key(row.target_state, row.target_label)
        for row in state_results
        if row.result == "captured"
        and int(row.frames) == 0
        and int(row.unique_panel_count) == 0
        and int(row.unique_text_count) == 0
    ]
    max_unique_text = max((int(row.unique_text_count) for row in state_results), default=0)
    return StateResultOverview(
        states_total=len(state_results),
        result_counts={k: int(v) for k, v in sorted(result_counts.items(), key=lambda kv: kv[0])},
        non_captured_states=non_captured,
        zero_signal_captured_states=zero_signal,
        max_unique_text_count_seen=int(max_unique_text),
    )


def _run_summary(run_id: str, files: list[FileSummary]) -> RunSummary:
    output_files: dict[str, str] = {}
    for f in files:
        for res_key, out_path in f.output_files.items():
            output_files[res_key] = out_path

    resolutions = sorted({res for f in files if f.resolution is not None for res in [f.resolution]}, key=_resolution_sort_key)
    primary: dict[str, FileSummary] = {}
    for res in resolutions:
        picked = _primary_file_for_resolution(files, res)
        if picked is not None:
            primary[res] = picked

    if not primary:
        run_status = "partial"
    elif any(f.status == "degraded" for f in primary.values()):
        run_status = "degraded"
    elif all(f.status == "complete" for f in primary.values()):
        run_status = "complete"
    else:
        run_status = "partial"

    return RunSummary(
        run_id=str(run_id),
        status=str(run_status),
        files=sorted(files, key=lambda x: x.path),
        expected_output_files=output_files,
        resolutions=resolutions,
        primary_by_resolution={
            res: PrimaryResolutionSummary(
                path=primary_file.path,
                status=primary_file.status,
                line_count=int(primary_file.line_count),
                size_bytes=int(primary_file.size_bytes),
                state_overview=_state_result_overview(primary_file.state_results),
                notes=list(primary_file.notes),
            )
            for res, primary_file in sorted(primary.items(), key=lambda kv: _resolution_sort_key(kv[0]))
        },
    )


def _resolution_sort_key(res: str) -> tuple[int, int]:
    if "x" not in res:
        return (1 << 30, 1 << 30)
    try:
        w_txt, h_txt = res.split("x", 1)
        return (int(w_txt), int(h_txt))
    except ValueError:
        return (1 << 30, 1 << 30)


def _best_by_resolution(run_summaries: list[RunSummary]) -> dict[str, BestResolutionSummary]:
    out: dict[str, BestResolutionSummary] = {}
    for run in run_summaries:
        for res, item in run.primary_by_resolution.items():
            candidate = BestResolutionSummary(
                run_id=str(run.run_id),
                status=str(item.status),
                path=item.path,
                line_count=int(item.line_count),
                size_bytes=int(item.size_bytes),
                state_overview=item.state_overview,
            )
            cur = out.get(res)
            if cur is None:
                out[res] = candidate
                continue
            cand_key = (
                _status_rank(candidate.status),
                int(candidate.line_count),
                int(candidate.size_bytes),
            )
            cur_key = (
                _status_rank(str(cur.status)),
                int(cur.line_count),
                int(cur.size_bytes),
            )
            if cand_key > cur_key:
                out[res] = candidate
    return {res: out[res] for res in sorted(out, key=_resolution_sort_key)}


def _render_markdown(summary: PanelStateResolutionSummary) -> str:
    lines: list[str] = []
    lines.append("# Panel state resolution capture report")
    lines.append("")
    lines.append("- issue: `#165` (support all resolutions)")
    lines.append(f"- input_glob: `{summary.input_glob}`")
    lines.append(f"- files_scanned: `{summary.files_scanned}`")
    lines.append(f"- runs_detected: `{summary.runs_detected}`")
    lines.append("")

    file_status_counts = summary.file_status_counts
    lines.append("## File triage")
    lines.append(f"- complete: `{int(file_status_counts.get('complete', 0))}`")
    lines.append(f"- degraded: `{int(file_status_counts.get('degraded', 0))}`")
    lines.append(f"- partial: `{int(file_status_counts.get('partial', 0))}`")
    lines.append("")

    lines.append("## Runs")
    for run in summary.runs:
        run_id = str(run.run_id)
        status = str(run.status)
        lines.append(f"### `{run_id}` ({status})")
        for file_obj in sorted(run.files, key=lambda f: str(f.path)):
            note_suffix = f" ({', '.join(str(n) for n in file_obj.notes)})" if file_obj.notes else ""
            lines.append(f"- `{file_obj.path}`: {file_obj.status}, lines={file_obj.line_count}{note_suffix}")

        primary = run.primary_by_resolution
        if primary:
            lines.append("- primary by resolution:")
            for res in sorted(primary, key=_resolution_sort_key):
                item = primary[res]
                ov = item.state_overview
                states_total = int(ov.states_total)
                captured = int(ov.result_counts.get("captured", 0))
                non_captured_count = len(ov.non_captured_states)
                zero_signal_count = len(ov.zero_signal_captured_states)
                lines.append(
                    f"  - `{res}`: {item.status}, captured={captured}/{states_total}, "
                    f"non_captured={non_captured_count}, zero_signal={zero_signal_count}",
                )
        lines.append("")

    lines.append("## Best Coverage By Resolution")
    best = summary.best_by_resolution
    if best:
        lines.append("| resolution | status | run_id | captured/total | non-captured | zero-signal | file |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for res in sorted(best, key=_resolution_sort_key):
            item = best[res]
            ov = item.state_overview
            states_total = 0 if ov is None else int(ov.states_total)
            captured = 0 if ov is None else int(ov.result_counts.get("captured", 0))
            non_captured_count = 0 if ov is None else len(ov.non_captured_states)
            zero_signal_count = 0 if ov is None else len(ov.zero_signal_captured_states)
            lines.append(
                f"| `{res}` | `{item.status}` | `{item.run_id}` | `{captured}/{states_total}` | "
                f"`{non_captured_count}` | `{zero_signal_count}` | `{item.path or ''}` |",
            )
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Notes")
    lines.append("- `partial` files with only `start`/`boot_detected` are typical handoff artifacts when the launcher resolution changes after attach.")
    lines.append("- `degraded` files indicate sweep completion with one or more non-captured states or captured states with zero panel/text/frame signal.")
    lines.append("- High `text_rows_with_replacement_char` usually means trailing garbage in text extraction and should not be treated as literal UI strings.")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reduce panel-state resolution sweep captures.")
    parser.add_argument(
        "--glob",
        type=str,
        default=DEFAULT_INPUT_GLOB,
        help=f"Input file glob (default: {DEFAULT_INPUT_GLOB})",
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=DEFAULT_JSON_OUT,
        help=f"Summary JSON output path (default: {DEFAULT_JSON_OUT})",
    )
    parser.add_argument(
        "--out-md",
        type=Path,
        default=DEFAULT_MD_OUT,
        help=f"Markdown report output path (default: {DEFAULT_MD_OUT})",
    )
    args = parser.parse_args(argv)

    files = sorted(Path().glob(args.glob))
    summaries = [_parse_file(path) for path in files]

    runs: dict[str, list[FileSummary]] = defaultdict(list)
    for file_summary in summaries:
        rid = file_summary.run_id or f"unknown:{Path(file_summary.path).name}"
        runs[rid].append(file_summary)

    run_summaries = [
        _run_summary(run_id, runs[run_id])
        for run_id in sorted(runs)
    ]

    file_status_counts = Counter(s.status for s in summaries)
    best_by_resolution = _best_by_resolution(run_summaries)

    summary = PanelStateResolutionSummary(
        generated_at=_now_iso(),
        input_glob=str(args.glob),
        files_scanned=len(summaries),
        runs_detected=len(run_summaries),
        file_status_counts={k: int(v) for k, v in sorted(file_status_counts.items(), key=lambda kv: kv[0])},
        runs=run_summaries,
        best_by_resolution=best_by_resolution,
    )

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_bytes(msgspec.json.encode(summary))

    md = _render_markdown(summary)
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text(md, encoding="utf-8")

    print(f"Wrote {args.out_json}")
    print(f"Wrote {args.out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
