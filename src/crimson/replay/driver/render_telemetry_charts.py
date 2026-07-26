from __future__ import annotations

import html
import importlib
import json
import math
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol, cast

import msgspec


class _TelemetryFrameLike(Protocol):
    @property
    def tick_index_after_update(self) -> int: ...

    @property
    def frame_ms(self) -> float: ...

    @property
    def update_ms(self) -> float: ...

    @property
    def draw_ms(self) -> float: ...

    @property
    def draw_calls_total(self) -> int: ...

    @property
    def pass_ms(self) -> dict[str, float]: ...


class _TelemetryFrame(msgspec.Struct, frozen=True):
    tick_index_after_update: int
    frame_ms: float
    update_ms: float
    draw_ms: float
    draw_calls_total: int
    pass_ms: dict[str, float]


_TIMING_COLORS = ("#4E79A7", "#F28E2B", "#E15759")
_DRAW_CALLS_COLOR = "#59A14F"
_PASS_SCHEME = "tableau20"
_PASS_TOP_N = 8
_PASS_STACK_MAX_POINTS = 1800
_PASS_CHILDREN_BY_PARENT: dict[str, frozenset[str]] = {
    "projectiles_effects": frozenset(
        {
            "laser_sight",
            "primary_projectiles",
            "particle_pool",
            "secondary_projectiles",
            "sprite_effect_pool",
            "effect_pool",
        },
    ),
    "bonus_ui": frozenset(
        {
            "bonus_pickups",
            "bonus_labels",
            "aim_indicators",
            "direction_arrows",
            "aim_enhancements",
        },
    ),
}


class _PassChartMeta(msgspec.Struct, frozen=True):
    pass_names: list[str]
    source_frames: int
    binned_points: int
    bin_size: int


def write_render_telemetry_charts(
    *,
    frames: Sequence[_TelemetryFrameLike],
    out_dir: Path,
    telemetry_json_path: Path | None = None,
) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    frame_timing_path = out / "frame_timing.svg"
    draw_calls_path = out / "draw_calls.svg"
    pass_timing_path = out / "pass_timing_stacked.svg"
    report_path = out / "report.md"

    frame_rows = [_frame_row(frame) for frame in list(frames)]
    _write_frame_timing_svg(frame_timing_path, frame_rows)
    _write_draw_calls_svg(draw_calls_path, frame_rows)
    pass_meta = _write_pass_timing_svg(pass_timing_path, frame_rows)
    _write_report_md(
        report_path,
        telemetry_json_path=telemetry_json_path,
        frame_timing=frame_timing_path,
        draw_calls=draw_calls_path,
        pass_timing=pass_timing_path,
        pass_names=pass_meta.pass_names,
        frame_count=len(frame_rows),
        pass_source_frames=pass_meta.source_frames,
        pass_binned_points=pass_meta.binned_points,
        pass_bin_size=pass_meta.bin_size,
    )

    return {
        "frame_timing_svg": frame_timing_path,
        "draw_calls_svg": draw_calls_path,
        "pass_timing_stacked_svg": pass_timing_path,
        "report_md": report_path,
    }


def write_render_telemetry_charts_from_json(
    *,
    telemetry_json_path: Path,
    out_dir: Path,
) -> dict[str, Path]:
    payload = json.loads(Path(telemetry_json_path).read_text(encoding="utf-8"))
    frames_payload = payload.get("frames")
    if not isinstance(frames_payload, list):
        raise TypeError("telemetry json is missing a frames list")
    frames: list[_TelemetryFrame] = []
    for entry in frames_payload:
        if not isinstance(entry, dict):
            continue
        frame = _TelemetryFrame(
            tick_index_after_update=int(entry.get("tick_index_after_update", 0)),
            frame_ms=float(entry.get("frame_ms", 0.0)),
            update_ms=float(entry.get("update_ms", 0.0)),
            draw_ms=float(entry.get("draw_ms", 0.0)),
            draw_calls_total=int(entry.get("draw_calls_total", 0)),
            pass_ms={str(k): float(v) for k, v in cast(dict[str, Any], entry.get("pass_ms", {})).items()},
        )
        frames.append(frame)
    return write_render_telemetry_charts(
        frames=frames,
        out_dir=out_dir,
        telemetry_json_path=Path(telemetry_json_path),
    )


def _frame_row(frame: _TelemetryFrameLike) -> dict[str, Any]:
    return {
        "tick_index": int(frame.tick_index_after_update),
        "frame_ms": float(frame.frame_ms),
        "update_ms": float(frame.update_ms),
        "draw_ms": float(frame.draw_ms),
        "draw_calls_total": int(frame.draw_calls_total),
        "pass_ms": {str(name): float(value) for name, value in frame.pass_ms.items()},
    }


def _write_frame_timing_svg(path: Path, frames: list[dict[str, Any]]) -> None:
    if not frames:
        _write_empty_svg(path, title="Per-tick frame timing (ms)")
        return

    rows: list[dict[str, Any]] = []
    for frame in frames:
        rows.extend(
            (
                {"tick_index": int(frame["tick_index"]), "metric": "frame_ms", "value": float(frame["frame_ms"])},
                {"tick_index": int(frame["tick_index"]), "metric": "update_ms", "value": float(frame["update_ms"])},
                {"tick_index": int(frame["tick_index"]), "metric": "draw_ms", "value": float(frame["draw_ms"])},
            ),
        )

    alt = _load_altair()
    chart = (
        alt.Chart(alt.Data(values=rows))
        .mark_line(clip=True, strokeWidth=0.5, interpolate="step-after")
        .encode(
            x=alt.X("tick_index:Q", title="Tick"),
            y=alt.Y("value:Q", title="Milliseconds"),
            color=alt.Color(
                "metric:N",
                title="Metric",
                scale=alt.Scale(
                    domain=["frame_ms", "update_ms", "draw_ms"],
                    range=list(_TIMING_COLORS),
                ),
            ),
            tooltip=[
                alt.Tooltip("tick_index:Q", title="Tick"),
                alt.Tooltip("metric:N", title="Metric"),
                alt.Tooltip("value:Q", title="ms", format=".3f"),
            ],
        )
        .properties(width=1180, height=360, title="Per-tick frame timing (ms)")
    )
    _save_svg(path=path, chart=chart)


def _write_draw_calls_svg(path: Path, frames: list[dict[str, Any]]) -> None:
    if not frames:
        _write_empty_svg(path, title="Per-tick draw calls")
        return

    rows = [
        {"tick_index": int(frame["tick_index"]), "draw_calls_total": int(frame["draw_calls_total"])} for frame in frames
    ]
    alt = _load_altair()
    chart = (
        alt.Chart(alt.Data(values=rows))
        .mark_line(clip=True, color=_DRAW_CALLS_COLOR, strokeWidth=0.5, interpolate="step-after")
        .encode(
            x=alt.X("tick_index:Q", title="Tick"),
            y=alt.Y("draw_calls_total:Q", title="Draw calls"),
            tooltip=[
                alt.Tooltip("tick_index:Q", title="Tick"),
                alt.Tooltip("draw_calls_total:Q", title="Draw calls"),
            ],
        )
        .properties(width=1180, height=360, title="Per-tick draw calls")
    )
    _save_svg(path=path, chart=chart)


def _write_pass_timing_svg(path: Path, frames: list[dict[str, Any]]) -> _PassChartMeta:
    if not frames:
        _write_empty_svg(path, title="Per-tick pass timing (stacked exclusive ms)")
        return _PassChartMeta(pass_names=[], source_frames=0, binned_points=0, bin_size=1)

    pass_totals: dict[str, float] = {}
    for frame in frames:
        exclusive_pass_ms = _exclusive_pass_ms(cast(dict[str, float], frame["pass_ms"]))
        for pass_name, pass_ms in exclusive_pass_ms.items():
            pass_totals[str(pass_name)] = pass_totals.get(str(pass_name), 0.0) + float(pass_ms)

    ordered_passes = [name for name, _total in sorted(pass_totals.items(), key=lambda item: item[1], reverse=True)]
    selected_passes = ordered_passes[:_PASS_TOP_N]
    include_other = len(ordered_passes) > len(selected_passes)

    if include_other:
        selected_passes = [*selected_passes, "other"]

    rows, binned_points, bin_size = _build_binned_pass_rows(
        frames=frames,
        selected_passes=selected_passes,
        include_other=include_other,
    )
    if not rows:
        _write_empty_svg(path, title="Per-tick pass timing (stacked exclusive ms)")
        return _PassChartMeta(
            pass_names=selected_passes,
            source_frames=len(frames),
            binned_points=0,
            bin_size=max(1, int(bin_size)),
        )

    alt = _load_altair()
    chart = (
        alt.Chart(alt.Data(values=rows))
        .mark_area(clip=True, opacity=0.9, interpolate="step-after")
        .encode(
            x=alt.X("tick_index:Q", title="Tick"),
            y=alt.Y("pass_ms:Q", title="Milliseconds", stack="zero"),
            color=alt.Color(
                "pass_name:N",
                title="Pass",
                sort=selected_passes,
                scale=alt.Scale(scheme=_PASS_SCHEME),
            ),
            tooltip=[
                alt.Tooltip("tick_index:Q", title="Tick"),
                alt.Tooltip("tick_start:Q", title="Tick start"),
                alt.Tooltip("tick_end:Q", title="Tick end"),
                alt.Tooltip("frames_in_bin:Q", title="Frames"),
                alt.Tooltip("pass_name:N", title="Pass"),
                alt.Tooltip("pass_ms:Q", title="ms", format=".3f"),
            ],
        )
        .properties(width=1180, height=360, title="Per-tick pass timing (stacked exclusive ms)")
    )
    _save_svg(path=path, chart=chart)
    return _PassChartMeta(
        pass_names=selected_passes,
        source_frames=len(frames),
        binned_points=int(binned_points),
        bin_size=int(bin_size),
    )


def _build_binned_pass_rows(
    *,
    frames: list[dict[str, Any]],
    selected_passes: list[str],
    include_other: bool,
) -> tuple[list[dict[str, Any]], int, int]:
    frame_count = len(frames)
    if frame_count <= 0:
        return [], 0, 1

    bin_size = max(1, int(math.ceil(float(frame_count) / float(_PASS_STACK_MAX_POINTS))))
    rows: list[dict[str, Any]] = []
    for start_idx in range(0, frame_count, bin_size):
        chunk = frames[start_idx : start_idx + bin_size]
        if not chunk:
            continue
        frames_in_bin = len(chunk)
        tick_start = int(chunk[0]["tick_index"])
        tick_end = int(chunk[-1]["tick_index"])
        tick_index = (float(tick_start) + float(tick_end)) / 2.0
        sums: dict[str, float] = {name: 0.0 for name in selected_passes}
        for frame in chunk:
            pass_ms = _exclusive_pass_ms(cast(dict[str, float], frame["pass_ms"]))
            other_total = 0.0
            for pass_name, value in pass_ms.items():
                numeric_value = float(value)
                if pass_name in sums:
                    sums[pass_name] += numeric_value
                else:
                    other_total += numeric_value
            if include_other:
                sums["other"] = sums.get("other", 0.0) + other_total
        for pass_name, total in sums.items():
            mean_value = float(total) / float(frames_in_bin)
            if mean_value <= 0.0:
                continue
            rows.append(
                {
                    "tick_index": tick_index,
                    "tick_start": tick_start,
                    "tick_end": tick_end,
                    "frames_in_bin": int(frames_in_bin),
                    "pass_name": pass_name,
                    "pass_ms": mean_value,
                },
            )

    binned_points = int(math.ceil(float(frame_count) / float(bin_size)))
    return rows, binned_points, int(bin_size)


def _exclusive_pass_ms(pass_ms: dict[str, float]) -> dict[str, float]:
    if not pass_ms:
        return {}

    exclusive = {str(name): float(value) for name, value in pass_ms.items()}
    for parent, children in _PASS_CHILDREN_BY_PARENT.items():
        parent_value = exclusive.get(parent)
        if parent_value is None:
            continue
        child_total = 0.0
        for child in children:
            child_total += float(exclusive.get(child, 0.0))
        exclusive[parent] = max(0.0, float(parent_value) - float(child_total))
    return exclusive


def _load_altair() -> Any:
    try:
        alt = importlib.import_module("altair")
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(
            "render telemetry chart generation requires optional dependency group `charts`; "
            "run `uv sync --extra charts`",
        ) from exc
    alt.data_transformers.disable_max_rows()
    return alt


def _save_svg(*, path: Path, chart: Any) -> None:
    chart.save(str(path))


def _write_empty_svg(path: Path, *, title: str) -> None:
    payload = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="200" viewBox="0 0 800 200">\n'
        '<rect width="100%" height="100%" fill="#ffffff"/>\n'
        f'<text x="16" y="24" font-size="14" font-family="monospace">{html.escape(title)}</text>\n'
        '<text x="16" y="48" font-size="12" font-family="monospace">No telemetry frames available.</text>\n'
        "</svg>\n"
    )
    path.write_text(payload, encoding="utf-8")


def _write_report_md(
    path: Path,
    *,
    telemetry_json_path: Path | None,
    frame_timing: Path,
    draw_calls: Path,
    pass_timing: Path,
    pass_names: list[str],
    frame_count: int,
    pass_source_frames: int,
    pass_binned_points: int,
    pass_bin_size: int,
) -> None:
    lines = [
        "# Replay Render Telemetry Report",
        "",
        "## Artifacts",
        f"- Frame timing: `{frame_timing.name}`",
        f"- Draw calls: `{draw_calls.name}`",
        f"- Pass timing (stacked, exclusive): `{pass_timing.name}`",
        f"- Frame count: `{int(frame_count)}`",
        f"- Passes shown in stack: `{', '.join(pass_names) if pass_names else 'none'}`",
        (
            f"- Pass stack binning: `{int(pass_source_frames)} source frames -> "
            f"{int(pass_binned_points)} bins (bin_size={int(pass_bin_size)})`"
        ),
    ]
    if telemetry_json_path is not None:
        lines.append(f"- Full telemetry JSON: `{telemetry_json_path}`")
    lines.append("")
    lines.append("Generated with Altair/Vega-Lite. Open the SVG files directly in a browser for inspection.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


__all__ = ["write_render_telemetry_charts", "write_render_telemetry_charts_from_json"]
