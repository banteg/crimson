"""Client frame profiles (CRIMSON_PROFILE): record a run once, then slice the file.

    CRIMSON_PROFILE=run.jsonl CRIMSON_WATCH=replays/run.crd crimson-core/build/app/crimson <game folder>
    uv run python tools/profile.py summary run.jsonl [--ticks 39000:51000] [--by 2000]
    uv run python tools/profile.py worst run.jsonl [--count 10] [--key gpu.ground]
    uv run python tools/profile.py compare before.jsonl after.jsonl [--ticks 39000:51000]
    uv run python tools/profile.py timeline run.jsonl --out run.html

A profile is a JSON line for the run, then one per frame the client showed: the replay tick it drew and the ticks it
covered, the wall time since the last frame, the game's live entities, the process's memory, each pass's CPU time
(from its mark to the next) and, on timed frames, GPU time (timer queries read once finished), the draws
by pass, texture and target as [quads, pixels], the scene's sizes and the targets (crimson-core/client/main.cpp).

A replay recorded with no tick to stop at plays to its end; CRIMSON_WATCH_MOMENTS records only its moments, each
with CRIMSON_WATCH_WINDOW ticks of history. Frames before playback (the preparing pass) and the jumps between
moments are left out unless --all keeps them. A key names a measure: wall, cpu, gpu (each pass's sum), cpu.<pass>,
gpu.<pass>, scene.<size>, entities.<kind>, rss. The GPU's `frame` pass spans the simulation's ticks, before anything
draws: it counts that time as idle GPU time, so the gpu sum leaves it out.

Timing the GPU costs the frame on macOS: ending or reading a timer query flushes the driver's command buffer, so a
timed GPU-bound frame waits in the pass after a costly one (whose CPU time then shows that wait) instead of at the
swap, and runs slower (about 4 ms a late-game frame). The client times every 8th frame (CRIMSON_PROFILE_GPU=<n>, 0
for none, 1 for all): GPU measures come from the timed frames. A timed frame drains the GPU and the frames after it
make that up, so wall and CPU measures are each run of 8 frames' mean (within a few percent of an untimed run's),
while `worst` and the timeline's worst wall time rank single untimed frames.
"""

import argparse
import html
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np

# A frame that moved playback further than this jumped (a seek between moments), rather than played.
PLAYED_TICKS = 8
COLORS = ["#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f", "#edc948", "#b07aa1", "#ff9da7", "#9c755f", "#bab0ac"]


@dataclass
class Profile:
    path: Path
    header: dict
    frames: list[dict]


def load(path: Path) -> Profile:
    lines = path.read_text().splitlines()
    # Older clients wrote a timed frame once its GPU time came, after the frames that followed it.
    frames = sorted((json.loads(line) for line in lines[1:] if line), key=lambda f: f["frame"])
    return Profile(path, json.loads(lines[0]), frames)


def ticks_range(text: str | None) -> tuple[float, float]:
    if not text:
        return -np.inf, np.inf
    lo, _, hi = text.partition(":")
    return float(lo) if lo else -np.inf, float(hi) if hi else np.inf


def played(profile: Profile, args: argparse.Namespace) -> list[dict]:
    """The frames playback drew, within --ticks: a replay's, once prepared, and none that jumped."""
    every = profile.header.get("gpu_every", 1)
    frames = [{**f, "every": every} for f in profile.frames]
    if not args.all and any(f["tick"] >= 0 for f in frames):
        frames = [f for f in frames if f["tick"] >= 0 and 0 <= f["ticks"] <= PLAYED_TICKS and f["wall"] > 0]
    lo, hi = ticks_range(args.ticks)
    return [f for f in frames if lo <= f["tick"] <= hi]


def measured(frames: list[dict], key: str, *, spikes: bool = False) -> list[dict]:
    """The frames that measure `key`: the GPU's on timed frames; the rest over runs of frames that each hold one
    timed frame, as their means (a timed frame drains the GPU and the frames after it make that up), or with
    `spikes` on single untimed frames."""
    if key == "gpu" or key.startswith("gpu."):
        return [f for f in frames if "gpu" in f]
    every = max(1, frames[0].get("every", 1)) if frames else 1
    if every == 1 or not any(f.get("timed") for f in frames):
        return frames
    if spikes:
        return [f for f in frames if not f.get("timed")]
    runs: dict[int, list[dict]] = {}
    for f in frames:
        runs.setdefault(f["frame"] // every, []).append(f)
    means = []
    for run in runs.values():
        if len(run) < every:
            continue
        cpu: dict[str, float] = {}
        for f in run:
            for name, ms in f["cpu"].items():
                cpu[name] = cpu.get(name, 0.0) + ms / every
        means.append({**run[-1], "wall": sum(f["wall"] for f in run) / every, "cpu": cpu, "timed": False})
    return means


def value(frame: dict, key: str) -> float:
    if key == "wall" or key == "rss":
        return frame[key]
    if key == "cpu":
        return sum(frame["cpu"].values())
    if key == "gpu":
        return sum(ms for name, ms in frame.get("gpu", {}).items() if name != "frame")
    group, _, name = key.partition(".")
    return frame.get(group, {}).get(name, 0.0)


def keys(frames: list[dict], group: str) -> list[str]:
    """A group's names, the costliest first."""
    totals: dict[str, float] = {}
    for f in frames:
        for name, ms in f.get(group, {}).items():
            if not (group == "gpu" and name == "frame"):
                totals[name] = totals.get(name, 0.0) + ms
    return [f"{group}.{name}" for name, _ in sorted(totals.items(), key=lambda item: -item[1])]


def stats(values: np.ndarray) -> list[float]:
    return [values.mean(), *np.percentile(values, [50, 90, 99]), values.max()] if len(values) else [np.nan] * 5


def describe(profile: Profile, frames: list[dict]) -> str:
    h = profile.header
    ticks = [f["tick"] for f in frames if f["tick"] >= 0]
    span = f", ticks {min(ticks)}-{max(ticks)}" if ticks else ""
    every = h.get("gpu_every", 1)
    timers = f"GPU timed every {every} frames" if every > 1 else "GPU timed every frame" if every else "GPU untimed"
    return (
        f"{profile.path.name}: client {h['client']} ({h['platform']}), drawable {h['drawable'][0]}x{h['drawable'][1]}, "
        f"render size {h['render_size']}, {timers}, {h.get('watch') or 'live play'}; {len(frames)} frames{span}"
    )


def table(rows: list[list], header: list[str]) -> str:
    cells = [[f"{c:.2f}" if isinstance(c, float) else str(c) for c in row] for row in [header, *rows]]
    widths = [max(len(row[i]) for row in cells) for i in range(len(header))]
    return "\n".join(
        "  ".join(c.ljust(w) if i == 0 else c.rjust(w) for i, (c, w) in enumerate(zip(row, widths, strict=True)))
        for row in cells
    )


def summary(args: argparse.Namespace) -> None:
    profile = load(args.profile)
    frames = played(profile, args)
    print(describe(profile, frames))
    if args.by:
        rows = []
        for start in range(
            min(f["tick"] for f in frames) // args.by * args.by, max(f["tick"] for f in frames) + 1, args.by,
        ):
            chunk = [f for f in frames if start <= f["tick"] < start + args.by]
            if not chunk:
                continue
            gpu_top = keys(chunk, "gpu")[:1] or ["-"]
            cpu_top = keys(chunk, "cpu")[:1] or ["-"]
            rows.append(
                [
                    f"{start}-{start + args.by}",
                    len(chunk),
                    *[float(np.percentile([value(f, "wall") for f in measured(chunk, "wall")], q)) for q in (50, 90)],
                    *[float(np.median([value(f, k) for f in measured(chunk, k)])) for k in ("cpu", "gpu")],
                    gpu_top[0],
                    cpu_top[0],
                    int(np.mean([value(f, "entities.creatures") for f in chunk])),
                ],
            )
        print(
            table(
                rows,
                ["ticks", "frames", "wall p50", "wall p90", "cpu p50", "gpu p50", "top gpu", "top cpu", "creatures"],
            ),
        )
        return
    measures = ["wall", "cpu", "gpu", *keys(frames, "cpu"), *keys(frames, "gpu")]
    rows = [[k, *stats(np.array([value(f, k) for f in measured(frames, k)]))] for k in measures]
    print(table(rows, ["ms", "mean", "p50", "p90", "p99", "max"]))
    sizes = ["rss", *keys(frames, "entities"), *keys(frames, "scene")]
    rows = [[k, *stats(np.array([value(f, k) for f in frames]))] for k in sizes]
    print()
    print(table(rows, ["count", "mean", "p50", "p90", "p99", "max"]))


def top(frame: dict, group: str, n: int = 3) -> str:
    items = [(name, ms) for name, ms in frame.get(group, {}).items() if not (group == "gpu" and name == "frame")]
    return " ".join(f"{name} {ms:.1f}" for name, ms in sorted(items, key=lambda item: -item[1])[:n])


def worst(args: argparse.Namespace) -> None:
    profile = load(args.profile)
    frames = played(profile, args)
    print(describe(profile, frames))
    chosen = sorted(measured(frames, args.key, spikes=True), key=lambda f: -value(f, args.key))[: args.count]
    rows = [
        [
            f["frame"],
            f["tick"],
            f["wall"],
            value(f, "cpu"),
            value(f, "gpu"),
            top(f, "cpu"),
            top(f, "gpu"),
            f["entities"]["creatures"],
            f["scene"].get("lights", 0),
        ]
        for f in chosen
    ]
    print(table(rows, ["frame", "tick", "wall", "cpu", "gpu", "top cpu", "top gpu", "creatures", "lights"]))


def compare(args: argparse.Namespace) -> None:
    """Two profiles of the same replay, frame by frame on the ticks both drew (else as wholes)."""
    profiles = [load(args.before), load(args.after)]
    sides = [played(p, args) for p in profiles]
    for profile, frames in zip(profiles, sides, strict=True):
        print(describe(profile, frames))
    if len({p.header.get("gpu_every", 1) for p in profiles}) > 1:
        print("warning: the profiles timed the GPU on different shares of their frames")
    by_tick = [{f["tick"]: f for f in frames if f["tick"] >= 0} for frames in sides]
    common = sorted(set(by_tick[0]) & set(by_tick[1]))
    if common:
        sides = [[side[t] for t in common] for side in by_tick]
        print(f"{len(common)} ticks both drew")
    else:
        print("no ticks in common: comparing the frames as wholes")
    measures = ["wall", "cpu", "gpu"]
    for group in ("cpu", "gpu"):
        measures += [k for k in keys(sides[0] + sides[1], group) if k not in measures]
    rows = []
    for k in measures:
        a, b = (np.array([value(f, k) for f in measured(frames, k)]) for frames in sides)
        if not len(a) or not len(b):
            continue
        before, after = float(np.median(a)), float(np.median(b))
        change = f"{(after / before - 1) * 100:+.0f}%" if before > 0.05 else "-"
        rows.append(
            [k, before, after, after - before, change, float(np.percentile(a, 90)), float(np.percentile(b, 90))],
        )
    print(table(rows, ["ms (median)", "before", "after", "delta", "change", "before p90", "after p90"]))


def timeline(args: argparse.Namespace) -> None:
    """The run frame by frame: frame times, the GPU's passes stacked, and the crowd, as an HTML page."""
    profile = load(args.profile)
    frames = played(profile, args)
    # Frames in order, so the moments a profile skips between sit side by side; the axis names their ticks.
    width, buckets = 1400, min(700, len(frames))
    which = np.arange(len(frames)) * buckets // len(frames)

    bucket_of = {f["frame"]: int(b) for f, b in zip(frames, which, strict=True)}

    def series(key: str, reduce=np.mean, *, spikes: bool = False) -> np.ndarray:
        values: list[list[float]] = [[] for _ in range(buckets)]
        for f in measured(frames, key, spikes=spikes):
            values[bucket_of[f["frame"]]].append(value(f, key))
        return np.array([reduce(v) if v else np.nan for v in values])

    passes = keys(frames, "gpu")
    shown, rest = passes[:8], passes[8:]
    stacked = [series(k) for k in shown]
    if rest:
        stacked.append(sum(series(k) for k in rest))
    names = [k.removeprefix("gpu.") for k in shown] + (["other"] if rest else [])

    def panel(title: str, lines: list[tuple[str, np.ndarray, str]], stack: list[np.ndarray] | None = None) -> str:
        height = 220
        top = np.nanmax([np.nanmax(v) for _, v, _ in lines] + ([np.nansum(stack, axis=0).max()] if stack else []))
        top = top if top > 0 else 1

        def sx(b: float) -> float:
            return 50 + (width - 60) * b / max(1, buckets - 1)

        def sy(v: float) -> float:
            return height - 20 - (height - 40) * v / top

        parts = [f'<text x="50" y="14" class="t">{html.escape(title)}</text>']
        for frac in (0, 0.5, 1):
            y = sy(top * frac)
            parts.append(
                f'<line x1="50" x2="{width - 10}" y1="{y:.1f}" y2="{y:.1f}" class="g"/>'
                f'<text x="44" y="{y + 4:.1f}" class="a">{top * frac:.0f}</text>',
            )
        if stack:
            base = np.zeros(buckets)
            for i, layer in enumerate(stack):
                layer = np.nan_to_num(layer)
                upper = base + layer
                points = [f"{sx(b):.1f},{sy(upper[b]):.1f}" for b in range(buckets)]
                points += [f"{sx(b):.1f},{sy(base[b]):.1f}" for b in reversed(range(buckets))]
                parts.append(
                    f'<polygon points="{" ".join(points)}" fill="{COLORS[i % len(COLORS)]}" opacity="0.85">'
                    f"<title>{html.escape(names[i])}</title></polygon>",
                )
                base = upper
        for b in np.linspace(0, buckets - 1, 7).astype(int):
            f = frames[int(np.flatnonzero(which == b)[0])]
            parts.append(
                f'<text x="{sx(b):.1f}" y="{height - 4}" class="x">{f["tick"] if f["tick"] >= 0 else f["frame"]}</text>',
            )
        for name, v, color in lines:
            points = " ".join(f"{sx(b):.1f},{sy(v[b]):.1f}" for b in range(buckets) if not np.isnan(v[b]))
            parts.append(
                f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="1.5">'
                f"<title>{html.escape(name)}</title></polyline>",
            )
        labels = [(name, color) for name, _, color in lines] + (
            [(n, COLORS[i % len(COLORS)]) for i, n in enumerate(names)] if stack else []
        )
        legend = "".join(f'<span><i style="background:{c}"></i>{html.escape(n)}</span>' for n, c in labels)
        return (
            f'<div class="p"><svg viewBox="0 0 {width} {height}" width="100%">{"".join(parts)}</svg>'
            f'<div class="l">{legend}</div></div>'
        )

    axis = "tick" if frames and frames[0]["tick"] >= 0 else "frame"
    body = [
        panel(
            f"frame time, ms: the mean of frames drawn together, and their worst wall time (axis: {axis})",
            [
                ("wall", series("wall"), "#222"),
                ("wall max", series("wall", np.max, spikes=True), "#aaa"),
                ("cpu", series("cpu"), "#e15759"),
                ("gpu", series("gpu"), "#4e79a7"),
            ],
        ),
        panel("GPU passes, ms", [], stacked),
        panel(
            "CPU passes, ms",
            [
                (k.removeprefix("cpu."), series(k), COLORS[i % len(COLORS)])
                for i, k in enumerate(keys(frames, "cpu")[:6])
            ],
        ),
        panel(
            "crowd",
            [
                ("creatures", series("entities.creatures"), "#59a14f"),
                ("projectiles", series("entities.projectiles"), "#f28e2b"),
                ("lights", series("scene.lights"), "#edc948"),
                ("beams", series("scene.beams"), "#b07aa1"),
            ],
        ),
    ]
    page = f"""<!doctype html><meta charset="utf-8"><title>Profile timeline</title>
<style>body{{font:13px system-ui;margin:16px;color:#222;background:#fff}}.p{{margin-bottom:18px}}
.t{{font:600 13px system-ui}}.a{{font:10px system-ui;text-anchor:end;fill:#666}}.x{{font:10px system-ui;text-anchor:middle;fill:#666}}.g{{stroke:#eee}}
.l span{{margin-right:12px;white-space:nowrap}}.l i{{display:inline-block;width:10px;height:10px;margin-right:4px}}</style>
<h3>{html.escape(describe(profile, frames))}</h3>{"".join(body)}"""
    args.out.write_text(page)
    print(args.out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    def command(name: str, run, *profiles: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=run.__doc__)
        for profile in profiles:
            sub.add_argument(profile, type=Path)
        sub.add_argument("--ticks", help="a tick range, as a:b (either end may be left out)")
        sub.add_argument("--all", action="store_true", help="keep the preparing pass and the jumps between moments")
        sub.set_defaults(run=run)
        return sub

    command("summary", summary, "profile").add_argument("--by", type=int, help="one row per this many ticks")
    sub = command("worst", worst, "profile")
    sub.add_argument("--count", type=int, default=10)
    sub.add_argument("--key", default="wall", help="the measure to rank by (wall, cpu, gpu, gpu.<pass>, ...)")
    command("compare", compare, "before", "after")
    command("timeline", timeline, "profile").add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not args.command:
        sys.exit(parser.format_usage())
    args.run(args)


if __name__ == "__main__":
    main()
