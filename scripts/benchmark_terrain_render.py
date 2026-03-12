from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import pyray
from PIL import Image, ImageChops, ImageStat

from crimson.effects_atlas import EffectId, effect_src_rect
from grim.assets import TextureId, load_runtime_resources, unload_runtime_resources
from grim.color import RGBA
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundCorpseDecal, GroundDecal, GroundRenderer, TerrainRtAlphaMode

CASES_PATH = Path("tests/fixtures/ground/ground_dump_cases.json")

TEXTURE_IDS_BY_SLOT = {
    0: TextureId.TER_Q1_BASE,
    1: TextureId.TER_Q1_OVERLAY,
    2: TextureId.TER_Q2_BASE,
    3: TextureId.TER_Q2_OVERLAY,
    4: TextureId.TER_Q3_BASE,
    5: TextureId.TER_Q3_OVERLAY,
    6: TextureId.TER_Q4_BASE,
    7: TextureId.TER_Q4_OVERLAY,
}

EFFECT_IDS = (
    EffectId.BURST,
    EffectId.RING,
    EffectId.BLOOD_SPLATTER,
    EffectId.EXPLOSION_BURST,
    EffectId.EXPLOSION_PUFF,
)


@dataclass(frozen=True)
class GroundCase:
    fixture: str
    seed: int
    width: int
    height: int
    tex0_index: int
    tex1_index: int
    tex2_index: int


@dataclass(frozen=True)
class BenchmarkAggregate:
    min_ms: float
    p50_ms: float
    mean_ms: float
    p95_ms: float
    max_ms: float
    stdev_ms: float


@dataclass(frozen=True)
class AlphaSummary:
    min_alpha: int
    max_alpha: int
    mean_alpha: float


@dataclass(frozen=True)
class RgbDiffSummary:
    max_delta: int
    mean_delta: float


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark terrain RT generation and decal baking strategies")
    parser.add_argument(
        "--assets-dir",
        type=Path,
        default=Path("game_bins/crimsonland/1.9.93-gog"),
        help="directory containing crimson.paq and runtime assets",
    )
    parser.add_argument(
        "--cases",
        type=Path,
        default=CASES_PATH,
        help="ground dump case JSON to use for terrain seeds and texture triplets",
    )
    parser.add_argument("--runs", type=int, default=6, help="measured runs per case and stage")
    parser.add_argument("--warmup-runs", type=int, default=2, help="warmup runs per case and stage")
    parser.add_argument("--decal-count", type=int, default=2048, help="generic decals baked per stress pass")
    parser.add_argument("--corpse-count", type=int, default=512, help="corpse decals baked per stress pass")
    parser.add_argument("--json-out", type=Path, help="optional JSON output path")
    return parser.parse_args()


def _load_cases(path: Path) -> list[GroundCase]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [
        GroundCase(
            fixture=str(row["fixture"]),
            seed=int(row["seed"]),
            width=int(row["width"]),
            height=int(row["height"]),
            tex0_index=int(row["tex0_index"]),
            tex1_index=int(row["tex1_index"]),
            tex2_index=int(row["tex2_index"]),
        )
        for row in data
    ]


def _aggregate(samples_ms: list[float]) -> BenchmarkAggregate:
    ordered = sorted(float(sample) for sample in samples_ms)
    if not ordered:
        raise ValueError("benchmark requires at least one sample")
    if len(ordered) == 1:
        p95 = ordered[0]
        stdev = 0.0
    else:
        p95 = statistics.quantiles(ordered, n=100, method="inclusive")[94]
        stdev = statistics.stdev(ordered)
    return BenchmarkAggregate(
        min_ms=ordered[0],
        p50_ms=statistics.median(ordered),
        mean_ms=statistics.fmean(ordered),
        p95_ms=float(p95),
        max_ms=ordered[-1],
        stdev_ms=float(stdev),
    )


def _terrain_renderer(
    resources,
    case: GroundCase,
    *,
    alpha_mode: TerrainRtAlphaMode,
) -> GroundRenderer:
    return GroundRenderer(
        texture=resources.texture(TEXTURE_IDS_BY_SLOT[case.tex0_index]),
        overlay=resources.texture(TEXTURE_IDS_BY_SLOT[case.tex1_index]),
        overlay_detail=resources.texture(TEXTURE_IDS_BY_SLOT[case.tex2_index]),
        rt_alpha_mode=alpha_mode,
        width=case.width,
        height=case.height,
        texture_scale=1.0,
    )


def _make_stress_decals(
    *,
    texture,
    width: int,
    height: int,
    count: int,
) -> tuple[GroundDecal, ...]:
    texture_w = float(texture.width)
    texture_h = float(texture.height)
    decals: list[GroundDecal] = []
    for idx in range(int(count)):
        effect_id = int(EFFECT_IDS[idx % len(EFFECT_IDS)])
        src_rect = effect_src_rect(effect_id, texture_width=texture_w, texture_height=texture_h)
        assert src_rect is not None, f"missing atlas rect for effect id {effect_id}"
        x = float((idx * 37) % width)
        y = float((idx * 53) % height)
        size = 20.0 + float(idx % 28)
        alpha = 0.42 + float(idx % 7) * 0.08
        gray = 0.76 + float(idx % 11) * 0.015
        decals.append(
            GroundDecal(
                texture=texture,
                src=rl.Rectangle(*src_rect),
                pos=Vec2(x, y),
                width=size,
                height=size,
                rotation_rad=float((idx * 17) % 628) * 0.01,
                tint=RGBA(gray, gray, gray, min(alpha, 1.0)).to_rl(),
                centered=True,
            ),
        )
    return tuple(decals)


def _make_stress_corpses(*, width: int, height: int, count: int) -> tuple[GroundCorpseDecal, ...]:
    corpses: list[GroundCorpseDecal] = []
    for idx in range(int(count)):
        x = float((idx * 41) % max(1, width - 48))
        y = float((idx * 61) % max(1, height - 48))
        size = 24.0 + float(idx % 20)
        alpha = 0.62 + float(idx % 5) * 0.075
        corpses.append(
            GroundCorpseDecal(
                bodyset_frame=idx & 0xF,
                top_left=Vec2(x, y),
                size=size,
                rotation_rad=float((idx * 29) % 628) * 0.01,
                tint=RGBA(1.0, 1.0, 1.0, min(alpha, 1.0)).to_rl(),
            ),
        )
    return tuple(corpses)


def _capture_target_rgba(target) -> Image.Image:
    image = rl.load_image_from_texture(target.texture)
    try:
        rl.image_flip_vertical(image)
        pixel_count = int(image.width) * int(image.height)
        colors = rl.load_image_colors(image)
        try:
            raw = bytes(pyray.ffi.buffer(colors, pixel_count * 4))
        finally:
            rl.unload_image_colors(colors)
        return Image.frombuffer(
            "RGBA",
            (int(image.width), int(image.height)),
            raw,
            "raw",
            "RGBA",
            0,
            1,
        ).copy()
    finally:
        rl.unload_image(image)


def _alpha_summary(image: Image.Image) -> AlphaSummary:
    alpha = image.getchannel("A")
    stat = ImageStat.Stat(alpha)
    return AlphaSummary(
        min_alpha=int(stat.extrema[0][0]),
        max_alpha=int(stat.extrema[0][1]),
        mean_alpha=float(stat.mean[0]),
    )


def _rgb_diff_summary(expected: Image.Image, actual: Image.Image) -> RgbDiffSummary:
    diff = ImageChops.difference(expected.convert("RGB"), actual.convert("RGB"))
    stat = ImageStat.Stat(diff)
    max_delta = max(extrema[1] for extrema in stat.extrema)
    mean_delta = sum(float(value) for value in stat.mean) / len(stat.mean)
    return RgbDiffSummary(max_delta=int(max_delta), mean_delta=float(mean_delta))


def _flush_draws() -> None:
    rl.rl_draw_render_batch_active()


def _warm_renderer(renderer: GroundRenderer, *, seed: int) -> None:
    renderer.schedule_generate(seed=seed)
    for _ in range(6):
        renderer.process_pending()
        if not renderer.generation_pending():
            break
    if renderer.render_target is None:
        raise RuntimeError("terrain benchmark could not create render target")


def _measure_ms(fn) -> float:
    start = time.perf_counter()
    fn()
    _flush_draws()
    return (time.perf_counter() - start) * 1000.0


def main() -> int:
    args = _parse_args()
    assets_dir = Path(args.assets_dir)
    if not (assets_dir / "crimson.paq").is_file():
        raise SystemExit(f"missing assets: expected {(assets_dir / 'crimson.paq')}")

    cases = _load_cases(Path(args.cases))
    if not cases:
        raise SystemExit(f"no benchmark cases found in {args.cases}")

    modes = (
        TerrainRtAlphaMode.PRESERVE_DEST_ALPHA,
        TerrainRtAlphaMode.MASK_ALPHA_WRITES,
        TerrainRtAlphaMode.BLEND_ALPHA,
    )

    rl.set_config_flags(int(rl.ConfigFlags.FLAG_WINDOW_HIDDEN))
    rl.set_trace_log_level(int(rl.TraceLogLevel.LOG_WARNING))
    rl.init_window(16, 16, "terrain-render-benchmark")
    resources = None
    try:
        resources = load_runtime_resources(assets_dir)
        particle_texture = resources.texture(TextureId.PARTICLES)
        bodyset_texture = resources.texture(TextureId.BODYSET)

        stage_samples: dict[str, dict[str, list[float]]] = {
            mode.value: {"generate": [], "decals": [], "corpses": [], "combined": []}
            for mode in modes
        }
        snapshots: dict[str, dict[str, dict[str, Image.Image]]] = {
            mode.value: {}
            for mode in modes
        }
        alpha_metrics: dict[str, dict[str, AlphaSummary]] = {mode.value: {} for mode in modes}
        diff_metrics: dict[str, dict[str, RgbDiffSummary]] = {mode.value: {} for mode in modes}

        for case in cases:
            decals = _make_stress_decals(
                texture=particle_texture,
                width=case.width,
                height=case.height,
                count=int(args.decal_count),
            )
            corpses = _make_stress_corpses(
                width=case.width,
                height=case.height,
                count=int(args.corpse_count),
            )
            for mode in modes:
                renderer = _terrain_renderer(resources, case, alpha_mode=mode)
                try:
                    _warm_renderer(renderer, seed=case.seed)

                    total_runs = int(args.warmup_runs) + int(args.runs)
                    for run_index in range(total_runs):
                        sample = _measure_ms(
                            lambda renderer=renderer, seed=case.seed + run_index: renderer.generate(seed=seed),
                        )
                        if run_index >= int(args.warmup_runs):
                            stage_samples[mode.value]["generate"].append(sample)

                    generate_image = _capture_target_rgba(renderer.render_target)
                    snapshots[mode.value].setdefault(case.fixture, {})["generate"] = generate_image
                    alpha_metrics[mode.value][f"{case.fixture}:generate"] = _alpha_summary(generate_image)

                    for run_index in range(total_runs):
                        renderer.generate(seed=case.seed + run_index)
                        sample = _measure_ms(
                            lambda renderer=renderer, decals=decals: renderer.bake_decals(decals),
                        )
                        if run_index >= int(args.warmup_runs):
                            stage_samples[mode.value]["decals"].append(sample)

                    for run_index in range(total_runs):
                        renderer.generate(seed=case.seed + run_index)
                        sample = _measure_ms(
                            lambda renderer=renderer, corpses=corpses: renderer.bake_corpse_decals(
                                bodyset_texture,
                                corpses,
                            ),
                        )
                        if run_index >= int(args.warmup_runs):
                            stage_samples[mode.value]["corpses"].append(sample)

                    for run_index in range(total_runs):
                        renderer.generate(seed=case.seed + run_index)
                        sample = _measure_ms(
                            lambda renderer=renderer, decals=decals, corpses=corpses: (
                                renderer.bake_decals(decals),
                                renderer.bake_corpse_decals(bodyset_texture, corpses),
                            ),
                        )
                        if run_index >= int(args.warmup_runs):
                            stage_samples[mode.value]["combined"].append(sample)

                    combined_image = _capture_target_rgba(renderer.render_target)
                    snapshots[mode.value][case.fixture]["combined"] = combined_image
                    alpha_metrics[mode.value][f"{case.fixture}:combined"] = _alpha_summary(combined_image)
                finally:
                    if renderer.render_target is not None:
                        rl.unload_render_texture(renderer.render_target)
                        renderer.render_target = None

        baseline_mode = TerrainRtAlphaMode.PRESERVE_DEST_ALPHA.value
        for mode in modes:
            if mode.value == baseline_mode:
                continue
            for case in cases:
                fixture = case.fixture
                diff_metrics[mode.value][f"{fixture}:generate"] = _rgb_diff_summary(
                    snapshots[baseline_mode][fixture]["generate"],
                    snapshots[mode.value][fixture]["generate"],
                )
                diff_metrics[mode.value][f"{fixture}:combined"] = _rgb_diff_summary(
                    snapshots[baseline_mode][fixture]["combined"],
                    snapshots[mode.value][fixture]["combined"],
                )

        payload = {
            "assets_dir": str(assets_dir),
            "cases": [asdict(case) for case in cases],
            "runs": int(args.runs),
            "warmup_runs": int(args.warmup_runs),
            "decal_count": int(args.decal_count),
            "corpse_count": int(args.corpse_count),
            "strategies": {},
        }

        for mode in modes:
            payload["strategies"][mode.value] = {
                "stages": {
                    stage: asdict(_aggregate(samples))
                    for stage, samples in stage_samples[mode.value].items()
                },
                "alpha": {
                    key: asdict(value)
                    for key, value in alpha_metrics[mode.value].items()
                },
                "rgb_diff_vs_preserve_dest_alpha": {
                    key: asdict(value)
                    for key, value in diff_metrics[mode.value].items()
                },
            }

        for mode in modes:
            strategy = payload["strategies"][mode.value]
            print(mode.value)
            for stage_name, metrics in strategy["stages"].items():
                print(
                    "  "
                    f"{stage_name:>8}: "
                    f"mean={metrics['mean_ms']:.3f}ms "
                    f"p50={metrics['p50_ms']:.3f}ms "
                    f"p95={metrics['p95_ms']:.3f}ms",
                )
            for key, alpha in strategy["alpha"].items():
                print(
                    "  "
                    f"{key} alpha: "
                    f"min={alpha['min_alpha']} max={alpha['max_alpha']} mean={alpha['mean_alpha']:.3f}",
                )
            if strategy["rgb_diff_vs_preserve_dest_alpha"]:
                for key, diff in strategy["rgb_diff_vs_preserve_dest_alpha"].items():
                    print(
                        "  "
                        f"{key} rgb diff vs preserve: "
                        f"max={diff['max_delta']} mean={diff['mean_delta']:.6f}",
                    )
            print()

        if args.json_out is not None:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    finally:
        unload_runtime_resources(resources)
        rl.close_window()


if __name__ == "__main__":
    raise SystemExit(main())
