from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import sys

from PIL import Image, ImageChops, ImageStat
import pytest
import pyray as rl

from grim.assets import TextureAsset, _load_texture_asset_from_bytes, load_paq_entries
from grim.terrain_render import GroundRenderer

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "ground"
CASES_PATH = FIXTURE_DIR / "ground_dump_cases.json"
PAQ_DIR = Path("game_bins") / "crimsonland" / "1.9.93-gog"
PAQ_PATH = PAQ_DIR / "crimson.paq"

TEXTURE_PATHS = {
    0: "ter/ter_q1_base.jaz",
    1: "ter/ter_q1_tex1.jaz",
    2: "ter/ter_q2_base.jaz",
    3: "ter/ter_q2_tex1.jaz",
    4: "ter/ter_q3_base.jaz",
    5: "ter/ter_q3_tex1.jaz",
    6: "ter/ter_q4_base.jaz",
    7: "ter/ter_q4_tex1.jaz",
}


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACTS_DIR = REPO_ROOT / "artifacts" / "tests" / "ground_dumps"

DOWNSAMPLE_FACTOR = int(os.environ.get("CRIMSON_GROUND_DUMP_DOWNSAMPLE", "4"))
MAX_DELTA_TOL = int(os.environ.get("CRIMSON_GROUND_DUMP_MAX_DELTA", "40"))
MEAN_DELTA_TOL = float(os.environ.get("CRIMSON_GROUND_DUMP_MEAN_DELTA", "3.0"))
RESAMPLE_BOX = getattr(Image, "Resampling", Image).BOX


def _artifacts_dir() -> Path:
    # Persist outputs in-repo (gitignored) so failures are easy to inspect.
    override = os.environ.get("CRIMSON_TEST_ARTIFACTS_DIR")
    if override:
        return Path(override)
    return DEFAULT_ARTIFACTS_DIR


@dataclass(frozen=True)
class GroundDumpCase:
    fixture: str
    seed: int
    width: int
    height: int
    tex0_index: int
    tex1_index: int
    tex2_index: int


def _load_cases() -> list[GroundDumpCase]:
    if not CASES_PATH.exists():
        return []
    data = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    cases: list[GroundDumpCase] = []
    for row in data:
        cases.append(
            GroundDumpCase(
                fixture=row["fixture"],
                seed=int(row["seed"]),
                width=int(row["width"]),
                height=int(row["height"]),
                tex0_index=int(row["tex0_index"]),
                tex1_index=int(row["tex1_index"]),
                tex2_index=int(row["tex2_index"]),
            )
        )
    return cases[-3:]


def _can_init_raylib() -> bool:
    if sys.platform.startswith("linux"):
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return False
    return True


@pytest.fixture(scope="module")
def raylib_context() -> None:
    if not _can_init_raylib():
        pytest.skip("raylib requires an active display")
    rl.set_config_flags(rl.FLAG_WINDOW_HIDDEN)
    rl.init_window(16, 16, "ground-fixtures")
    try:
        yield None
    finally:
        rl.close_window()


@pytest.fixture(scope="module")
def terrain_textures(raylib_context) -> dict[int, TextureAsset]:
    if not PAQ_PATH.exists():
        pytest.skip(f"missing game assets: {PAQ_PATH}")
    entries = load_paq_entries(PAQ_DIR)
    assets = {}
    for terrain_id, rel_path in TEXTURE_PATHS.items():
        asset = _load_texture_asset_from_bytes(f"terrain_{terrain_id}", rel_path, entries.get(rel_path))
        if asset.texture is None:
            pytest.skip(f"missing terrain texture: {rel_path}")
        assets[terrain_id] = asset
    try:
        yield assets
    finally:
        for asset in assets.values():
            asset.unload()


def _export_render_target(target: rl.RenderTexture, out_path: Path) -> None:
    image = rl.load_image_from_texture(target.texture)
    try:
        # OpenGL render textures are stored flipped; convert to top-left origin so
        # dumps compare 1:1 with the original D3D8 render target captures.
        rl.image_flip_vertical(image)
        rl.export_image(image, str(out_path))
    finally:
        rl.unload_image(image)


def _diff_summary(expected: Image.Image, actual: Image.Image) -> tuple[int, float]:
    if DOWNSAMPLE_FACTOR > 1:
        w, h = expected.size
        down_w = max(1, int(w) // DOWNSAMPLE_FACTOR)
        down_h = max(1, int(h) // DOWNSAMPLE_FACTOR)
        expected = expected.resize((down_w, down_h), resample=RESAMPLE_BOX)
        actual = actual.resize((down_w, down_h), resample=RESAMPLE_BOX)
    diff = ImageChops.difference(expected, actual)
    stat = ImageStat.Stat(diff)
    max_delta = max(extrema[1] for extrema in stat.extrema)
    mean_delta = sum(stat.mean) / len(stat.mean)
    return int(max_delta), float(mean_delta)


def test_ground_dumps_match_fixtures(terrain_textures: dict[int, TextureAsset]) -> None:
    cases = _load_cases()
    if not cases:
        pytest.skip("missing ground dump fixtures")
    out_root = _artifacts_dir()
    out_root.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    for case in cases:
        fixture_path = FIXTURE_DIR / case.fixture
        if not fixture_path.exists():
            pytest.skip(f"missing fixture: {fixture_path}")
        base = terrain_textures[case.tex0_index].texture
        overlay = terrain_textures[case.tex1_index].texture
        detail = terrain_textures[case.tex2_index].texture
        renderer = GroundRenderer(
            texture=base,
            overlay=overlay,
            overlay_detail=detail,
            width=case.width,
            height=case.height,
            texture_scale=1.0,
        )
        renderer.schedule_generate(seed=case.seed, layers=3)
        for _ in range(6):
            renderer.process_pending()
            if not renderer._pending_generate:
                break
        assert renderer.render_target is not None

        case_dir = out_root / Path(case.fixture).stem
        case_dir.mkdir(parents=True, exist_ok=True)
        expected_out = case_dir / "expected.png"
        actual_out = case_dir / "actual.png"
        diff_out = case_dir / "diff.png"
        meta_out = case_dir / "meta.json"

        # Always save the generated output for easy visual inspection.
        _export_render_target(renderer.render_target, actual_out)
        rl.unload_render_texture(renderer.render_target)
        renderer.render_target = None

        expected = Image.open(fixture_path).convert("RGB")
        actual = Image.open(actual_out).convert("RGB")
        assert actual.size == expected.size
        max_delta, mean_delta = _diff_summary(expected, actual)

        # Keep a copy of the expected fixture next to the output for side-by-side viewing.
        try:
            shutil.copyfile(fixture_path, expected_out)
        except OSError:
            # If copying fails for any reason, still allow the test to proceed.
            pass

        if max_delta > MAX_DELTA_TOL or mean_delta > MEAN_DELTA_TOL:
            ImageChops.difference(expected, actual).save(diff_out)
            meta_out.write_text(
                json.dumps(
                    {
                        "fixture": case.fixture,
                        "seed": case.seed,
                        "width": case.width,
                        "height": case.height,
                        "tex0_index": case.tex0_index,
                        "tex1_index": case.tex1_index,
                        "tex2_index": case.tex2_index,
                        "max_delta": max_delta,
                        "mean_delta": mean_delta,
                        "downsample_factor": DOWNSAMPLE_FACTOR,
                        "max_delta_tol": MAX_DELTA_TOL,
                        "mean_delta_tol": MEAN_DELTA_TOL,
                        "expected": str(expected_out),
                        "actual": str(actual_out),
                        "diff": str(diff_out),
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            failures.append(
                f"fixture mismatch for {case.fixture} seed={case.seed} "
                f"(downsample={DOWNSAMPLE_FACTOR}, max_delta={max_delta} (tol={MAX_DELTA_TOL}), "
                f"mean_delta={mean_delta:.3f} (tol={MEAN_DELTA_TOL:.3f})); out={case_dir}"
            )
        else:
            # Avoid stale artifacts from previous failing runs.
            for p in (diff_out, meta_out):
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass

    if failures:
        pytest.fail("\n".join(failures))
