from __future__ import annotations

import contextlib
import json
import os
import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest
from PIL import Image, ImageChops, ImageStat

from crimson.sim.terrain_generate import terrain_generate
from crimson.terrain_slots import resolve_terrain_slots
from grim.assets import (
    TEXTURE_SPECS,
    TextureId,
    _load_texture_asset_from_bytes,
    _select_texture_asset,
    load_paq_entries,
)
from grim.rand import Crand
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer

pytestmark = pytest.mark.terrain

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "ground"
CASES_PATH = FIXTURE_DIR / "ground_dump_cases.json"

TERRAIN_TEXTURE_IDS = tuple(texture_id for texture_id in TextureId if texture_id.name.startswith("TER_"))

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ARTIFACTS_DIR = REPO_ROOT / "artifacts" / "tests" / "ground_dumps"

DOWNSAMPLE_FACTOR = int(os.environ.get("CRIMSON_GROUND_DUMP_DOWNSAMPLE", "4"))
MAX_DELTA_TOL = int(os.environ.get("CRIMSON_GROUND_DUMP_MAX_DELTA", "40"))
# The captures were rendered from the shipped JAZ terrain, the tests' crimson.paq carries the lossless source art
# instead: the q3 pair differs from its JAZ by ~12/255 in red, which lifts that dump's mean delta from 2.2 to 4.4.
# A misstamped ground (the next seed) stays above 6.6 on every case.
MEAN_DELTA_TOL = float(os.environ.get("CRIMSON_GROUND_DUMP_MEAN_DELTA", "5.0"))
_RESAMPLING = getattr(Image, "Resampling", None)
RESAMPLE_BOX = cast(int, getattr(_RESAMPLING, "BOX", cast(Any, Image).BOX))


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
            ),
        )
    return cases[-3:]


@pytest.fixture(scope="module")
def terrain_textures(raylib_context, assets_dir: Path) -> Iterator[dict[TextureId, rl.Texture]]:
    """The terrain textures from the tests' crimson.paq, picked and decoded as the runtime loads them."""
    entries = load_paq_entries(assets_dir)
    textures: dict[TextureId, rl.Texture] = {}
    try:
        for texture_id in TERRAIN_TEXTURE_IDS:
            rel_path, payload = _select_texture_asset(entries, TEXTURE_SPECS[texture_id].rel_path)
            texture = _load_texture_asset_from_bytes(rel_path, payload)
            assert texture is not None, f"undecodable terrain texture: {rel_path}"
            textures[texture_id] = texture
        yield textures
    finally:
        for texture in textures.values():
            rl.unload_texture(texture)


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


def test_ground_dumps_match_fixtures(terrain_textures: dict[TextureId, rl.Texture]) -> None:
    cases = _load_cases()
    assert cases, "ground dump fixtures must contain captured cases"
    out_root = _artifacts_dir()
    out_root.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    for case in cases:
        fixture_path = FIXTURE_DIR / case.fixture
        slots = (case.tex0_index, case.tex1_index, case.tex2_index)
        base, overlay, detail = resolve_terrain_slots(slots, terrain_textures.__getitem__)
        renderer = GroundRenderer(
            texture=base,
            overlay=overlay,
            overlay_detail=detail,
            width=case.width,
            height=case.height,
        )
        # Compare at the capture's pixel dimensions even on a Retina display.
        renderer.schedule_stamps(
            terrain_generate(Crand(case.seed), slots).layers,
            texture_scale=renderer._render_pixel_ratio(),
        )
        renderer.process_pending()
        assert renderer.render_target_ready()
        assert renderer.render_target is not None

        case_dir = out_root / Path(case.fixture).stem
        case_dir.mkdir(parents=True, exist_ok=True)
        expected_out = case_dir / "expected.png"
        actual_out = case_dir / "actual.png"
        diff_out = case_dir / "diff.png"
        meta_out = case_dir / "meta.json"

        # Always save the generated output for easy visual inspection.
        _export_render_target(renderer.render_target, actual_out)
        renderer.close()

        expected = Image.open(fixture_path).convert("RGB")
        actual = Image.open(actual_out).convert("RGB")
        assert actual.size == expected.size
        max_delta, mean_delta = _diff_summary(expected, actual)

        # Keep a copy of the expected fixture next to the output for side-by-side viewing.
        with contextlib.suppress(OSError):
            shutil.copyfile(fixture_path, expected_out)

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
                f"mean_delta={mean_delta:.3f} (tol={MEAN_DELTA_TOL:.3f})); out={case_dir}",
            )
        else:
            # Avoid stale artifacts from previous failing runs.
            for p in (diff_out, meta_out):
                with contextlib.suppress(FileNotFoundError):
                    p.unlink()

    if failures:
        pytest.fail("\n".join(failures))
