"""Check Python's submitted trail vertices against recorded native PC=24 corners."""

import argparse
import hashlib
import importlib.util
import json
import shutil
import struct
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import msgspec

from crimson.math_parity import f32
from crimson.projectiles.types import Projectile, ProjectileTemplateId
from crimson.render.frame import RenderFrame
from crimson.render.projectile_draw import primary_dispatch
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world import projectiles as world
from crimson.render.world.context import WorldRenderCtx
from crimson.render.world.viewport import ViewTransform
from grim.assets import TextureId
from grim.geom import Vec2

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BEFORE_COMMIT = "544af3e051a82f3df995a1532cc75a7fbf13cccc"
CONTEXT = "src/crimson/render/world/context.py"
BULLET = "src/crimson/render/projectile_draw/primary_bullet.py"
SCALES = ((1.0, 1.0), (2.0, 2.0), (1.5, 0.75))
PORTED_TYPES = {1, 2, 3, 5, 6, 29}
GIT = shutil.which("git")
assert GIT is not None
DRAW_CALLS = (
    "begin_blend_mode",
    "rl_set_texture",
    "rl_begin",
    "rl_end",
    "end_blend_mode",
    "rl_color4ub",
    "rl_tex_coord2f",
    "rl_vertex2f",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bits(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


def from_bits(value):
    return struct.unpack("<f", struct.pack("<I", value))[0]


class TextureStub:
    id = 1


class ResourcesStub:
    def texture(self, texture_id):
        return TextureStub() if texture_id == TextureId.BULLET_TRAIL else None


def historical_module(relative_path, name, package, directory):
    source = subprocess.check_output([GIT, "show", f"{BEFORE_COMMIT}:{relative_path}"], cwd=ROOT)
    path = directory / Path(relative_path).name
    path.write_bytes(source)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = package
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module, sha(source)


def historical_handler(directory):
    directory.mkdir(exist_ok=True)
    context, context_sha = historical_module(
        CONTEXT,
        "crimson.render.world._previous_trail_context",
        "crimson.render.world",
        directory,
    )
    bullet, bullet_sha = historical_module(
        BULLET,
        "crimson.render.projectile_draw._previous_trail_bullet",
        "crimson.render.projectile_draw",
        directory,
    )
    # Rebind the old module's imported draw helper to its exact historical definition.
    bullet.draw_bullet_trail_quad = context.draw_bullet_trail_quad
    return bullet.draw_bullet_trail, {CONTEXT: context_sha, BULLET: bullet_sha}


def selected_fixtures():
    assert {int(kind) for kind in ProjectileTemplateId} & {*range(8), 29} == PORTED_TYPES
    receipt_path = HERE / "results.json"
    receipt = json.loads(receipt_path.read_text())
    fixture_path = HERE / receipt["fixtures"]["file"]
    assert sha(fixture_path.read_bytes()) == receipt["fixtures"]["sha256"]
    assert sha((ROOT / "tools/match/scratches/projectile_render/scratch.cpp").read_bytes()) == receipt["source_sha256"]
    selected = []
    for line in fixture_path.read_text().splitlines():
        row = json.loads(line)
        case = row["case"]
        if case["fpcw"] != 0x007F:
            continue
        if case["group"] in ("discovery", "moving-camera", "coincident"):
            selected.append(row)
        elif case["group"] == "pool-and-gates":
            projectile = case["records"][0]
            if (
                projectile["type_id"] in PORTED_TYPES
                and projectile["index"] == 0
                and projectile["life"] == f32(0.2)
                and case["alpha"] == f32(0.7)
                and case["glow"] == 1
            ):
                selected.append(row)
    assert len(selected) == 1161
    return selected, receipt, sha(receipt_path.read_bytes())


def observe(fixtures, scale, handler):
    frame = RenderFrame(
        world_size=1024.0,
        demo_mode_active=False,
        config=None,
        camera=Vec2(),
        ground=None,
        state=object(),
        players=[],
        creatures=object(),
        resources=ResourcesStub(),
        elapsed_ms=0.0,
        bonus_anim_phase=0.0,
        rtx_mode=RtxRenderMode.CLASSIC,
    )
    events, results = [], []
    handlers = (handler, *primary_dispatch.PRIMARY_PROJECTILE_DRAW_HANDLERS[1:])
    with ExitStack() as stack:
        stack.enter_context(patch.object(primary_dispatch, "PRIMARY_PROJECTILE_DRAW_HANDLERS", handlers))
        for name in DRAW_CALLS:

            def capture(*arguments, call_name=name):
                events.append(
                    [
                        call_name,
                        [bits(value) for value in arguments] if call_name == "rl_vertex2f" else list(arguments),
                    ],
                )

            stack.enter_context(patch.object(world.rl, name, side_effect=capture))
        for fixture in fixtures:
            case = fixture["case"]
            camera = Vec2(*case["camera"])
            ctx = WorldRenderCtx(
                frame=msgspec.structs.replace(frame, camera=camera),
                view=ViewTransform(
                    camera=camera,
                    view_scale=Vec2(*scale),
                    screen_size=Vec2(1024, 1024),
                    out_size=Vec2(1024 * scale[0], 1024 * scale[1]),
                ),
            )
            events.clear()
            active = sorted(
                (row for row in case["records"] if row["active"] and row["type_id"] in PORTED_TYPES),
                key=lambda row: row["index"],
            )
            for row in active:
                assert row["life"] > 0 and 0 < case["alpha"] <= 1
                projectile = Projectile(
                    type_id=ProjectileTemplateId(row["type_id"]),
                    origin=Vec2(*row["origin"]),
                    pos=Vec2(*row["position"]),
                    vel=Vec2(*row["velocity"]),
                    life_timer=row["life"],
                    angle=row["angle"],
                )
                world.draw_projectile(ctx, projectile, proj_index=row["index"], alpha=case["alpha"])
            vertices = [value for name, arguments in events if name == "rl_vertex2f" for value in arguments]
            assert len(vertices) == len(active) * 8
            results.append(
                {
                    "fixture": fixture["index"],
                    "vertices": vertices,
                    "other_calls": [event for event in events if event[0] != "rl_vertex2f"],
                    "trace_sha256": sha(json.dumps(events).encode()),
                },
            )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    fixtures, native_receipt, native_receipt_sha = selected_fixtures()
    current_handler = primary_dispatch.PRIMARY_PROJECTILE_DRAW_HANDLERS[0]
    previous_handler, previous_sources = historical_handler(out / "before")
    results = []
    for scale in SCALES:
        current = observe(fixtures, scale, current_handler)
        previous = observe(fixtures, scale, previous_handler)
        negatives, records = [], []
        for fixture, actual, before in zip(fixtures, current, previous, strict=True):
            assert actual["fixture"] == before["fixture"] == fixture["index"]
            assert actual["other_calls"] == before["other_calls"]
            active = sorted((row for row in fixture["case"]["records"] if row["active"]), key=lambda row: row["index"])
            expected = [
                bits(from_bits(word) * scale[index % 2])
                for row, corners in zip(active, fixture["corners"], strict=True)
                if row["type_id"] in PORTED_TYPES
                for index, word in enumerate(corners)
            ]
            assert actual["vertices"] == expected, (fixture["index"], scale, actual["vertices"], expected)
            differing = [index for index, (a, b) in enumerate(zip(before["vertices"], expected, strict=True)) if a != b]
            if differing:
                negatives.append(
                    {
                        "fixture": fixture["index"],
                        "group": fixture["case"]["group"],
                        "coordinates": differing,
                        "native_projected": expected,
                        "previous": before["vertices"],
                    },
                )
            records.append(
                {
                    "fixture": fixture["index"],
                    "vertices_sha256": sha(json.dumps(expected).encode()),
                    "trace_sha256": actual["trace_sha256"],
                },
            )
        discovery_failures = sum(row["group"] == "discovery" for row in negatives)
        if scale == (1.0, 1.0):
            assert discovery_failures == 292
        results.append(
            {
                "scale": scale,
                "fixtures": len(fixtures),
                "failed": 0,
                "previous_failures": len(negatives),
                "previous_discovery_failures": discovery_failures,
                "records": records,
                "negative_controls": negatives,
            },
        )
        print(
            f"Verified Python scale {scale}: {len(fixtures)} cases; previous source fails {len(negatives)}",
            flush=True,
        )
    sources = (
        CONTEXT,
        BULLET,
        "src/crimson/render/world/projectiles.py",
        "src/crimson/render/projectile_draw/primary_dispatch.py",
        "src/crimson/render/world/viewport.py",
        "src/crimson/math_parity.py",
        "src/crimson/projectiles/types.py",
        "src/grim/geom.py",
    )
    record = {
        "schema_version": 1,
        "kind": "python-conventional-trail-submitted-vertices",
        "new_source_matches": 0,
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "before_commit": BEFORE_COMMIT,
        "source_sha256": {name: sha((ROOT / name).read_bytes()) for name in sources},
        "previous_source_sha256": previous_sources,
        "native_receipt_sha256": native_receipt_sha,
        "native_fixture_sha256": native_receipt["fixtures"]["sha256"],
        "native_image_sha256": native_receipt["image_sha256"],
        "results": results,
        "boundaries": {
            "entry": "actual Python draw_projectile registry dispatch, trail handler and quad submission",
            "data": "recorded native PC=24 corner words from 1161 positive-alpha fixtures for six represented Python types; native-only ids 0/4/7 are excluded; no native re-execution here",
            "projection": "component-wise viewport scaling after native corner rounding; unit, doubled and unequal-axis scales",
            "before": "exact historical context and bullet modules; old helper import rebound to its historical definition",
            "state": "all non-vertex GL recording calls remain identical to the previous renderer",
            "scope": "submitted vertex bits with a trail-only texture fixture; no GPU output, sprite heads, world gates or simulation-state claim",
        },
    }
    (out / "port-results.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
