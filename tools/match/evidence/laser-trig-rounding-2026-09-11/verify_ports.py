"""Compare actual Python laser draw submissions with recorded native geometry/colors."""

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

from msgspec import structs

from crimson.perks import PerkId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world import projectiles as world
from crimson.render.world.context import WorldRenderCtx
from crimson.render.world.viewport import ViewTransform
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.assets import TextureId
from grim.geom import Vec2

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BEFORE_COMMIT = "07d412c426b343ee0328b543b63d73ce376509a0"
PROJECTILES = "src/crimson/render/world/projectiles.py"
DRAW = "src/crimson/render/world/draw.py"
SCALES = ((1.0, 1.0), (2.0, 2.0), (1.5, 0.75), (0.25, 0.5))
CALLS = (
    "begin_blend_mode",
    "rl_set_texture",
    "rl_begin",
    "rl_end",
    "end_blend_mode",
    "rl_color4ub",
    "rl_tex_coord2f",
    "rl_vertex2f",
)
GIT = shutil.which("git")
assert GIT is not None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bits(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


def from_bits(value):
    return struct.unpack("<f", struct.pack("<I", value))[0]


def geometry_key(player, camera):
    return tuple(bits(value) for value in (*player["position"], player["heading"], *camera))


class TextureStub:
    id = 1


class ResourcesStub:
    def texture(self, texture_id):
        return TextureStub() if texture_id == TextureId.BULLET_TRAIL else None


def historical_handler(out):
    source = subprocess.check_output([GIT, "show", f"{BEFORE_COMMIT}:{PROJECTILES}"], cwd=ROOT)
    path = out / "before-projectiles.py"
    path.write_bytes(source)
    name = "crimson.render.world._historical_laser"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "crimson.render.world"
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module.draw_sharpshooter_laser_sight, sha(source)


def observe(rows, scale, preserve_bugs, handler, *, legacy=False):
    frame = RenderFrame(
        world_size=1024.0,
        demo_mode_active=False,
        config=None,
        camera=Vec2(),
        ground=None,
        state=GameplayState(preserve_bugs=preserve_bugs),
        players=[],
        creatures=object(),
        resources=ResourcesStub(),
        elapsed_ms=0.0,
        bonus_anim_phase=0.0,
        rtx_mode=RtxRenderMode.CLASSIC,
    )
    events, results = [], []
    with ExitStack() as stack:
        for name in CALLS:
            stack.enter_context(patch.object(world.rl, name, side_effect=lambda *a, n=name: events.append((n, a))))
        for row in rows:
            case = row["case"]
            players = []
            for item in case["players"][: case["player_count"]]:
                player = PlayerState(
                    index=item["index"],
                    pos=Vec2(*item["position"]),
                    health=item["health"],
                    aim_heading=item["heading"],
                )
                player.perk_counts[int(PerkId.SHARPSHOOTER)] = item["sharpshooter"]
                players.append(player)
            view = ViewTransform(
                camera=Vec2(*case["camera"]),
                view_scale=Vec2(*scale),
                screen_size=Vec2(1024.0, 1024.0),
                out_size=Vec2(1024.0 * scale[0], 1024.0 * scale[1]),
            )
            ctx = WorldRenderCtx(frame=structs.replace(frame, players=players), view=view)
            kwargs = {"scale": view.scale} if legacy else {}
            events.clear()
            handler(ctx, camera=view.camera, view_scale=view.view_scale, alpha=case["alpha"], **kwargs)
            results.append(
                {
                    "vertices": [bits(v) for name, args in events if name == "rl_vertex2f" for v in args],
                    "colors": [list(args) for name, args in events if name == "rl_color4ub"],
                    "other_calls": [call for call in events if call[0] not in ("rl_vertex2f", "rl_color4ub")],
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
    receipt_path = HERE / "results.json"
    receipt = json.loads(receipt_path.read_text())
    fixture_path = HERE / receipt["fixtures"]["file"]
    assert sha(fixture_path.read_bytes()) == receipt["fixtures"]["sha256"]
    assert sha((ROOT / "tools/match/scratches/projectile_render/scratch.cpp").read_bytes()) == receipt["source_sha256"]
    colors_path = HERE / "native-colors.json"
    color_receipt = json.loads(colors_path.read_text())
    assert color_receipt["native_fixture_sha256"] == receipt["fixtures"]["sha256"]
    palettes = {bits(r["alpha"]): r["packed_argb"] for r in color_receipt["cases"] if r["fpcw"] == 0x007F}
    geometry = {}
    rows = []
    for line in fixture_path.read_text().splitlines():
        row = json.loads(line)
        case = row["case"]
        if case["fpcw"] != 0x007F:
            continue
        visible = [p for p in case["players"] if p["index"] < case["player_count"] and p["health"] > 0]
        if not case["players"][0]["sharpshooter"]:
            visible = []
        for player, corners in zip(visible, row["native_corners"], strict=True):
            key = geometry_key(player, case["camera"])
            assert key not in geometry or geometry[key] == corners
            geometry[key] = corners
        if 1e-3 < case["alpha"] <= 1.0:
            rows.append(row)
    assert len(rows) == 2376
    before_handler, before_sha = historical_handler(out)
    records = []
    for preserve_bugs in (True, False):
        for scale in SCALES:
            current = observe(rows, scale, preserve_bugs, world.draw_sharpshooter_laser_sight)
            previous = observe(rows, scale, preserve_bugs, before_handler, legacy=True)
            old_vertices = old_colors = submitted = 0
            examples = []
            for row, actual, before in zip(rows, current, previous, strict=True):
                case = row["case"]
                players = case["players"][: case["player_count"]]
                native_corners = [
                    geometry[geometry_key(player, case["camera"])]
                    for player in players
                    if player["health"] > 0 and (players[0] if preserve_bugs else player)["sharpshooter"] > 0
                ]
                expected_vertices = [
                    bits(from_bits(word) * scale[index % 2])
                    for corners in native_corners
                    for index, word in enumerate(corners)
                ]
                palette = palettes[bits(case["alpha"])]
                expected_colors = [
                    [(color >> 16) & 255, (color >> 8) & 255, color & 255, (color >> 24) & 255]
                    for _ in native_corners
                    for color in palette
                ]
                assert actual["vertices"] == expected_vertices, (row["index"], scale, preserve_bugs)
                assert actual["colors"] == expected_colors, (row["index"], scale, preserve_bugs)
                assert actual["other_calls"] == before["other_calls"]
                assert len(actual["vertices"]) == len(before["vertices"])
                vertex_failure = before["vertices"] != expected_vertices
                color_failure = before["colors"] != expected_colors
                old_vertices += vertex_failure
                old_colors += color_failure
                submitted += bool(native_corners)
                if (vertex_failure or color_failure) and len(examples) < 3:
                    examples.append(
                        {
                            "index": row["index"],
                            "expected_vertices": expected_vertices,
                            "before_vertices": before["vertices"],
                            "expected_colors": expected_colors,
                            "before_colors": before["colors"],
                        },
                    )
            records.append(
                {
                    "preserve_bugs": preserve_bugs,
                    "scale": scale,
                    "cases": len(rows),
                    "cases_with_quads": submitted,
                    "current_vertex_failures": 0,
                    "current_color_failures": 0,
                    "before_vertex_failures": old_vertices,
                    "before_color_failures": old_colors,
                    "current_ordered_trace_hashes_sha256": sha(
                        json.dumps([r["trace_sha256"] for r in current]).encode(),
                    ),
                    "before_ordered_trace_hashes_sha256": sha(
                        json.dumps([r["trace_sha256"] for r in previous]).encode(),
                    ),
                    "before_failure_examples": examples,
                },
            )
            print(
                f"preserve_bugs={preserve_bugs} scale={scale}: {len(rows)} pass; old geometry/color failures {old_vertices}/{old_colors}",
            )
    assert all(r["before_vertex_failures"] == r["cases_with_quads"] for r in records)
    record = {
        "schema_version": 1,
        "kind": "python-laser-native-submissions",
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "current_sources": {path: sha((ROOT / path).read_bytes()) for path in (PROJECTILES, DRAW)},
        "before_commit": BEFORE_COMMIT,
        "before_projectiles_sha256": before_sha,
        "native_geometry_receipt_sha256": sha(receipt_path.read_bytes()),
        "native_fixture_sha256": sha(fixture_path.read_bytes()),
        "native_color_receipt_sha256": sha(colors_path.read_bytes()),
        "native_body_sha256": receipt["native_body_sha256"],
        "native_geometry_keys": len(geometry),
        "selected_fixture_indices": [r["index"] for r in rows],
        "runs": records,
        "boundaries": {
            "geometry": "Recorded native PC24 float corners, projected by the rewrite's per-axis viewport scale",
            "colors": "Recorded original Grim2D packed slots; Python alpha is already in (1e-3,1] for selected inputs",
            "ownership": "Both preserve_bugs modes; per-player mode selects the same player's independently recorded native corners",
            "calls": "Actual Python draw function with recording raylib calls; texture, UV, blend, and draw counts unchanged",
            "scope": "Submission identity for bounded fixtures; no GPU pixel, whole-frame, alpha-clamp, or simulation-state proof",
        },
    }
    (out / "port-results.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
