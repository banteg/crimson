"""Record native creature color arithmetic and Grim2D's packed output at PC24."""

import argparse
import hashlib
import importlib.util
import itertools
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent / "creature-hit-flash-2026-09-11/verify.py"
spec = importlib.util.spec_from_file_location("creature_color_parent", PARENT)
parent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)
frames, match = parent.frames, parent.match


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    colors = (
        (0.8, 0.7, 0.6, 0.9),
        (0.1, 0.2, 0.3, 1.0),
        (0.3333333432674408, 0.501, 0.999, 0.05),
        (0.0, 0.0, 0.0, 0.0),
        (1.0, 1.0, 1.0, 1.0),
        (0.2, 0.8, 0.4, 0.5000000596046448),
    )
    records = []
    for index, (tint, lifecycle) in enumerate(itertools.product(colors, (-2.0, -0.125, 0.0, 16.0))):
        records.append(
            {
                "index": index * 3,
                "type_id": 0,
                "active": 1,
                "flags": (0, 4)[index % 2],
                "pos_x": 128.0 + index * 64.0,
                "pos_y": 256.0 + index * 32.0,
                "size": (16.0, 32.5, 64.0, 200.0)[index % 4],
                "anim_phase": 4.2,
                "heading": 1.4,
                "lifecycle_stage": lifecycle,
                "hit_flash_timer": 0.15,
                "max_health": (100.0, 499.9999694824219, 500.0, 700.0)[index % 4],
                **dict(zip(("tint_r", "tint_g", "tint_b", "tint_a"), tint, strict=True)),
            },
        )
    # Keep an alive weak creature on the common tint, independently of corpse fading.
    records.append(dict(records[3], index=383, max_health=100.0, pos_x=3000.0))
    # Bounded out-of-unit diagnostics distinguish byte truncation from clamping.
    records.extend(
        [
            dict(records[3], index=381, pos_x=2800.0, tint_r=-0.1, tint_g=1.1, tint_b=0.3, tint_a=1.01),
            dict(records[3], index=382, pos_x=2900.0, tint_r=-0.25, tint_g=0.5, tint_b=1.25, tint_a=-0.1),
        ],
    )
    records.sort(key=lambda row: row["index"])
    for energy, transition in itertools.product(
        (0.0, 0.0001, 0.1, 0.3333333432674408, 0.5, 0.9999999403953552, 1.0, 1.5),
        (0.0, 0.001, 0.371, 0.8, 1.0),
    ):
        yield {
            "name": f"energy-{energy}-transition-{transition}",
            "type_id": 0,
            "energizer": parent.f32(energy),
            "transition": parent.f32(transition),
            "shadows": 1,
            "monster_vision": 0,
            "flash": 1,
            "fpcw": 0x7F,
            "creatures": records,
        }


def color_draws(case, calls, color):
    source, destination, batch = 5, 6, None
    rgba = frame = None
    records = case["creatures"]
    queues = {"shadow": records, "body": records, "flash": [row for row in records for _ in range(2)]}
    cursor = dict.fromkeys(queues, 0)
    draws = []
    for name, words in calls:
        if name == "grim_set_config_var":
            if words[0] == 19:
                source = words[1]
            elif words[0] == 20:
                destination = words[1]
        elif name == "grim_begin_batch":
            assert batch is None
            batch = {(1, 6): "shadow", (5, 6): "body", (5, 2): "flash"}[source, destination]
        elif name == "grim_end_batch":
            assert batch is not None
            batch = None
        elif name == "grim_set_atlas_frame":
            assert words[0] == 8
            frame = words[1]
        elif name == "grim_set_color_ptr":
            rgba = words
        elif name == "grim_draw_quad":
            assert batch is not None and rgba is not None and frame is not None
            record = queues[batch][cursor[batch]]
            cursor[batch] += 1
            x = struct.unpack("<f", struct.pack("<I", words[0]))[0]
            offset = record["size"] * 0.5 + (0.7 if batch == "shadow" else 0.0)
            assert abs(x - (record["pos_x"] + 13.25 - offset)) < 0.001
            packed = color(tuple(rgba))
            draws.append(
                {"pass": batch, "index": record["index"], "frame": frame, "rgba_bits": rgba, "packed_color": packed},
            )
    assert batch is None
    assert all(cursor[name] == len(values) for name, values in queues.items())
    return draws


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert parent.unicorn.__version__ == "2.1.4"
    assert (
        sha(match.default_image_path().read_bytes())
        == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    )
    config, source_sha = parent.build_config("creature_render_type", out)
    obj = match.compile_scratch(config, force=True)
    comparison = frames.Comparison(config, obj)
    layout = frames.parent.check_fixture_layout(config, out)
    native_color = parent.NativeColor()
    cache = {}

    def packed(words):
        if words not in cache:
            cache[words] = native_color.pack(words)
        return cache[words]

    witnesses, traces = [], []
    coverage = {"native": set(), "candidate": set()}
    for case in cases():
        result = comparison.compare(case)
        assert result["calls_equal"] and result["writes_equal"], case["name"]
        for side, offsets in coverage.items():
            offsets.update(result[side]["coverage"])
        expected = color_draws(case, result["native"]["calls"], packed)
        witnesses.append({"input": case, "expected": expected})
        traces.append(
            {
                "name": case["name"],
                "calls_sha256": sha(json.dumps(result["native"]["calls"]).encode()),
                "writes": result["native"]["writes"],
            },
        )
    raw = (json.dumps({"schema_version": 1, "fpcw": 0x7F, "cases": witnesses}, indent=2) + "\n").encode()
    (out / "witnesses.json").write_bytes(raw)
    result = {
        "script_sha256": sha(Path(__file__).read_bytes()),
        "parent_sha256": sha(PARENT.read_bytes()),
        "source_sha256": source_sha,
        "native_image_sha256": sha(match.default_image_path().read_bytes()),
        "grim_image_sha256": sha(match.default_image_path("grim.dll").read_bytes()),
        "native_body_sha256": sha(comparison.image.function_bytes(comparison.native_start, comparison.native_end)),
        "candidate_body_sha256": sha(comparison.body.data),
        "layout": layout,
        "witnesses_sha256": sha(raw),
        "cases": len(witnesses),
        "failing_comparisons": 0,
        "draws": sum(len(row["expected"]) for row in witnesses),
        "unique_packed_inputs": len(cache),
        "instruction_coverage": {side: sorted(offsets) for side, offsets in coverage.items()},
        "color_instruction_coverage": sorted(native_color.coverage),
        "color_ftol_import_address": native_color.ftol_import,
        "color_ftol_binding": "Grim2D imported _ftol is modeled by the game's original CRT converter",
        "color_ftol_game_address": native_color.ftol_start,
        "traces": traces,
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps({name: result[name] for name in ("cases", "draws", "unique_packed_inputs", "failing_comparisons")}),
    )
    case = next(
        row for row in witnesses if row["input"]["energizer"] == 0.0 and row["input"]["transition"] == parent.f32(0.8)
    )
    print(json.dumps(next(row for row in case["expected"] if row["pass"] == "body" and row["index"] == 383)))


if __name__ == "__main__":
    main()
