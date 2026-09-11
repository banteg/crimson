"""Record native creature sprite pass order and unclamped draw dimensions."""

import argparse
import hashlib
import itertools
import json
import math
import struct
import sys
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent / "creature-frame-selection-2026-09-11"
sys.path.insert(0, str(PARENT))
import runner

match = runner.parent.match
SPECIES = (0, 3, 4, 2, 1)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def cases():
    records = []
    for ordinal, (size, kind) in enumerate(itertools.product((8.0, 16.0, 32.5, 64.0, 128.0, 200.0), (4, 0, 1, 3, 2))):
        records.append(
            {
                "index": ordinal * 3,
                "type_id": kind,
                "active": 1,
                "size": size,
                "pos_x": 128.0 + ordinal * 64.0,
                "pos_y": 256.0 + ordinal * 32.0,
                "heading": 1.4,
                "anim_phase": 4.2,
                "flags": 4 if ordinal % 2 else 0,
                "lifecycle_stage": (16.0, -0.25, 7.0)[ordinal % 3],
                "hit_flash_timer": 0.15 if ordinal % 7 else 0.0,
                "max_health": 100.0 if ordinal % 3 else 700.0,
                "tint_r": 0.8,
                "tint_g": 0.7,
                "tint_b": 0.6,
                "tint_a": 0.9,
            },
        )
    records.extend(
        [
            dict(records[0], index=380, type_id=5, pos_x=3000.0),
            dict(records[1], index=381, active=0, pos_x=3100.0),
            dict(records[3], index=382, lifecycle_stage=-11.0, size=200.0, pos_x=3200.0),
            dict(records[1], index=383, size=4.0, pos_x=3300.0),
        ],
    )
    for shadows, vision, flash, energy in itertools.product((0, 1), (0, 1), (0, 1), (0.0, 0.5)):
        yield {
            "name": f"shadows-{shadows}-vision-{vision}-flash-{flash}-energy-{energy}",
            "shadows": shadows,
            "monster_vision": vision,
            "flash": flash,
            "energizer": energy,
            "fpcw": 0x7F,
            "transition": 0.8,
            "creatures": records,
        }


def sprite_draws(calls, case, kind):
    source, destination, batch = 5, 6, None
    frame = rotation = None
    active = [r for r in case["creatures"] if r["active"] and r["type_id"] == kind]
    queues = {
        "shadow": active if case["shadows"] and not case["monster_vision"] else [],
        "body": active,
        "flash": [r for r in active if r["hit_flash_timer"] > 0.0 and r["lifecycle_stage"] >= -10.0 for _ in range(2)]
        if case["flash"]
        else [],
    }
    cursors = dict.fromkeys(queues, 0)
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
        elif name == "grim_set_rotation":
            rotation = words[0]
        elif name == "grim_draw_quad":
            assert batch is not None and frame is not None and rotation is not None
            record = queues[batch][cursors[batch]]
            cursors[batch] += 1
            if batch != "shadow":
                size_bits = struct.unpack("<I", struct.pack("<f", record["size"]))[0]
                assert words[2:] == [size_bits, size_bits]
            assert words[2] == words[3]
            x, y = struct.unpack("<2f", struct.pack("<2I", *words[:2]))
            offset = record["size"] * 0.5 + (0.7 if batch == "shadow" else 0.0)
            # Bind each label to its native position; fixture spacing exceeds
            # this PC24 tolerance by several orders of magnitude.
            assert math.isclose(x, record["pos_x"] + 13.25 - offset, rel_tol=0, abs_tol=0.001)
            assert math.isclose(y, record["pos_y"] - 18.5 - offset, rel_tol=0, abs_tol=0.001)
            draws.append(
                {
                    "pass": batch,
                    "index": record["index"],
                    "type_id": kind,
                    "frame": frame,
                    "quad_bits": words,
                    "rotation_bits": rotation,
                },
            )
    assert batch is None
    assert all(cursors[name] == len(values) for name, values in queues.items())
    assert [row["pass"] for row in draws] == [name for name, values in queues.items() for _ in values]
    return draws


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert runner.parent.unicorn.__version__ == "2.1.4"
    assert (
        sha(match.default_image_path().read_bytes())
        == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    )
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/creature_render_type")
    directory = out / "current"
    directory.mkdir(exist_ok=True)
    source = (config.directory / config.source).read_bytes()
    (directory / config.source).write_bytes(source)
    config = replace(config, directory=directory)
    obj = match.compile_scratch(config, force=True)
    comparison = runner.Comparison(config, obj)
    layout = runner.parent.check_fixture_layout(config, out)
    inputs = list(cases())
    witnesses, traces = [], []
    coverage = {"native": set(), "candidate": set()}
    for case in inputs:
        expected = []
        for kind in SPECIES:
            result = comparison.compare(dict(case, type_id=kind))
            assert result["calls_equal"] and result["writes_equal"], (case["name"], kind)
            for side, offsets in coverage.items():
                offsets.update(result[side]["coverage"])
            expected.extend(sprite_draws(result["native"]["calls"], case, kind))
            traces.append(
                {
                    "case": case["name"],
                    "type_id": kind,
                    "calls_sha256": sha(json.dumps(result["native"]["calls"]).encode()),
                    "writes": result["native"]["writes"],
                },
            )
        witnesses.append({"input": case, "expected": expected})
    data = {"schema_version": 1, "species_order": SPECIES, "cases": witnesses}
    encoded = (json.dumps(data, indent=2) + "\n").encode()
    (out / "witnesses.json").write_bytes(encoded)
    metrics = match.run_match(
        obj_path=obj, function=config.function, symbol_name=config.symbol, reference_aliases=config.reference_aliases,
    )
    result = {
        "script_sha256": sha(Path(__file__).read_bytes()),
        "source_sha256": sha(source),
        "native_image_sha256": sha(match.default_image_path().read_bytes()),
        "native_body_sha256": sha(comparison.image.function_bytes(comparison.native_start, comparison.native_end)),
        "candidate_body_sha256": sha(comparison.body.data),
        "parent_files": {
            str(path.relative_to(HERE.parent)): sha(path.read_bytes())
            for path in (PARENT / "runner.py", PARENT / "fixtures.py", runner.PARENT)
        },
        "layout": layout,
        "witnesses_sha256": sha(encoded),
        "scenarios": len(inputs),
        "native_candidate_comparisons": len(traces),
        "failing_comparisons": 0,
        "instruction_coverage": {side: sorted(offsets) for side, offsets in coverage.items()},
        "draws": sum(len(row["expected"]) for row in witnesses),
        "match": {
            "ratio": metrics.ratio,
            "instructions": len(metrics.candidate_lines),
            "references_ok": metrics.masked_operand_audit.ok_count,
            "reference_problems": metrics.masked_operand_audit.problem_count,
            "exact": metrics.exact,
            "body_byte_exact": metrics.body_byte_exact,
        },
        "traces": traces,
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                name: result[name]
                for name in ("scenarios", "native_candidate_comparisons", "failing_comparisons", "draws")
            },
        ),
    )


if __name__ == "__main__":
    main()
