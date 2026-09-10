"""Replay bounded overlay calls, trail rounding, and a local encoded tint window."""

import argparse
import itertools
import json
import math
from dataclasses import replace
from pathlib import Path

import runner

HERE = Path(__file__).resolve().parent
FUNCTION = "player_render_overlays"
probe = runner.probe
sha, bits, f32 = runner.sha, runner.bits, runner.f32


def metrics(p):
    result = p.result
    return {
        "ratio": result.ratio,
        "candidate_instructions": len(result.candidate_lines),
        "target_instructions": len(result.target_lines),
        "references_ok": result.masked_operand_audit.ok_count,
        "reference_problems": result.masked_operand_audit.problem_count,
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
    }


def identity(p):
    return {
        "source_sha256": sha((p.config.directory / p.config.source).read_bytes()),
        "object_sha256": sha(p.object_path.read_bytes()),
        "body_sha256": sha(p.body.data),
        "build_key": runner.match._scratch_build_key(p.config, runner.match.DEFAULT_MATCH_ROOT),
        "relocations": p.relocations,
        "metrics": metrics(p),
    }


def line_frame(case, alpha=0.7, count=1, index=0):
    return {
        "alpha": alpha,
        "player_count": count,
        "overlay_index": index,
        "players": [{"index": index, "position": case["player"]}],
        "targets": [[0, *case["target"]]],
    }


def trail_quads(trace):
    active, count = False, 0
    for name, args in trace["calls"]:
        if name == "D3DXVec2Normalize":
            active = True
        elif name == "grim_end_batch":
            active = False
        elif active and name == "grim_draw_quad":
            assert args[2:] == [bits(32.0)] * 2
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert runner.unicorn.__version__ == "2.1.4"
    config = runner.match.load_scratch_config(runner.match.DEFAULT_MATCH_ROOT / "scratches" / FUNCTION)
    current = runner.Program(config)
    source = (config.directory / config.source).read_text()
    copy = "                    player_render_vec2_t normalized = render_delta;\n"
    normalize = "                    D3DXVec2Normalize(\n"
    assert source.count(copy) == source.count(normalize) == 1
    wrong_distance = source.replace(copy, "").replace(normalize, copy + normalize)
    alpha_copy = "memcpy(&a, &alpha, sizeof(a));"
    assert source.count(alpha_copy) == 1
    previous_source = (HERE / "previous-source.cpp").read_text()
    assert sha(previous_source.encode()) == "a50f2d9af1995c22fdc442ffb9411364a99590927aa408cbe8a02b4292ba1339"
    controls = {}
    for name, text in (
        ("distance", wrong_distance),
        ("tint", source.replace(alpha_copy, "a = alpha;")),
        ("previous", previous_source),
    ):
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_text(text)
        controls[name] = runner.Program(replace(config, directory=directory))
    # This window has no PC-relative operands; linked absolute relocations use native addresses.
    alpha_window = current.image.function_bytes(0x428C66, 0x428C8E)
    assert runner.linked_body(current).count(alpha_window) == 1
    assert runner.linked_body(controls["distance"]).count(alpha_window) == 1
    assert runner.linked_body(controls["tint"]).count(alpha_window) == 0
    assert runner.linked_body(controls["previous"]).count(alpha_window) == 0
    rows, negatives, examples = [], [], {}

    def check(label, frame, expected_quads=None, expected_distance=None):
        native = runner.run(current, True, frame)
        candidate = runner.run(current, False, frame)
        for key in ("calls", "writes", "distance_bits", "player_state_sha256", "creature_state_sha256"):
            assert native[key] == candidate[key], (label, key)
        if expected_quads is not None:
            assert trail_quads(native) == expected_quads, (label, trail_quads(native), expected_quads)
        if expected_distance is not None:
            assert native["distance_bits"] == expected_distance
        rows.append(
            {
                "label": label,
                "frame": frame,
                "call_trace_sha256": sha(json.dumps(native["calls"]).encode()),
                "writes": native["writes"],
                "distance_bits": native["distance_bits"],
                "trail_quads": trail_quads(native),
                "player_state_sha256": native["player_state_sha256"],
                "creature_state_sha256": native["creature_state_sha256"],
                "native_instructions_exercised": native["coverage"],
                "candidate_instructions_exercised": candidate["coverage"],
            },
        )
        return native

    cases = json.loads((HERE / "boundary-fixtures.json").read_text())
    for case in cases:
        dx, dy = (f32(f32(t) - f32(p)) for p, t in zip(case["player"], case["target"], strict=True))
        distance = f32(math.sqrt(dx * dx + dy * dy))
        assert bits(distance) == int(case["native_bits"], 16)
        for alpha, (count, index) in itertools.product((0.2, 0.7, 1.5), ((1, 0), (2, 0), (2, 1))):
            frame = line_frame(case, alpha, count, index)
            native = check(
                f"boundary-{case['radius']}-{alpha}-{count}-{index}",
                frame,
                math.ceil(distance / 8),
                [bits(distance)],
            )
            if (alpha, count, index) == (0.7, 1, 0):
                for name in ("distance", "previous"):
                    wrong = runner.run(controls[name], False, frame)
                    assert wrong["calls"] != native["calls"]
                    assert wrong["distance_bits"] == [int(case["candidate_bits"], 16)]
                    assert trail_quads(wrong) != trail_quads(native)
                    negatives.append(
                        {
                            "control": name,
                            "radius": case["radius"],
                            "native_distance_bits": native["distance_bits"],
                            "wrong_distance_bits": wrong["distance_bits"],
                            "native_quads": trail_quads(native),
                            "wrong_quads": trail_quads(wrong),
                        },
                    )
                tint = runner.run(controls["tint"], False, frame)
                assert tint["calls"] == native["calls"] and tint["writes"] == native["writes"]
                if case["radius"] == 8:
                    examples = {"native": native, "wrong_distance": wrong, "tint_calls_unchanged": True}
    for radius in (0.0, 7.9, 8.0, 8.1, 79.9, 80.0, 80.1):
        case = {"player": [0.0, 0.0], "target": [radius, 0.0]}
        accepted = radius <= 80
        check(
            f"axis-{radius}",
            line_frame(case),
            math.ceil(f32(radius) / 8) if accepted else 0,
            [bits(radius)] if accepted else [],
        )
    for field, value in (("line_perk", False), ("suppressed", 1), ("alpha", 0.0), ("alpha", -0.1)):
        frame = line_frame(cases[0])
        frame[field] = value
        check(f"gate-{field}-{value}", frame, 0, [])
    for trail in (0.0, 0.25, 0.25001):
        frame = line_frame(cases[0])
        frame["players"][0]["trail"] = trail
        check(f"trail-gate-{trail}", frame, 2 if trail > 0.25 else 0)
    for (count, index), health, flash, aim, shield, alpha in itertools.product(
        ((1, 0), (2, 0), (2, 1)),
        (0.0, 100.0),
        (0.0, 0.5),
        (0.3, -2.4),
        (0.0, 0.7),
        (0.2, 0.7, 1.5),
    ):
        frame = {
            "player_count": count,
            "overlay_index": index,
            "alpha": alpha,
            "line_perk": False,
            "players": [
                {"index": i, "position": pos, "health": health, "flash": flash, "aim_heading": aim, "shield": shield}
                for i, pos in enumerate(((100.23, 150.27), (220.31, 210.37)))
            ],
        }
        check(f"body-{count}-{index}-{health}-{flash}-{aim}-{shield}-{alpha}", frame, 0, [])
    assert current.result.ratio > controls["previous"].result.ratio
    assert current.result.masked_operand_audit.problem_count == 0
    assert not current.result.exact and not current.result.body_byte_exact
    record = {
        "schema_version": 1,
        "kind": "native-overlay-tint-trail",
        "new_source_matches": 0,
        "unicorn_version": runner.unicorn.__version__,
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "runner_sha256": sha(Path(runner.__file__).read_bytes()),
        "engine_sha256": sha(runner.ENGINE.read_bytes()),
        "fixtures_sha256": sha((HERE / "boundary-fixtures.json").read_bytes()),
        "image_sha256": sha(runner.match.default_image_path().read_bytes()),
        "native_body_sha256": sha(current.image.function_bytes(current.native_start, current.native_end)),
        "current": identity(current),
        "controls": {name: identity(p) for name, p in controls.items()},
        "alpha_window": {
            "start": "0x428c66",
            "end_exclusive": "0x428c8e",
            "bytes": alpha_window.hex(),
            "current_occurrences": 1,
            "distance_control_occurrences": 1,
            "tint_control_occurrences": 0,
            "previous_occurrences": 0,
        },
        "fixtures": rows,
        "negative_controls": negatives,
        "examples": examples,
        "boundaries": {
            "grim": "recording thiscall stubs; only initialized config value word compared",
            "effect_select_texture": "recording no-op",
            "perk_count_get": "explicit frame results",
            "D3DXVec2Normalize": "shared sqrt/divide float32 model; external DLL not executed",
            "math": "machine x87 and native crt_ftol, control word 0x037f",
            "UV_tables": "native image snapshot; no graphics backend or pixel comparison",
        },
    }
    (out / "results.json").write_text(json.dumps(record, indent=2, default=str) + "\n")
    print(
        f"{len(rows)} overlay fixtures agree; {len(negatives)} distance negatives rejected; local tint window verified.",
    )


if __name__ == "__main__":
    main()
