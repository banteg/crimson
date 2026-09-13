"""Replay corpse vector rounding against native x86 and existing creature cases."""

import argparse
import importlib.util
import itertools
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HISTORICAL = HERE.parent / "creature-state-publication-2026-09-11"
INTERACTION = HERE.parent / "creature-interaction-boundaries-2026-09-13"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


recovery = module("corpse_recovery", HERE / "recover.py")
sys.path.insert(0, str(HISTORICAL))
import execute as engine
import fixtures
import verify as legacy

sys.path.pop(0)
interaction = module("corpse_interaction_controls", INTERACTION / "verify.py")


def tiny_cases():
    def f32(bits):
        return struct.unpack("<f", struct.pack("<I", bits))[0]

    for bits, flags, fpcw, xy in itertools.product(
        (1, 3, 5, 0x7FFFFF, 0x800001, 0x1000001),
        (0, 4),
        (0x7F, 0x37F),
        (0, 3),
    ):
        yield {
            "name": f"corpse-{bits:x}-{flags}-pc{fpcw:03x}-{xy}",
            "dt": 0.1,
            "dt_ms": 100,
            "violence": 0,
            "queued": 1,
            "fpcw": fpcw,
            "creatures": [
                {
                    "lifecycle_stage": 0.1,
                    "health": 0,
                    "pos_x": f32(xy),
                    "pos_y": f32(xy),
                    "size": f32(bits),
                    "flags": flags,
                    "heading": 1.0,
                },
            ],
        }


def callback_cases():
    for index, (x, y) in enumerate(((2, 10), (10, 2), (-2, 10), (10, -2), (3, 4), (-3, -4))):
        for fpcw in (0x37F, 0x7F):
            yield {
                "name": f"contact-target-{index}-pc{fpcw:03x}",
                "dt": 0,
                "dt_ms": 0,
                "player_positions": [(0, 0), (10, 0)],
                "fpcw": fpcw,
                "creatures": [
                    {
                        "health": 100,
                        "lifecycle_stage": 16,
                        "ai_mode": 2,
                        "move_speed": 0,
                        "pos_x": x,
                        "pos_y": y,
                        "size": 40,
                        "attack_cooldown": 0,
                    },
                ],
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert engine.unicorn.__version__ == "2.1.4"
    assert legacy.sha(engine.match.default_image_path().read_bytes()) == legacy.IMAGE_SHA256
    before = (HERE / "before.cpp").read_text()
    assert legacy.sha(before.encode()) == recovery.BEFORE_SHA256
    sources = recovery.stages(before)
    config = engine.match.load_scratch_config(engine.match.DEFAULT_MATCH_ROOT / "scratches/creature_update_all")
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    layout = fixtures.check_layout(config, args.out)
    programs = {name: legacy.build(config, args.out, name, source) for name, source in sources.items()}
    fixed = programs["recovered"]
    assert legacy.sha(fixed.program.body.data) == "a2e7176ed1768b37c7c81142fc624393c05c4df7cf6e8bfe3a8aeaeb7266e3aa"
    result = fixed.program.result
    assert not result.exact and not result.body_byte_exact
    assert result.candidate_lines[0] == result.target_lines[0] == "sub esp, 0x7c"
    assert result.prefix_instructions == 10
    assert legacy.metric(fixed)["references"] == [228, 0, 1]
    tiny_rows, failures = [], {name: [] for name in programs}
    cases = list(tiny_cases())
    assert len(cases) == 48
    for index, case in enumerate(cases):
        native = fixed.run(True, case)
        row = {"case": case, "native": legacy.observation(native), "candidates": {}}
        for name, program in programs.items():
            actual = program.run(False, case)
            changed = [key for key in legacy.KEYS if native[key] != actual[key]]
            if changed:
                failures[name].append({"case": index, "keys": changed})
            row["candidates"][name] = legacy.observation(actual)
        tiny_rows.append(row)
    assert {name: len(rows) for name, rows in failures.items()} == {
        "before": 24,
        "ordinary-vector": 12,
        "both-vectors": 0,
        "recovered": 0,
    }, failures
    print("PASS: 48 tiny-size cases; before and one-arm controls rejected", flush=True)
    prior = json.loads((HISTORICAL / "results.json").read_text())
    old_cases = fixtures.scenarios()
    boundaries = list(interaction.boundary_cases())
    assert len(old_cases) == 2472 and len(boundaries) == 192
    rows = []
    for index, case in enumerate(old_cases + boundaries):
        native = fixed.run(True, case)
        actual = fixed.run(False, case)
        changed = [key for key in legacy.KEYS if native[key] != actual[key]]
        assert not changed, (case["name"], changed)
        digest = legacy.observation(native)
        if index < len(old_cases):
            assert prior["rows"][index]["name"] == case["name"]
            assert prior["rows"][index]["native"] == digest
        rows.append({"name": case["name"], "native": digest, "recovered": legacy.observation(actual)})
        if index % 200 == 0:
            print(f"Verified {index + 1}/{len(old_cases) + len(boundaries)} regression cases", flush=True)
    callbacks = []
    for case in callback_cases():
        for native in (True, False):
            ordinary = fixed.run(native, case)
            adapted, _ = interaction.run_callback_control(fixed, native, case, False)
            assert all(ordinary[key] == adapted[key] for key in legacy.KEYS)
        native, native_mutations = interaction.run_callback_control(fixed, True, case, True)
        actual, actual_mutations = interaction.run_callback_control(fixed, False, case, True)
        assert native_mutations == actual_mutations
        assert all(native[key] == actual[key] for key in legacy.KEYS), case["name"]
        callbacks.append(
            {
                "name": case["name"],
                "mutations": native_mutations,
                "native": legacy.observation(native),
                "recovered": legacy.observation(actual),
            },
        )
    harness_paths = [
        HERE / "verify.py",
        HERE / "recover.py",
        INTERACTION / "verify.py",
        INTERACTION / "recover.py",
        HISTORICAL / "verify.py",
        HISTORICAL / "execute.py",
        HISTORICAL / "fixtures.py",
    ]
    record = {
        "schema_version": 1,
        "function": config.function,
        "unicorn": engine.unicorn.__version__,
        "image_sha256": legacy.IMAGE_SHA256,
        "native_body_sha256": legacy.sha(
            fixed.program.image.function_bytes(fixed.program.native_start, fixed.program.native_end),
        ),
        "source_sha256": {name: legacy.sha(source.encode()) for name, source in sources.items()},
        "compiler": config.compiler,
        "cflags": config.cflags,
        "compiler_files_sha256": {
            name: legacy.sha(
                (engine.match.DEFAULT_MATCH_ROOT / "compilers" / config.compiler / "Bin" / name).read_bytes(),
            )
            for name in ("CL.EXE", "C1.DLL", "C1XX.DLL", "C2.DLL")
        },
        "harness_sha256": {str(path.relative_to(HERE.parent)): legacy.sha(path.read_bytes()) for path in harness_paths},
        "engine_sha256": legacy.sha(engine.ENGINE_PATH.read_bytes()),
        "matcher_sha256": legacy.sha(Path(engine.match.__file__).read_bytes()),
        "layout": layout,
        "metrics": {name: legacy.metric(program) for name, program in programs.items()},
        "tiny_cases": len(cases),
        "tiny_failures": failures,
        "tiny_observations": tiny_rows,
        "historical_cases": len(old_cases),
        "interaction_boundary_cases": len(boundaries),
        "historical_native_receipts_verified": True,
        "regression_observations": rows,
        "callback_controls": callbacks,
        "scope": "Finite native x86 observations with shared callback models. Tiny/subnormal sizes are diagnostic inputs, not claimed gameplay occurrences. No exact match claim.",
    }
    (args.out / "results.json").write_bytes(legacy.serialize(record))
    print("PASS: 48 tiny, 2472 historical, 192 interaction and 12 callback cases", flush=True)


if __name__ == "__main__":
    main()
