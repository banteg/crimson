"""Replay target-distance boundaries and the existing native creature controls."""

import argparse
import importlib.util
import itertools
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


recovery = module("retarget_recovery", HERE / "recover.py")
corpse = module("retarget_corpse_controls", HERE.parent / "creature-corpse-vectors-2026-09-13/verify.py")
legacy = corpse.legacy
engine = corpse.engine


def neighbor(value, delta):
    bits = struct.unpack("<I", struct.pack("<f", value))[0]
    return struct.unpack("<f", struct.pack("<I", bits + delta))[0]


def boundary_cases():
    for pair, arrangement, target, tick, pc, count in itertools.product(
        ((1, 2), (2, 1), (1, 1), (2, 3), (3, 4), (5, 6), (30, 40), (60, 80)),
        range(6),
        (0, 1),
        (0, 69),
        (0x37F, 0x7F),
        (1, 2),
    ):
        x, y = pair
        other = ((0, 0), (2 * x, 0), (0, 2 * y), (2 * x, 2 * y), (neighbor(2 * x, -1), 0), (neighbor(2 * x, 1), 0))[
            arrangement
        ]
        yield {
            "name": f"retarget-{x}-{y}-layout{arrangement}-target{target}-tick{tick}-pc{pc:03x}-players{count}",
            "tick": tick,
            "dt": 0,
            "dt_ms": 0,
            "player_count": count,
            "player_positions": [(0, 0), other],
            "player_health": [100, 100],
            "fpcw": pc,
            "creatures": [
                {
                    "pos_x": x,
                    "pos_y": y,
                    "target_player": target,
                    "health": 100,
                    "lifecycle_stage": 16,
                    "ai_mode": 2,
                    "move_speed": 0,
                    "size": 40,
                    "attack_cooldown": 1,
                },
            ],
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    before = (HERE / "before.cpp").read_text()
    assert legacy.sha(before.encode()) == recovery.BEFORE_SHA
    assert engine.unicorn.__version__ == "2.1.4"
    assert legacy.sha(engine.match.default_image_path().read_bytes()) == legacy.IMAGE_SHA256
    config = engine.match.load_scratch_config(engine.match.DEFAULT_MATCH_ROOT / "scratches/creature_update_all")
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    layout = corpse.fixtures.check_layout(config, args.out)
    sources = recovery.stages(before)
    programs = {name: legacy.build(config, args.out, name, source) for name, source in sources.items()}
    fixed = programs["recovered"]
    assert legacy.sha(fixed.program.body.data) == "67f3a0775f7bc8f685d5ccaaf7109bf25bc583430fc388c6f57cc9791ee332ce"
    failures = {name: [] for name in programs}
    boundary_rows = []
    cases = list(boundary_cases())
    assert len(cases) == 768
    for index, case in enumerate(cases):
        native = fixed.run(True, case)
        row = {"case": case, "native": legacy.observation(native), "candidates": {}}
        for name, program in programs.items():
            actual = program.run(False, case)
            changed = [key for key in legacy.KEYS if native[key] != actual[key]]
            if changed:
                failures[name].append({"case": index, "keys": changed})
            row["candidates"][name] = legacy.observation(actual)
        boundary_rows.append(row)
        if index % 100 == 0:
            print(f"Boundary cases {index + 1}/{len(cases)}", flush=True)
    assert {name: len(rows) for name, rows in failures.items()} == {
        "before": 28,
        "initial-distance": 28,
        "alternate-distance": 0,
        "solo-distance": 0,
        "recovered": 0,
    }, failures
    print("Boundary failures", {name: len(rows) for name, rows in failures.items()}, flush=True)
    prior = json.loads((corpse.HISTORICAL / "results.json").read_text())
    historical = corpse.fixtures.scenarios()
    interaction = list(corpse.interaction.boundary_cases())
    tiny = list(corpse.tiny_cases())
    assert (len(historical), len(interaction), len(tiny)) == (2472, 192, 48)
    rows = []
    for index, case in enumerate(historical + interaction + tiny):
        native = fixed.run(True, case)
        actual = fixed.run(False, case)
        changed = [key for key in legacy.KEYS if native[key] != actual[key]]
        assert not changed, (case["name"], changed)
        digest = legacy.observation(native)
        if index < len(historical):
            assert prior["rows"][index]["name"] == case["name"]
            assert prior["rows"][index]["native"] == digest
        rows.append({"name": case["name"], "native": digest, "recovered": legacy.observation(actual)})
        if index % 200 == 0:
            print(f"Regression cases {index + 1}/2712", flush=True)
    callbacks = []
    for case in corpse.callback_cases():
        for native in (True, False):
            ordinary = fixed.run(native, case)
            adapted, _ = corpse.interaction.run_callback_control(fixed, native, case, False)
            assert all(ordinary[key] == adapted[key] for key in legacy.KEYS)
        native, native_mutations = corpse.interaction.run_callback_control(fixed, True, case, True)
        actual, actual_mutations = corpse.interaction.run_callback_control(fixed, False, case, True)
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
    record = {
        "schema_version": 1,
        "kind": "creature-retarget-distance",
        "new_exact_matches": 0,
        "unicorn": engine.unicorn.__version__,
        "compiler": config.compiler,
        "cflags": config.cflags,
        "compiler_files_sha256": {
            name: legacy.sha(
                (engine.match.DEFAULT_MATCH_ROOT / "compilers" / config.compiler / "Bin" / name).read_bytes(),
            )
            for name in ("CL.EXE", "C1.DLL", "C1XX.DLL", "C2.DLL")
        },
        "native_body_sha256": legacy.sha(
            fixed.program.image.function_bytes(fixed.program.native_start, fixed.program.native_end),
        ),
        "matcher_sha256": legacy.sha(Path(engine.match.__file__).read_bytes()),
        "source_sha256": {name: legacy.sha(source.encode()) for name, source in sources.items()},
        "harness_sha256": {
            str(path.relative_to(HERE.parent)): legacy.sha(path.read_bytes())
            for path in (
                HERE / "recover.py",
                HERE / "verify.py",
                corpse.HERE / "verify.py",
                corpse.HERE / "recover.py",
                corpse.HISTORICAL / "execute.py",
                corpse.HISTORICAL / "verify.py",
                corpse.HISTORICAL / "fixtures.py",
                corpse.interaction.HERE / "verify.py",
                engine.ENGINE_PATH,
            )
        },
        "native_image_sha256": legacy.IMAGE_SHA256,
        "layout": layout,
        "metrics": {name: legacy.metric(program) for name, program in programs.items()},
        "boundary_failures": failures,
        "boundaries": boundary_rows,
        "regressions": rows,
        "callback_controls": callbacks,
        "historical_native_receipts_verified": True,
        "scope": "Finite native x86 observations with the existing explicit callback models; not a full match or whole-game equivalence proof.",
    }
    (args.out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print("PASS: 768 boundaries, 2712 regressions, 12 callback controls", flush=True)


if __name__ == "__main__":
    main()
