"""Replay creature interaction rounding and local-owner evidence against native x86."""

import argparse
import importlib.util
import math
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HISTORICAL = HERE.parent / "creature-state-publication-2026-09-11"
spec = importlib.util.spec_from_file_location("interaction_recovery", HERE / "recover.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
sys.path.insert(0, str(HISTORICAL))
import execute as engine
import fixtures as historical_fixtures
import verify as legacy

sys.path.pop(0)


def f32(value):
    return struct.unpack("<f", struct.pack("<f", value))[0]


def boundary_cases():
    pairs = []
    for i in range(1, 1000):
        x = f32(i * 0.1)
        y = f32(math.sqrt(10000 - x * x))
        length = math.hypot(x, y)
        if length < 100 and f32(length) == 100:
            pairs.append((x, y))
        if len(pairs) == 12:
            break
    assert len(pairs) == 12
    for i, (x, y) in enumerate(pairs):
        for axis, position in enumerate(((x, y), (y, x), (-x, y), (x, -y))):
            for enabled in (False, True):
                for fpcw in (0x37F, 0x7F):
                    yield {
                        "name": f"radius100-{i}-{axis}-{int(enabled)}-pc{fpcw:03x}",
                        "dt": 0,
                        "dt_ms": 0,
                        "tick": 69,
                        "player_positions": [(0, 0), (0, 0)],
                        "perks": [2] if enabled else [],
                        "fpcw": fpcw,
                        "creatures": [
                            {
                                "health": 100,
                                "lifecycle_stage": 16,
                                "ai_mode": 2,
                                "move_speed": 0,
                                "pos_x": position[0],
                                "pos_y": position[1],
                                "size": 40,
                                "flags": 0,
                                "collision_timer": -0.1,
                            },
                        ],
                    }


def run_callback_control(comparison, native, case, mutate):
    """Temporarily select player 1 between damage and normalization callbacks.

    This is an ABI dependency witness, not a claim that the real helpers change
    creature targets. The normal external-call models remain unchanged.
    """
    original = engine.unicorn.Uc
    program = comparison.program
    mutations = []

    def factory(*args, **kwargs):
        uc = original(*args, **kwargs)
        hook_add = uc.hook_add

        def add(kind, callback, *args, **kwargs):
            if kind == engine.unicorn.UC_HOOK_CODE:
                original_callback = callback

                def callback(uc, address, size, data):
                    if mutate and address in (
                        program.address("player_take_damage"),
                        program.address("D3DXVec2Normalize"),
                    ):
                        value = int(address == program.address("player_take_damage"))
                        slot = case["creatures"][0].get("index", 0)
                        target = program.address("creature_pool") + slot * 152 + engine.FIELDS["target_player"][0]
                        uc.mem_write(target, bytes([value]))
                        mutations.append([target, value])
                    original_callback(uc, address, size, data)

            return hook_add(kind, callback, *args, **kwargs)

        uc.hook_add = add
        return uc

    engine.unicorn.Uc = factory
    try:
        result = comparison.run(native, case)
    finally:
        engine.unicorn.Uc = original
    if mutate:
        assert [value for _, value in mutations] == [1, 0]
    return result, mutations


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
    layout = historical_fixtures.check_layout(config, args.out)
    programs = {name: legacy.build(config, args.out, name, text) for name, text in sources.items()}
    fixed = programs["contact-reload"]
    boundaries = list(boundary_cases())
    old_cases = historical_fixtures.scenarios()
    assert len(boundaries) == 192 and len(old_cases) == 2472
    rows, failures = [], {name: [] for name in programs}
    for index, case in enumerate(boundaries + old_cases):
        native = fixed.run(True, case)
        if index < len(boundaries):
            creature = case["creatures"][0]
            x, y = creature["pos_x"], creature["pos_y"]
            expected = math.hypot(x, y) < 100
            if case["fpcw"] == 0x7F:
                expected = f32(math.sqrt(f32(f32(x * x) + f32(y * y)))) < 100
            assert (["perk_count_get", 2] in native["calls"]) == expected
        row = {"name": case["name"], "native": legacy.observation(native), "candidates": {}}
        for name, program in programs.items():
            current = program.run(False, case)
            changed = [key for key in legacy.KEYS if native[key] != current[key]]
            if changed:
                failures[name].append({"index": index, "case": case["name"], "keys": changed})
            row["candidates"][name] = legacy.observation(current)
        rows.append(row)
        if index % 200 == 0:
            print(f"Verified {index + 1}/{len(boundaries) + len(old_cases)} cases", flush=True)
    assert all(not failures[name] for name in programs if name != "before"), failures
    assert len(failures["before"]) == 96
    assert all(row["index"] < 192 and row["case"].endswith("pc37f") for row in failures["before"])
    assert any("state" in row["keys"] for row in failures["before"])
    callback_rows = []
    for index, (x, y) in enumerate(((2, 10), (10, 2), (-2, 10), (10, -2), (3, 4), (-3, -4))):
        for fpcw in (0x37F, 0x7F):
            case = {
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
            for native in (True, False):
                ordinary = fixed.run(native, case)
                adapted, _ = run_callback_control(fixed, native, case, False)
                assert all(ordinary[k] == adapted[k] for k in legacy.KEYS)
            native, mutations = run_callback_control(fixed, True, case, True)
            current, current_mutations = run_callback_control(fixed, False, case, True)
            old, old_mutations = run_callback_control(programs["distance-local"], False, case, True)
            assert mutations == current_mutations == old_mutations
            assert all(native[k] == current[k] for k in legacy.KEYS)
            changed = [k for k in legacy.KEYS if native[k] != old[k]]
            assert "calls" in changed
            callback_rows.append(
                {
                    "case": case,
                    "mutations": mutations,
                    "native": legacy.observation(native),
                    "recovered": legacy.observation(current),
                    "old_differences": changed,
                },
            )
    manifest = {
        "image_sha256": legacy.IMAGE_SHA256,
        "native_body_sha256": legacy.sha(
            fixed.program.image.function_bytes(fixed.program.native_start, fixed.program.native_end),
        ),
        "compiler": config.compiler,
        "cflags": config.cflags,
        "source_sha256": {name: legacy.sha(s.encode()) for name, s in sources.items()},
        "harness_sha256": {
            str(p.relative_to(HERE.parent)): legacy.sha(p.read_bytes())
            for p in [
                HERE / "verify.py",
                HERE / "recover.py",
                HISTORICAL / "verify.py",
                HISTORICAL / "execute.py",
                HISTORICAL / "fixtures.py",
            ]
        },
        "layout": layout,
        "metrics": {name: legacy.metric(p) for name, p in programs.items()},
        "boundary_cases": len(boundaries),
        "historical_cases": len(old_cases),
        "failures": failures,
        "observations": rows,
        "callback_controls": callback_rows,
        "scope": "Finite native/candidate observations with shared callback models; PC64 boundary and transient ABI witnesses are diagnostic.",
    }
    (args.out / "results.json").write_bytes(legacy.serialize(manifest))
    print("PASS: 192 boundary, 2472 historical and 12 callback cases; old source rejected", flush=True)


if __name__ == "__main__":
    main()
