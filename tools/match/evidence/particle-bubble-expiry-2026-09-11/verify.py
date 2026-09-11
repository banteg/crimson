"""Recover native bubble-expiry witnesses for inactive creature targets."""

import argparse
import hashlib
import itertools
import json
import struct
from dataclasses import replace
from pathlib import Path

from execute import POOLS, Program, match, run, unicorn

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_layout(config, out):
    layout = {}
    for name, (count, size) in POOLS.items():
        layout[f"sizeof({name}) / sizeof({name}[0])"] = count
        layout[f"sizeof({name}[0])"] = size
    for owner, fields in {
        "particle_t": {
            "active": (0, 1),
            "render_flag": (1, 1),
            "intensity": (36, 4),
            "spin": (44, 4),
            "style_id": (48, 1),
            "target_id": (52, 4),
        },
        "creature_t": {"active": (0, 1), "pos_x": (20, 4), "pos_y": (24, 4), "flags": (140, 4)},
    }.items():
        for field, (offset, size) in fields.items():
            layout[f"offsetof({owner}, {field})"] = offset
            layout[f"sizeof((({owner} *)0)->{field})"] = size
    for name, size in (
        ("survival_recent_death_count", 4),
        ("survival_reward_fire_seen", 1),
        ("survival_reward_handout_enabled", 1),
    ):
        layout[f"sizeof(gameplay_run_state.{name})"] = size
    directory = out / "layout"
    directory.mkdir(exist_ok=True)
    source = (
        '#include "crimsonland_gameplay.h"\n#include "crimsonland_game_state_owner.h"\n'
        "#include <stddef.h>\n#define survival_recent_death_pos gameplay_run_state.survival_recent_death_pos\n"
        'extern "C" { unsigned int execution_offsets[] = {' + ", ".join(layout) + "}; }\n"
    )
    (directory / "scratch.cpp").write_text(source)
    obj = match.parse_coff_object(match.compile_scratch(replace(config, directory=directory)).read_bytes())
    symbol = next(row for row in obj.symbols if row.name == "_execution_offsets")
    raw = obj.sections[symbol.section_number - 1].data[symbol.value : symbol.value + len(layout) * 4]
    assert list(struct.unpack("<" + "I" * len(layout), raw)) == list(layout.values())
    return layout


def scenarios():
    cases = []
    for cw, count, bubbles, target, fire, handout in itertools.product(
        (0x7F, 0x37F),
        range(7),
        (1, 3),
        (0, 383),
        (0, 1),
        (0, 1),
    ):
        cases.append(
            {
                "fpcw": cw,
                "dt": 0.015625,
                "rng_seed": 20260911,
                "history_count": count,
                "fire_seen": fire,
                "handout_enabled": handout,
                "history_positions": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
                "creatures": [{"index": target, "active": 0, "x": 123.25, "y": 456.5, "flags": 0}],
                "particles": [
                    {"index": j * 63, "style": 8, "render": 0, "intensity": 0.8, "target": target}
                    for j in range(bubbles)
                ],
            },
        )
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    assert (
        sha(match.default_image_path().read_bytes())
        == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    )
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    p = Program(config)
    layout = check_layout(config, args.out)
    witnesses = []
    coverage = set()
    for index, case in enumerate(scenarios()):
        native = run(p, True, case)
        candidate = run(p, False, case)
        for key in ("state", "scalars", "calls", "writes", "rng_state", "rng_callers"):
            assert native[key] == candidate[key], (index, key)
        death_calls = [row for row in native["calls"] if row[0] == "creature_handle_death"]
        assert death_calls == [["creature_handle_death", case["creatures"][0]["index"], 0]] * len(case["particles"])
        assert not native["rng_callers"]
        assert not any(row[0] == "sfx_play_panned" for row in native["calls"])
        coverage.update(native["coverage"])
        witnesses.append(
            {
                "index": index,
                "input": case,
                "history_count": struct.unpack("<i", native["scalars"]["survival_recent_death_count"])[0],
                "fire_seen": native["scalars"]["survival_reward_fire_seen"][0],
                "handout_enabled": native["scalars"]["survival_reward_handout_enabled"][0],
                "history_positions": list(struct.unpack("<6f", native["state"]["survival_recent_death_pos"])),
                "death_calls": len(death_calls),
                "rng_state": native["rng_state"],
            },
        )
    encoded = json.dumps(witnesses, indent=2) + "\n"
    (args.out / "witnesses.json").write_text(encoded)
    regression_bytes = (json.dumps([row for row in witnesses if row["input"]["fpcw"] == 0x7F], indent=2) + "\n").encode()
    (args.out / "particle-bubble-expiry.json").write_bytes(regression_bytes)
    report = {
        "source_sha256": sha((config.directory / config.source).read_bytes()),
        "object_sha256": sha(p.object_path.read_bytes()),
        "body_sha256": sha(p.body.data),
        "build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "witnesses_sha256": sha(encoded.encode()),
        "shared_regressions_sha256": sha(regression_bytes),
        "cases": len(witnesses),
        "full_observation_matches": len(witnesses),
        "layout": layout,
        "native_helpers": {
            name: {"entry": entry, "instructions": len(pcs)} for name, (entry, pcs) in p.helpers.items()
        },
        "native_coverage": sorted(coverage),
    }
    (args.out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
