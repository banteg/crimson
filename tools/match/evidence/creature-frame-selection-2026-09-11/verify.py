"""Export native creature-frame witnesses without changing the matching source."""

import argparse
import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from fixtures import TYPE_INFO, scenarios
from runner import PARENT, Comparison, atlas_batches, parent

HERE = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert parent.unicorn.__version__ == "2.1.4"
    match = parent.match
    assert (
        sha(match.default_image_path().read_bytes())
        == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    )
    assert sha(PARENT.read_bytes()) == "34bd1380f39c3b49aa2d9876dc62444e18d93720311ceef7e2aa169d4cd4f9db"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/creature_render_type")
    layout = parent.check_fixture_layout(config, args.out)
    object_path = match.compile_scratch(config)
    comparison = Comparison(config, object_path)
    cases = scenarios()
    (args.out / "cases.json").write_bytes(json_bytes(cases))
    # Writing the parent's original (5, 1) table through the new fixture must
    # reproduce every observation, including instruction coverage and writes.
    fixture_controls = []
    original = parent.Comparison(config, object_path)
    for case in cases:
        if not case["name"].startswith("lifecycle"):
            continue
        control = copy.deepcopy(case)
        control["type_info"] = [(5, 1)] * 6
        for side in ("native", "candidate"):
            assert comparison.execute(side, control) == original.execute(side, control)
        fixture_controls.append(case["name"])
    rows, witnesses, coverage = [], [], [set(), set()]
    pc24_frames, pc64_differences = {}, []
    for case in cases:
        result = comparison.compare(case)
        assert result["calls_equal"] and result["writes_equal"], case["name"]
        batches = atlas_batches(result["native"]["calls"])
        records = sorted(case["creatures"], key=lambda record: record["index"])
        assert len(batches) == 3 and all(len(batch) == len(records) for batch in batches)
        assert batches[0] == batches[1], "Shadow and main frame selection differ"
        for record, frame, flash_frame in zip(records, batches[1], batches[2], strict=True):
            key = (case["name"].rsplit("-cw-", 1)[0], record["index"])
            if case["fpcw"] == 0x7F:
                pc24_frames[key] = frame
                base, mirror = TYPE_INFO[case["type_id"]]
                witnesses.append(
                    {
                        "case": case["name"],
                        "slot": record["index"],
                        "type_id": case["type_id"],
                        "base_frame": base,
                        "mirror_long": bool(mirror),
                        "flags": record["flags"],
                        "lifecycle_stage": record["lifecycle_stage"],
                        "phase": record["anim_phase"],
                        "frame": frame,
                        "flash_frame": flash_frame,
                    },
                )
            elif pc24_frames[key] != frame:
                pc64_differences.append(
                    {"case": case["name"], "slot": record["index"], "pc24": pc24_frames[key], "pc64": frame},
                )
        rows.append(
            {
                "case": case["name"],
                "creatures": len(records),
                "calls": len(result["native"]["calls"]),
                "calls_sha256": sha(json_bytes(result["native"]["calls"])),
                "writes_sha256": sha(json_bytes(result["native"]["writes"])),
            },
        )
        for index, side in enumerate(("native", "candidate")):
            coverage[index].update(result[side]["coverage"])
        print(f"{case['name']}: {len(records)} creatures agree", flush=True)
    source = (config.directory / config.source).read_text()
    controls = []
    for name, old, new in (
        (
            "drop-dead-shock-offset",
            "if ((flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) != 0)",
            "if (creature->lifecycle_stage >= 0.0f && (flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) != 0)",
        ),
        ("early-alive-frame", "creature->lifecycle_stage < 16.0f", "creature->lifecycle_stage < 15.0f"),
    ):
        assert old in source
        directory = args.out / name
        directory.mkdir(exist_ok=True)
        mutated = source.replace(old, new)
        (directory / config.source).write_text(mutated)
        changed_object = match.compile_scratch(replace(config, directory=directory))
        case = next(case for case in cases if case["name"] == "lifecycle-type-3-cw-007f")
        result = Comparison(config, changed_object).compare(case)
        assert not result["calls_equal"], name
        controls.append(
            {
                "name": name,
                "source_sha256": sha(mutated.encode()),
                "case": case["name"],
                "calls_equal": result["calls_equal"],
                "writes_equal": result["writes_equal"],
            },
        )
    witness_data = {
        "schema_version": 1,
        "kind": "native-creature-frame-selection",
        "fpcw": 0x7F,
        "witnesses": witnesses,
    }
    witness_raw = json_bytes(witness_data)
    (args.out / "witnesses.json").write_bytes(witness_raw)
    matching = match.run_match(
        obj_path=object_path,
        function=config.function,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    result = {
        "schema_version": 1,
        "kind": "native-creature-frame-selection-audit",
        "scope": "Exact call and observed write equality for these PC24/PC64 native and C++ fixtures; PC24 shadow/body frame witnesses for ports. No GPU or all-input proof.",
        "sources": {name: sha((HERE / name).read_bytes()) for name in ("fixtures.py", "runner.py", "verify.py")},
        "parent_sha256": sha(PARENT.read_bytes()),
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "source_sha256": sha(source.encode()),
        "candidate_body_sha256": sha(comparison.body.data),
        "unicorn": parent.unicorn.__version__,
        "fixture_layout": layout,
        "fixture_controls": fixture_controls,
        "cases_sha256": sha(json_bytes(cases)),
        "witnesses_sha256": sha(witness_raw),
        "witness_count": len(witnesses),
        "coverage": {side: sorted(values) for side, values in zip(("native", "candidate"), coverage, strict=True)},
        "matching": {
            "ratio": matching.ratio,
            "candidate_instructions": len(matching.candidate_lines),
            "target_instructions": len(matching.target_lines),
            "references": [
                matching.masked_operand_audit.ok_count,
                matching.masked_operand_audit.unresolved_count,
                matching.masked_operand_audit.problem_count,
            ],
            "exact": matching.exact,
            "body_byte_exact": matching.body_byte_exact,
        },
        "negative_controls": controls,
        "pc64_frame_differences": pc64_differences,
        "cases": rows,
    }
    (args.out / "results.json").write_bytes(json_bytes(result))
    print(f"Exported {len(witnesses)} PC24 witnesses; {len(pc64_differences)} frame differences at PC64", flush=True)


if __name__ == "__main__":
    main()
