"""Measure particle impact recovery, retained residuals, and native port fixtures."""

import argparse
import collections
import hashlib
import importlib.util
import json
import struct
from dataclasses import replace
from pathlib import Path

from execute import CATEGORIES, POOLS, F, Program, match, run, unicorn
from fixtures import check_layout, fields, integrated_scenarios, scenarios
from recover import recover

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(p):
    result = p.result
    return {
        "source_sha256": sha((p.config.directory / p.config.source).read_bytes()),
        "object_sha256": sha(p.object_path.read_bytes()),
        "body_sha256": sha(p.body.data),
        "build_key": match._scratch_build_key(p.config, match.DEFAULT_MATCH_ROOT),
        "ratio": result.ratio,
        "candidate_instructions": len(result.candidate_disassembly),
        "target_instructions": len(result.target_disassembly),
        "references_ok": result.masked_operand_audit.ok_count,
        "reference_problems": result.masked_operand_audit.problem_count,
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
    }


def observations(trace, case, index):
    return {
        "index": index,
        "input": case,
        "particle": fields(trace, "particles", case["particles"][0]["index"]),
        "creature": fields(trace, "creatures", case["creatures"][0]["index"]),
        "sprites": [
            dict(index=j, **fields(trace, "sprites", j))
            for j in range(384)
            if trace["state"]["sprite_effect_pool"][j * 44]
        ],
        "calls": trace["calls"],
        "rng_state": trace["rng_state"],
        "rng_callers": trace["rng_callers"],
    }


def differences(a, b):
    return [key for key in ("state", "scalars", "calls", "writes", "rng_state") if a[key] != b[key]]


def compare_fields(native, candidate, before):
    residual = []
    for category, name in CATEGORIES.items():
        count, stride = POOLS[name]
        for index in range(count):
            for field, (offset, fmt) in F[category].items():
                start = index * stride + offset
                end = start + struct.calcsize(fmt)
                n, c, b = (row["state"][name][start:end] for row in (native, candidate, before))
                if c != n:
                    assert b != n, (category, index, field, "new field regression", n.hex(), c.hex(), b.hex())
                    residual.append(
                        {
                            "field": f"{category}[{index}].{field}",
                            "native": n.hex(),
                            "before": b.hex(),
                            "recovered": c.hex(),
                        },
                    )
    return residual


def nohit_cases():
    path = HERE.parent / "projectile-particle-update-2026-09-11/fixtures.py"
    spec = importlib.util.spec_from_file_location("nohit_fixtures", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.scenarios()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    assert sha(match.default_image_path().read_bytes()) == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    before = (HERE / "before.cpp").read_text()
    assert sha(before.encode()) == "eaa8170a3090ebbfa1e7ae61fec4a9d63f49be48ad692247b988d36d3b569a93"
    programs = {}
    for name, source in (
        ("before", before),
        ("scale", recover(before, displacement=False)),
        ("recovered", recover(before)),
        ("sdk-geometry", recover(before, sdk_geometry=True)),
    ):
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / "scratch.cpp").write_text(source)
        programs[name] = Program(replace(config, directory=directory))
    layout = check_layout(config, out)
    p = programs["recovered"]
    cases = scenarios(p)
    assert len(cases) == 1230
    (out / "cases.json").write_text(json.dumps(cases, indent=2) + "\n")
    counts = {name: collections.Counter() for name in programs}
    residuals = []
    coverage = {name: set() for name in ("native", *programs)}
    receipts = []
    for index, case in enumerate(cases):
        native = run(p, True, case)
        traces = {name: run(program, False, case) for name, program in programs.items()}
        coverage["native"].update(native["coverage"])
        for name, trace in traces.items():
            wrong = differences(native, trace)
            counts[name][",".join(wrong) or "equal"] += 1
            coverage[name].update(trace["coverage"])
            assert all(native[key] == trace[key] for key in ("scalars", "calls", "rng_state")), (index, name, wrong)
        assert traces["sdk-geometry"]["state"] == native["state"], (index, "sdk geometry state")
        remaining = compare_fields(native, traces["recovered"], traces["before"])
        if remaining:
            assert case["fpcw"] == 0x37F
            residuals.append({"index": index, "fields": remaining, "input": case})
        # Fields already on the wrong PC64 deflection branch can change again
        # when their final displacement gets its correct rounding boundary.
        # Record all three values above. Bytes outside named fields must remain
        # native-correct or retain the exact before-state, including padding.
        for name in POOLS:
            covered = set()
            for category, pool_name in CATEGORIES.items():
                if pool_name == name:
                    for offset, fmt in F[category].values():
                        covered.update(range(offset, offset + struct.calcsize(fmt)))
            stride = POOLS[name][1]
            for offset, (n, c, b) in enumerate(
                zip(
                    native["state"][name],
                    traces["recovered"]["state"][name],
                    traces["before"]["state"][name],
                    strict=True,
                ),
            ):
                if offset % stride not in covered:
                    assert c == n or c == b, (index, name, "new unobserved-byte regression")
        receipts.append(
            {
                "index": index,
                "native_state_sha256": sha(b"".join(native["state"].values())),
                "native_calls_sha256": sha(json.dumps(native["calls"]).encode()),
                "native_writes_sha256": sha(json.dumps(native["writes"]).encode()),
                "recovered_state_sha256": sha(b"".join(traces["recovered"]["state"].values())),
            },
        )
        if index % 200 == 0:
            print("impacts", index, "/", len(cases), flush=True)
    assert len(residuals) == 25
    # Prior full-pool no-hit proof remains exact in every observed dimension.
    prior = nohit_cases()
    for index, case in enumerate(prior):
        native = run(p, True, case)
        for name in ("recovered", "sdk-geometry"):
            assert not differences(native, run(programs[name], False, case)), (index, "nohit", name)
        if index % 800 == 0:
            print("no-hit", index, "/", len(prior), flush=True)
    integrated = Program(p.config, integrated=True)
    witnesses = []
    integrated_counts = collections.Counter()
    integrated_inputs = integrated_scenarios(cases)
    for index, case in enumerate(integrated_inputs):
        native = run(integrated, True, case)
        candidate = run(integrated, False, case)
        wrong = differences(native, candidate)
        assert all(native[key] == candidate[key] for key in ("state", "scalars", "calls", "rng_state")), (
            index,
            "integrated",
            wrong,
        )
        integrated_counts[",".join(wrong) or "equal"] += 1
        witnesses.append(observations(native, case, index))
    (out / "port-witnesses.json").write_text(json.dumps(witnesses, indent=2) + "\n")
    result = {
        "reference_sha256": sha(match.default_image_path().read_bytes()),
        "identities": {name: identity(program) for name, program in programs.items()},
        "helper_bodies": {
            name: {"address": entry, "instructions": len(pcs)} for name, (entry, pcs) in integrated.helpers.items()
        },
        "layout": layout,
        "impact_cases": len(cases),
        "cases_sha256": sha((out / "cases.json").read_bytes()),
        "comparisons": {name: dict(counter) for name, counter in counts.items()},
        "residuals": residuals,
        "nohit_cases": len(prior),
        "integrated_cases": len(witnesses),
        "integrated_comparisons": dict(integrated_counts),
        "port_witnesses_sha256": sha((out / "port-witnesses.json").read_bytes()),
        "coverage": {name: sorted(pcs) for name, pcs in coverage.items()},
        "observations_sha256": sha(json.dumps(receipts).encode()),
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("verified", {name: dict(count) for name, count in counts.items()}, "retained", len(residuals), flush=True)


if __name__ == "__main__":
    main()
