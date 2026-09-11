"""Verify recovered particle vector boundaries against bounded native trajectories."""

import argparse
import hashlib
import json
import struct
from dataclasses import replace
from pathlib import Path

from execute import F, Program, match, run, unicorn
from fixtures import check_layout, scenarios
from recover import recover

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(p):
    r = p.result
    return {
        "source_sha256": sha((p.config.directory / p.config.source).read_bytes()),
        "object_sha256": sha(p.object_path.read_bytes()),
        "body_sha256": sha(p.body.data),
        "build_key": match._scratch_build_key(p.config, match.DEFAULT_MATCH_ROOT),
        "ratio": r.ratio,
        "candidate_instructions": len(r.candidate_disassembly),
        "target_instructions": len(r.target_disassembly),
        "references_ok": r.masked_operand_audit.ok_count,
        "reference_problems": r.masked_operand_audit.problem_count,
        "exact": r.exact,
        "body_byte_exact": r.body_byte_exact,
    }


def observations(trace, frame):
    result = []
    for item in sorted(frame["particles"], key=lambda x: x["index"]):
        index = item["index"]
        result.append(
            dict(
                index=index,
                **{
                    name: struct.unpack_from("<" + fmt, trace["state"]["particle_pool"], index * 56 + offset)[0]
                    for name, (offset, fmt) in F["particles"].items()
                },
            ),
        )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    before = (HERE / "before.cpp").read_text()
    assert sha(before.encode()) == "7245eccc7426b22b561a90b4d4a024f3c6d769c274f24cc760b034043973edc1"
    programs = {}
    for name, source in (
        ("before", before),
        ("vectors", recover(before, angle_owner=False)),
        ("recovered", recover(before)),
        ("velocity-owner", recover(before, angle_owner=False, velocity_owner=True)),
    ):
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / "scratch.cpp").write_text(source)
        programs[name] = Program(replace(config, directory=directory))
    layout = check_layout(config, out)
    assert recover(before) == (config.directory / config.source).read_text()
    p = programs["recovered"]
    cases = scenarios()
    (out / "cases.json").write_text(json.dumps(cases, indent=2) + "\n")
    keys = ("state", "scalars", "calls", "writes", "rng_state")
    negatives = {name: {"count": 0, "examples": []} for name in ("before", "vectors")}
    coverage = {key: set() for key in ("native", "candidate")}
    rows = []
    witnesses = []
    for i, case in enumerate(cases):
        native = run(p, True, case)
        candidate = run(p, False, case)
        bad = [key for key in keys if native[key] != candidate[key]]
        assert not bad, (i, case, bad)
        alternate = run(programs["velocity-owner"], False, case)
        assert all(native[key] == alternate[key] for key in keys), (i, case, "velocity-owner")
        coverage["native"].update(native["coverage"])
        coverage["candidate"].update(candidate["coverage"])
        for name, record in negatives.items():
            if not case.get("particles"):
                continue
            control = run(programs[name], False, case)
            wrong = [key for key in keys if native[key] != control[key]]
            if wrong:
                record["count"] += 1
                if len(record["examples"]) < 12:
                    record["examples"].append(
                        {
                            "index": i,
                            "input": case,
                            "differences": wrong,
                            "native": observations(native, case),
                            "control": observations(control, case),
                        },
                    )
        rows.append(
            {
                "index": i,
                "state_sha256": sha(b"".join(native["state"].values())),
                "calls_sha256": sha(json.dumps(native["calls"]).encode()),
                "writes_sha256": sha(json.dumps(native["writes"]).encode()),
            },
        )
        if (
            case.get("particles")
            and case.get("fpcw", 0x7F) == 0x7F
            and all(item["style"] in (0, 1, 2, 8) for item in case["particles"])
        ):
            witnesses.append(
                {
                    "index": i,
                    "input": case,
                    "particles": observations(native, case),
                    "rng_state": native["rng_state"],
                    "draws": [call[1] for call in native["calls"] if call[0] == "crt_rand"],
                    "rng_callers": native["rng_callers"],
                },
            )
        if i % 400 == 0:
            print("verified", i, "/", len(cases), flush=True)
    assert all(row["count"] > 0 for row in negatives.values())
    result = {
        "reference_sha256": sha(match.default_image_path().read_bytes()),
        "identities": {name: identity(p) for name, p in programs.items()},
        "layout": layout,
        "cases": len(cases),
        "cases_sha256": sha((out / "cases.json").read_bytes()),
        "negative_controls": negatives,
        "coverage": {key: sorted(value) for key, value in coverage.items()},
        "observations_sha256": sha(json.dumps(rows).encode()),
        "port_witnesses": len(witnesses),
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    (out / "port-witnesses.json").write_text(json.dumps(witnesses, indent=2) + "\n")
    print(
        "verified",
        len(cases),
        "negative counts",
        {name: row["count"] for name, row in negatives.items()},
        flush=True,
    )


if __name__ == "__main__":
    main()
