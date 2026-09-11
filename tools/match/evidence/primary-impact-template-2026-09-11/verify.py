"""Measure primary template recovery and preserve remaining PC64 decal debt."""

import argparse
import collections
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from execute import Program, match, run, unicorn
from fixtures import check_layout, scenarios
from recover import recover

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(program):
    result = program.result
    return {
        "source_sha256": sha((program.config.directory / program.config.source).read_bytes()),
        "object_sha256": sha(program.object_path.read_bytes()),
        "body_sha256": sha(program.body.data),
        "build_key": match._scratch_build_key(program.config, match.DEFAULT_MATCH_ROOT),
        "ratio": result.ratio,
        "instructions": len(result.candidate_disassembly),
        "references_ok": result.masked_operand_audit.ok_count,
        "reference_problems": result.masked_operand_audit.problem_count,
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
    }


def observation_digest(trace):
    data = {key: {name: value.hex() for name, value in trace[key].items()} for key in ("state", "scalars")}
    data.update({key: trace[key] for key in ("calls", "writes", "rng_state", "rng_callers")})
    return sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())


def call_residuals(native, candidate, before):
    assert len(native) == len(candidate) == len(before)
    residuals = []
    random_fx_index = -1
    for index, (n, c, b) in enumerate(zip(native, candidate, before, strict=True)):
        assert n[0] == c[0] == b[0], (index, n, c, b)
        if n[0] == "fx_queue_add_random":
            random_fx_index += 1
        if n != c:
            assert n != b, ("new call failure", index, n, b, c)
            residuals.append(
                {"index": index, "random_fx_slot": random_fx_index % 4, "native": n, "before": b, "recovered": c},
            )
    return residuals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--count", type=int, default=1000)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    assert (
        sha(match.default_image_path().read_bytes())
        == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    )
    before = (HERE / "before.cpp").read_text()
    assert sha(before.encode()) == "29ced950a9a07ed4972859045889678b2d6bceaded5a482c92b5dc2ab8bd23f0"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    sources = {
        "before": before,
        "flags": recover(before, scales=()),
        "scale": recover(before, flags=False),
        "recovered": recover(before),
        "all-scaled-vectors": recover(before, scales=(1, 2, 3)),
    }
    configs = {}
    for name, source in sources.items():
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / "scratch.cpp").write_text(source)
        configs[name] = replace(config, directory=directory)
    programs = {name: Program(c) for name, c in configs.items()}
    layout = check_layout(config, out)
    cases = list(scenarios(programs["before"], args.count))
    case_bytes = (json.dumps(cases, indent=2) + "\n").encode()
    (out / "cases.json").write_bytes(case_bytes)
    report = {
        "programs": {name: identity(p) for name, p in programs.items()},
        "layout": layout,
        "cases_sha256": sha(case_bytes),
        "cases_per_mode": len(cases),
        "modes": {},
    }
    for integrated in (False, True):
        mode = "native-damage-fx" if integrated else "recorded-damage-fx"
        if integrated:
            programs = {name: Program(c, integrated=True) for name, c in configs.items()}
        counts = {name: collections.Counter() for name in programs}
        native_digests = []
        residuals = []
        coverage = set()
        for index, case in enumerate(cases):
            native = run(programs["before"], True, case)
            traces = {name: run(program, False, case) for name, program in programs.items()}
            native_digests.append(observation_digest(native))
            coverage.update(native["coverage"])
            for name, trace in traces.items():
                for key in ("state", "scalars", "calls", "writes", "rng_state"):
                    counts[name][key + "_failures"] += trace[key] != native[key]
                assert trace["state"] == native["state"], (mode, index, name, "state")
                assert trace["scalars"] == native["scalars"], (mode, index, name, "scalars")
                assert trace["rng_state"] == native["rng_state"], (mode, index, name, "rng_state")
            assert traces["recovered"]["writes"] == native["writes"], (mode, index, "writes")
            assert traces["all-scaled-vectors"]["calls"] == native["calls"], (mode, index, "full alternate")
            retained = call_residuals(native["calls"], traces["recovered"]["calls"], traces["before"]["calls"])
            if retained:
                assert case["fpcw"] == 0x37F
                assert all(
                    row["random_fx_slot"] == 3 and row["native"][0] in ("fx_queue_add_random", "fx_queue_add")
                    for row in retained
                )
                residuals.append({"index": index, "residuals": retained})
        report["modes"][mode] = {
            "comparison_counts": {name: dict(count) for name, count in counts.items()},
            "retained_residuals": residuals,
            "native_observation_digests": native_digests,
            "native_coverage": sorted(coverage),
            "helpers": {
                name: {"entry": entry, "instructions": len(pcs)}
                for name, (entry, pcs) in programs["before"].helpers.items()
            },
        }
        print(mode, json.dumps(report["modes"][mode]["comparison_counts"]), flush=True)
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
