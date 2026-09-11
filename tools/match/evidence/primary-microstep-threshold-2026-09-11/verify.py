"""Compare native and C++ microstep cadence, movement, and player damage."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

from execute import CATEGORIES, POOLS, F, Program, match, run, unicorn
from fixtures import COLLISION_SEEDS, check_layout, movement_cases, player_cases


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fields(trace, category, index):
    name = CATEGORIES[category]
    return {
        field: struct.unpack_from("<" + fmt, trace["state"][name], index * POOLS[name][1] + offset)[0]
        for field, (offset, fmt) in F[category].items()
    }


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
    native_digests = []

    def check(case):
        native, candidate = run(p, True, case), run(p, False, case)
        index = len(witnesses)
        for key in ("state", "scalars", "calls", "writes", "rng_state", "rng_callers"):
            assert native[key] == candidate[key], (index, key)
        assert not native["rng_callers"]
        observations = {key: {name: data.hex() for name, data in native[key].items()} for key in ("state", "scalars")}
        observations.update({key: native[key] for key in ("calls", "writes", "rng_state", "rng_callers")})
        native_digests.append(sha(json.dumps(observations, sort_keys=True, separators=(",", ":")).encode()))
        coverage.update(native["coverage"])
        queries = [
            list(struct.unpack("<2f", struct.pack("<2I", *call[1])))
            for call in native["calls"]
            if call[0] == "creature_find_in_radius"
        ]
        assert len(queries) == sum(call[0] == "vec2_add" for call in native["calls"])
        witnesses.append(
            {
                "index": index,
                "input": case,
                "primary": fields(native, "primary", case["primary"][0]["index"]),
                "players": [fields(native, "players", item["index"]) for item in case.get("players", [])],
                "creature_queries": queries,
                "rng_state": native["rng_state"],
            },
        )

    for case in movement_cases():
        check(case)
    for case in player_cases(witnesses[:500]):
        check(case)
    assert len(witnesses) == 605
    encoded = (json.dumps(witnesses, indent=2) + "\n").encode()
    (args.out / "witnesses.json").write_bytes(encoded)
    selected = [row for row in witnesses if row["index"] < 32 or row["index"] in COLLISION_SEEDS or row["index"] >= 500]
    assert len(selected) == 156
    regression = (json.dumps(selected, indent=2) + "\n").encode()
    (args.out / "primary-microstep-threshold.json").write_bytes(regression)
    report = {
        "source_sha256": sha((config.directory / config.source).read_bytes()),
        "object_sha256": sha(p.object_path.read_bytes()),
        "body_sha256": sha(p.body.data),
        "build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "witnesses_sha256": sha(encoded),
        "shared_regressions_sha256": sha(regression),
        "cases": len(witnesses),
        "full_observation_matches": len(witnesses),
        "shared_regressions": len(selected),
        "layout": layout,
        "native_helpers": {
            name: {"entry": entry, "instructions": len(pcs)} for name, (entry, pcs) in p.helpers.items()
        },
        "native_coverage": sorted(coverage),
        "native_observation_digests": native_digests,
    }
    (args.out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("cases", "full_observation_matches", "shared_regressions")}))


if __name__ == "__main__":
    main()
