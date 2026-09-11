"""Capture native primary impact, blood-splatter, damage, and randomized FX output."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

from execute import Program, match, run, unicorn
from fixtures import check_layout, fields, scenarios


def sha(data):
    return hashlib.sha256(data).hexdigest()


def observation_digest(trace):
    data = {key: {name: value.hex() for name, value in trace[key].items()} for key in ("state", "scalars")}
    data.update({key: trace[key] for key in ("calls", "writes", "rng_state", "rng_callers")})
    return sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())


def template_scale_reset_proof(program):
    # effect_defaults_reset initializes scale before gameplay; retain the
    # actual native store, rather than inferring a value from the zeroed image.
    address = 0x0042DFA9
    encoded = bytes.fromhex("c705c8b14a000000803f")
    offset = address - program.image.image_base
    assert program.image.mapped[offset : offset + len(encoded)] == encoded
    return {
        "function": "effect_defaults_reset",
        "instruction_address": address,
        "instruction_bytes": encoded.hex(),
        "destination": 0x004AB1C8,
        "value_bits": 0x3F800000,
    }


def witness(index, case, trace):
    calls = trace["calls"]
    expected = {
        "primary": fields(trace, "primary", case["primary"][0]["index"]),
        "creature": fields(trace, "creatures", case["creatures"][0]["index"]),
        "draws": [call[1] for call in calls if call[0] == "crt_rand"],
        "rng_callers": trace["rng_callers"],
        "rng_state": trace["rng_state"],
        "shots_hit": struct.unpack("<I", trace["scalars"]["highscore_record_shots_hit"])[0],
    }
    for name, helper in (
        ("damage_calls", "creature_apply_damage"),
        ("decals", "fx_queue_add"),
        ("splatters", "effect_spawn_blood_splatter"),
        ("effects", "effect_spawn"),
    ):
        expected[name] = [call[1:] for call in calls if call[0] == helper]
    expected["random_positions"] = [call[1] for call in calls if call[0] == "fx_queue_add_random"]
    return {"index": index, "input": case, "expected": expected}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--count", type=int, default=1000)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    image_sha = sha(match.default_image_path().read_bytes())
    assert image_sha == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    program = Program(config, integrated=True)
    layout = check_layout(config, out)
    cases = list(scenarios(program, args.count))
    witnesses = []
    digests = []
    coverage = set()
    for index, case in enumerate(cases):
        trace = run(program, True, case)
        witnesses.append(witness(index, case, trace))
        digests.append(observation_digest(trace))
        coverage.update(trace["coverage"])
    data = (json.dumps(witnesses, indent=2) + "\n").encode()
    (out / "witnesses.json").write_bytes(data)
    result = {
        "cases": len(cases),
        "native_image_sha256": image_sha,
        "witnesses_sha256": sha(data),
        "native_observation_digests": digests,
        "native_coverage": sorted(coverage),
        "layout": layout,
        "template_scale_reset": template_scale_reset_proof(program),
        "helpers": {name: {"entry": entry, "instructions": len(pcs)} for name, (entry, pcs) in program.helpers.items()},
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("cases", "native_image_sha256", "witnesses_sha256")}), flush=True)


if __name__ == "__main__":
    main()
