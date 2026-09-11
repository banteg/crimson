"""Replay the four preceding renderer fixture sets against the current candidate.

Historical receipts remain immutable. Their native trace hashes are checked,
then the newly compiled source must reproduce those same complete call traces.
"""

import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("secondary_verifier", HERE / "verify.py")
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)
probe = verify.probe
match = probe.match
PACKAGES = ("plasma-head-alpha", "beam-direction", "ion-chain-product", "laser-owner-rounding")


def arguments(package, data, row):
    kw = {}
    if package == "laser-owner-rounding":
        count, perks, headings, health, alpha, glow = row["fixture"]
        players = tuple(
            (i, x, y, health[i], headings[i], perks[i])
            for i, (x, y) in enumerate(((100.0, 150.0), (220.0, 210.0)))
        )
        return (None, 0.4, alpha, glow), {"player_count": count, "player_rows": players}
    if package == "beam-direction":
        position, origin = data["geometries"][row["geometry"]]
        kw = {"position": position, "origin": origin, "beam_stubs": True}
    elif package == "ion-chain-product":
        kw = {
            "beam_stubs": True, "native_creature_search": True,
            "creature_rows": data["creature_fixtures"][row["positions"]], "perk_count": row["perk"],
        }
    alpha = row["alpha"] if package == "ion-chain-product" else row["transition_alpha"]
    return (row["type_id"], row["life"], alpha, row["glow"]), kw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
    current = probe.Program(config)
    source_sha = probe.sha((config.directory / config.source).read_bytes())
    image_sha = probe.sha(match.DEFAULT_IMAGE_PATH.read_bytes())
    results = []
    for name in PACKAGES:
        path = HERE.parent / (name + "-2026-09-10") / "results.json"
        data = json.loads(path.read_text())
        assert data["image_sha256"] == image_sha
        assert data["source_sha256"] == verify.BEFORE_SHA
        assert data["native_body_sha256"] == probe.sha(current.image.function_bytes(current.native_start, current.native_end))
        fixtures = []
        for index, row in enumerate(data["fixtures"]):
            positional, kwargs = arguments(name, data, row)
            native = probe.run(current, True, *positional, **kwargs)
            candidate = probe.run(current, False, *positional, **kwargs)
            verify.same_trace(native, candidate)
            trace_sha = probe.sha(json.dumps(native["calls"]).encode())
            assert trace_sha == row["call_trace_sha256"], (name, index, "Historical native trace changed")
            assert native["state_sha256"] == row["projectile_state_sha256"]
            for key in ("creature_state_sha256", "player_state_sha256"):
                if key in row:
                    assert native[key] == row[key]
            fixtures.append({"index": index, "call_trace_sha256": trace_sha,
                             "native_instructions_exercised": native["coverage"],
                             "candidate_instructions_exercised": candidate["coverage"]})
        results.append({"package": name, "receipt_sha256": probe.sha(path.read_bytes()), "fixtures": fixtures})
        print(f"Verified {name}: {len(fixtures)} historical native traces", flush=True)
    record = {
        "schema_version": 1, "kind": "renderer-fixture-regression-replay",
        "source_sha256": source_sha, "verifier_sha256": probe.sha(Path(__file__).read_bytes()),
        "secondary_verifier_sha256": probe.sha((HERE / "verify.py").read_bytes()),
        "engine_sha256": probe.sha(verify.ENGINE.read_bytes()), "image_sha256": image_sha,
        "candidate_object_sha256": probe.sha(current.object_path.read_bytes()),
        "candidate_body_sha256": probe.sha(current.body.data), "results": results,
        "new_source_matches": 0,
        "scope": "same fixture inputs and recording external-call contracts as the four pinned historical receipts",
    }
    (out / "regressions.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
