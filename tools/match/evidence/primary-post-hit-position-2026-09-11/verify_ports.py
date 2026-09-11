"""Compare native post-jitter sound and freeze output with the actual Python world path."""

import argparse
import collections
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

import crimson.effects
import crimson.projectiles.runtime.behaviors
import crimson.projectiles.runtime.projectile_pool
import crimson.projectiles.types
import crimson.sim.presentation_step
import crimson.sim.world_state
from tests.support.primary_impact import differences, observe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--witnesses", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-differences", action="store_true")
    args = parser.parse_args()
    witnesses = json.loads(args.witnesses.read_text())
    failures = []
    counts = collections.Counter()
    for witness in witnesses:
        failed = differences(witness, observe(witness["input"]))
        if failed:
            failures.append({"index": witness["index"], "differences": failed})
            counts.update(row["field"] for row in failed)
    result = {
        "cases": len(witnesses),
        "witnesses_sha256": hashlib.sha256(args.witnesses.read_bytes()).hexdigest(),
        "source_sha256": {
            module.__name__: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
            for module in (
                crimson.effects,
                crimson.projectiles.runtime.behaviors,
                crimson.projectiles.runtime.projectile_pool,
                crimson.projectiles.types,
                crimson.sim.presentation_step,
                crimson.sim.world_state,
            )
        },
        "failing_cases": len(failures),
        "difference_counts": dict(counts),
        "failures": failures,
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("cases", "failing_cases", "difference_counts")}), flush=True)
    assert args.allow_differences or not failures


if __name__ == "__main__":
    main()
