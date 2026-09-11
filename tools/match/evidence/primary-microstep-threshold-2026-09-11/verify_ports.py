"""Compare all fresh native primary microstep witnesses against Python."""

import argparse
import hashlib
import json
import math
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from crimson.projectiles.runtime import projectile_pool
from tests.support.primary_microstep import differences, observe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-results", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--legacy-threshold", action="store_true", help="Replay the old double-precision length condition in memory",
    )
    args = parser.parse_args()
    raw = args.native_results.read_bytes()
    witnesses = json.loads(raw)
    failed = []
    context = nullcontext()
    source = Path(projectile_pool.__file__).read_text()
    if args.legacy_threshold:
        assert source.count("x87_pc24_hypot(") == 1

        def legacy_length(x, y):
            # Exact former Vec2.length expression, applied only at this threshold.
            return math.sqrt(x * x + y * y)

        context = patch.object(projectile_pool, "x87_pc24_hypot", legacy_length)
    with context:
        for witness in witnesses:
            errors = differences(witness, observe(witness["input"]))
            if errors:
                failed.append({"index": witness["index"], "differences": errors})
    report = {
        "cases": len(witnesses),
        "matches": len(witnesses) - len(failed),
        "witnesses_sha256": hashlib.sha256(raw).hexdigest(),
        "failures": failed,
        "legacy_threshold": args.legacy_threshold,
        "python_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
    }
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"cases={len(witnesses)} matches={report['matches']} failures={len(failed)}")
    if args.legacy_threshold:
        assert failed
        assert all(any(error["field"] == "creature_queries" for error in row["differences"]) for row in failed)
    else:
        assert not failed


if __name__ == "__main__":
    main()
