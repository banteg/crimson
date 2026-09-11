"""Compare the Python particle pool with the generated native PC24 witnesses."""

import argparse
import hashlib
import json
from pathlib import Path

from tests.support.particle_update import compare


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-results", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raw = args.native_results.read_bytes()
    witnesses = json.loads(raw)
    for witness in witnesses:
        compare(witness)
    result = {"cases": len(witnesses), "native_witnesses_sha256": hashlib.sha256(raw).hexdigest()}
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(result)


if __name__ == "__main__":
    main()
