"""Compare the Python runtime with every generated native integrated impact."""

import argparse
import hashlib
import json
from pathlib import Path

from export_regressions import normalize

from tests.support.particle_impact import compare


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-results", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raw = args.native_results.read_bytes()
    witnesses = json.loads(raw)
    for witness in witnesses:
        compare(normalize(witness))
    result = {"cases": len(witnesses), "native_witnesses_sha256": hashlib.sha256(raw).hexdigest()}
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(result)


if __name__ == "__main__":
    main()
