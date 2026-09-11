"""Select a compact shared regression set from fresh native witnesses."""

import argparse
import json
from pathlib import Path


def select(witnesses):
    selected = []
    mixed = 0
    for witness in witnesses:
        frame = witness["input"]
        if "rng_seed" not in frame:
            continue
        if len(frame["particles"]) > 1:
            if mixed < 8:
                selected.append(witness)
                mixed += 1
        elif frame["particles"][0]["intensity"] in (0.15, 0.8, 1.2) and frame["dt"] in (1e-20, 0.016, 1.0):
            selected.append(witness)
    assert len(selected) == 80
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-results", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    selected = select(json.loads(args.native_results.read_text()))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(selected, indent=2) + "\n")


if __name__ == "__main__":
    main()
