"""Select one complete Pistol/Pulse, origin, gore, Bloody Mess, and Freeze cycle."""

import argparse
import json
from pathlib import Path


def select(witnesses):
    assert len(witnesses) == 480
    selected = [row for row in witnesses if row["parent_index"] < 12]
    combinations = {
        (
            row["input"]["primary"][0]["type"],
            row["input"]["mode"],
            row["input"]["violence_disabled"],
            bool(row["input"]["perks"]),
            row["input"]["freeze"],
        )
        for row in selected
    }
    assert len(selected) == len(combinations) == 48
    assert any(
        row["input"]["freeze"] and row["expected"]["effects"][-1][2][-1] == 0
        for row in selected
    )
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--witnesses", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.write_text(json.dumps(select(json.loads(args.witnesses.read_text())), indent=2) + "\n")


if __name__ == "__main__":
    main()
