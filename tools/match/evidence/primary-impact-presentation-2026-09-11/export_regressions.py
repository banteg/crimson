"""Select ten complete cycles of origin, violence, and Bloody Mess native witnesses."""

import argparse
import collections
import json
from pathlib import Path


def select(witnesses):
    assert len(witnesses) == 1000
    selected = witnesses[:120]
    groups = collections.Counter(
        (row["input"]["mode"], row["input"]["violence_disabled"], bool(row["input"]["perks"]))
        for row in selected
    )
    assert len(groups) == 12 and set(groups.values()) == {10}
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--witnesses", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.write_text(json.dumps(select(json.loads(args.witnesses.read_text())), indent=2) + "\n")


if __name__ == "__main__":
    main()
