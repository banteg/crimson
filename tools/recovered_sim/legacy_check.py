"""Compare each recorded fixture prefix under matching original-bug policies.

Only common scalar fields are diagnosed; recorded final scores are not checked.
"""

import argparse
import json
from pathlib import Path

from replay import diagnose, encode

from crimson.replay.codec import load_replay_file

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=HERE.parents[1] / "tests/fixtures/replays")
    parser.add_argument("--native", type=Path, default=HERE / "build/native/core")
    parser.add_argument("--ticks", type=int, default=1200)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = {}
    for file in sorted(args.fixtures.glob("*.crd")):
        replay = load_replay_file(file)
        report[file.name] = diagnose(replay, encode(replay, args.ticks), args.native, preserve_bugs=True)
    if not report:
        raise ValueError("No replay fixtures")
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if any(not result["common_fields_equal"] for result in report.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
