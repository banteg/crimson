"""Compare each recorded fixture prefix under matching original-bug policies.

Only common scalar fields are diagnosed; recorded final scores are not checked.
"""

import argparse
import json
from pathlib import Path

from replay import diagnose, encode

from crimson.replay.codec import load_replay_file

HERE = Path(__file__).resolve().parent
# Pin the supported diagnostic corpus. Newly added replays may use controller
# schemes outside this spike; explicitly selected files still fail on those.
FIXTURES = (
    "quest-2.10-failed.crd",
    "quest-2.5-completed.crd",
    "quest-4.10-failed.crd",
    "survival-34325.crd",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=HERE.parents[1] / "tests/fixtures/replays")
    parser.add_argument("--native", type=Path, default=HERE / "build/native/core")
    parser.add_argument("--ticks", type=int, default=1200)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--replay", action="append", help="Fixture filename; defaults to the four documented inputs")
    args = parser.parse_args()
    report = {}
    for name in args.replay or FIXTURES:
        file = args.fixtures / name
        replay = load_replay_file(file)
        report[file.name] = diagnose(replay, encode(replay, args.ticks), args.native, preserve_bugs=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if any(not result["common_fields_equal"] for result in report.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
