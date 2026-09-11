"""Select shared particle impact regressions from fresh native PC24 witnesses."""

import argparse
import copy
import json
import struct
from pathlib import Path


def f32_bits(bits):
    return struct.unpack("<f", struct.pack("<I", bits))[0]


def normalize(witness):
    row = copy.deepcopy(witness)
    row["particle"]["index"] = row["input"]["particles"][0]["index"]
    row["creature"]["index"] = row["input"]["creatures"][0]["index"]
    calls = row.pop("calls")
    row["draws"] = [call[1] for call in calls if call[0] == "crt_rand"]
    row["damage_calls"] = [call[1:] for call in calls if call[0] == "creature_apply_damage"]
    row["decals"] = [
        dict(
            effect=call[1],
            x=f32_bits(call[2][0]),
            y=f32_bits(call[2][1]),
            width=f32_bits(call[3]),
            height=f32_bits(call[4]),
            rotation=f32_bits(call[5]),
            **dict(zip(("r", "g", "b", "a"), map(f32_bits, call[6]))),
        )
        for call in calls
        if call[0] == "fx_queue_add"
    ]
    return row


def select(witnesses):
    assert len(witnesses) == 663
    # Six complete mode/style groups, every explicit tint boundary case, and
    # all live/corpse cases with fire and bullet perks independently enabled.
    selected = [normalize(row) for row in witnesses if row["index"] < 72 or row["index"] >= 600]
    assert len(selected) == 135
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-results", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.write_text(json.dumps(select(json.loads(args.native_results.read_text())), indent=2) + "\n")


if __name__ == "__main__":
    main()
