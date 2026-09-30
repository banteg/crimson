"""Compare all recovered quest builders against the original x86 executable.

Unicorn JIT must run outside the command sandbox, like tests/native_oracle.
This checks table construction; it does not establish whole-run x87 parity.
"""

import argparse
import json
import random
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from crimson.quests import QUESTS
from crimson_re.dbg.native_oracle import NativeOracle

HERE = Path(__file__).resolve().parent
SEEDS = (0, 1, 1337, 0xBEEF, 0x7FFF_FFFF, 0xDEADBEEF, *random.Random(0x437A00).choices(range(1 << 32), k=26))


def read_snapshots(data):
    offset = 0
    snapshots = []
    while offset < len(data):
        count = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        snapshots.append(data[offset : offset + count * 4])
        offset += count * 4
    if offset != len(data):
        raise ValueError("Truncated snapshots")
    return snapshots


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--build", type=Path, default=HERE / "build")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    cases = [(seed, q.level.global_index, hardcore, 1) for q in QUESTS for hardcore in (0, 1) for seed in SEEDS]
    payload = b"".join(struct.pack("<4I", *case) for case in cases)
    native = subprocess.check_output([str(args.build / "native/core"), "--quest-probe"], input=payload)
    with tempfile.NamedTemporaryFile() as source:
        source.write(payload)
        source.flush()
        wasm = subprocess.check_output(
            [shutil.which("node"), str(HERE / "builder_probe.mjs"), source.name, str(args.build / "wasm/core.wasm")],
        )
    if native != wasm:
        raise ValueError("Native/WASM builder probes differ")
    snapshots = read_snapshots(native)
    if len(snapshots) != len(cases):
        raise ValueError("Missing builder snapshots")

    oracle = NativeOracle(args.exe)
    oracle.run_static_initializers()
    entries, count = oracle.alloc(256 * 24), oracle.alloc(4)
    pristine = oracle.snapshot()
    differences = []
    for case, actual in zip(cases, snapshots, strict=True):
        seed, index, hardcore, players = case
        quest = QUESTS[index]
        oracle.restore(pristine)
        oracle.write_u32("terrain_texture_width", 1024)
        oracle.write_u32("terrain_texture_height", 1024)
        oracle.write_u32("config_player_count", players)
        oracle.write_u8("config_hardcore", hardcore)
        oracle.rand_state = seed
        name = "quest_build_" + re.sub(r"[^a-z0-9]+", "_", quest.title.lower()).strip("_")
        oracle.call(name, entries, count)
        n = oracle.read_i32(count)
        expected = struct.pack("<II", n, oracle.rand_state) + oracle.read(entries, n * 24)
        if expected != actual:
            first = next(
                (i for i, (a, b) in enumerate(zip(actual, expected, strict=False)) if a != b),
                min(len(actual), len(expected)),
            )
            differences.append(
                {
                    "quest": quest.level.text,
                    "seed": seed,
                    "hardcore": hardcore,
                    "first_byte": first,
                    "native": struct.unpack_from("<f", actual, first // 4 * 4)[0],
                    "original": struct.unpack_from("<f", expected, first // 4 * 4)[0],
                },
            )
    report = {"cases": len(cases), "quests": 50, "native_wasm": "bit exact", "original_mismatches": differences}
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if differences:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
