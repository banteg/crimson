"""Show why VC6 C2 cross-jumping merged or refused each pair of jumps (diagnostic only; no match credit).

Runs a Crimson scratch through `il_stage_trace.py --preset jumpopt` (preserving observer; whole-COFF,
replay and missing-stream controls unchanged) with two more return hooks inside `cross_jump_pair`
0x1071dfc6:

    tuples_equal          call 0x1071e08a -> 0x1073d365  (a = J1 side, b = J2 side, eax = equal)
    tuple_encoded_length  call 0x1071e19f -> 0x10737ad8  (/Ot byte count, eax = bytes)

For every `cross_jump_pair(J1, J2)` it prints the verdict, each backward comparison (the last one is
where matching stopped) and each counted length. J1 is the later reference in the label's list and
loses its copy. The running byte sum stops as soon as it reaches 20, and a merge needs sum + counter
> 20. See tools/match/c2/compiler/aim-chain-mover.md.

    uv run python scripts/c2/xjump_trace.py tools/match/scratches/player_update --out /private/tmp/xj-pu \
        [--jump 6c33d018]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import il_stage_trace as stage

stage.PRESETS["xjump"] = stage.PRESETS["jumpopt"] + (
    (0x1071E08A, 0x1073D365, "tuples_equal", True, 0),
    (0x1071E19F, 0x10737AD8, "tuple_encoded_length", True, 0),
)


def report(events, jumps: set[str]):
    il: list[str] = []
    pending: dict[str, dict] = {}
    log: list[str] = []

    def show(addr: str | None) -> str:
        line = next((x for x in il if x.split()[1] == addr), None)
        return stage.pretty(line) if line else f"<{addr}>"

    for event in events:
        name, fields = event["name"], stage.head_fields(event)
        dump = [line for line in event["body"].splitlines() if line.startswith("T ")]
        if dump and (name in ("jo2", "mover") or (name == "cross_jump_label_refs" and event["boundary"] == "return")):
            il = dump
        if name not in ("cross_jump_pair", "tuples_equal", "tuple_encoded_length"):
            continue
        if event["boundary"] == "entry":
            pending[name] = fields
            if name == "cross_jump_pair":
                log = []
            continue
        entry = pending.pop(name, {})
        if name == "tuples_equal":
            log.append(f"eq={fields.get('eax')}  {show(entry.get('ecx'))}\n          vs {show(entry.get('edx'))}")
        elif name == "tuple_encoded_length":
            log.append(f"len={int(fields.get('eax', '0'), 16)}  {show(entry.get('ecx'))}")
        else:
            j1, j2 = entry.get("ecx"), entry.get("edx")
            if jumps and not ({j1, j2} & jumps):
                continue
            verdict = "MERGED" if fields.get("eax", "0") != "0" else "no"
            print(f"--- cross_jump_pair J1={j1} J2={j2}: {verdict}")
            print(f"    J1: {show(j1)}\n    J2: {show(j2)}")
            for line in log:
                print("   ", line)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", nargs="?", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reuse", action="store_true", help="Re-render an existing --out trace")
    parser.add_argument("--jump", action="append", default=[], help="Only pairs involving this jmp tuple address")
    args = parser.parse_args()
    if not args.reuse:
        if args.scratch is None:
            parser.error("scratch is required unless --reuse")
        c2, iv = stage.load_modules(False, None)
        stage.trace(c2, iv, args.scratch, args.out, "xjump")
    events = stage.decode((args.out / "observed/phases.bin").read_bytes(), stage.result_profile(args.out))
    report(events, set(args.jump))


if __name__ == "__main__":
    main()
