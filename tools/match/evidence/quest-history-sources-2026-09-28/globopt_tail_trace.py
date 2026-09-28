"""Preserving C2 trace of the IV driver plus the tail of `globopt_run`, with temp symbol flags.

It adds IL dumps (entry and return) around the steps that run after the loop optimizer:
fact deletion, the last dead-code pass 0x10713683, temp-destination restore, adjacent-copy
folding and finalisation. Class-3 symbols print their +0x32 flag byte as `f<hex>`; bits 0-1
mark derived induction variables (`get_derived_iv` 0x10753def), the only temps that phase-3
CSE copy propagation (`find_available_copy_source` 0x10709b5a) substitutes for a named local.

    uv run python tools/match/evidence/quest-history-sources-2026-09-28/globopt_tail_trace.py \
        <scratch-dir> --out <new-dir> [--grep PATTERN ...]

`--grep` prints, for every dump where they change, the IL tuples matching any pattern
(for example `'_template_id` or `#328c`). Only the pinned msvc6.5 C2 is supported.
"""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts/c2"))
import iv_trace

from crimson import match_c2 as c2

GLOBOPT_TAIL = (
    (0x107134E9, 0x107450D7, "loop_opt_per_loop", True, 1),
    (0x10713665, 0x10707B6B, "globopt_tail_7b6b", True, 1),
    (0x1071366C, 0x1070A547, "delete_status1_fact_tuples", True, 1),
    (0x10713673, 0x1070B9AB, "delete_status2_fact_tuples", True, 1),
    (0x1071367C, 0x1070789C, "alloc_block_dataflow_sets", True, 1),
    (0x10713683, 0x10706BD0, "globopt_dead_code_elim_last", True, 1),
    (0x107136F2, 0x10743190, "rebuild_flow_graph_after_dce", True, 1),
    (0x1071370D, 0x10706BD0, "globopt_dead_code_elim_extra", True, 1),
    (0x1071369A, 0x107061C8, "globopt_restore_temp_destinations", True, 1),
    (0x107136A1, 0x10726654, "globopt_fold_adjacent_copies", True, 1),
    (0x107136A8, 0x107266FF, "globopt_finalize_tuples", True, 1),
)
FLAGGED = 's("z"); dec(W(y, 0x20)); if (*(unsigned char *)(y + 4) == 3) { s("f"); hx(*(unsigned char *)(y + 0x32)); }'


def trace(scratch, out):
    iv_trace.OBSERVER = iv_trace.OBSERVER.replace('s("z"); dec(W(y, 0x20));', FLAGGED)
    profile = iv_trace.profile_with_hooks(iv_trace.IV_HOOKS + GLOBOPT_TAIL, passes=True)
    stock = (c2.load_profile, c2.observer_source, c2.decode_trace)
    c2.load_profile = lambda: profile
    c2.observer_source = iv_trace.observer_source
    c2.decode_trace = iv_trace.decode
    try:
        return c2.trace(scratch, out)
    finally:
        c2.load_profile, c2.observer_source, c2.decode_trace = stock


def grep(out, patterns):
    profile = json.loads((out / "profile.json").read_text())
    events = iv_trace.decode((out / "observed/phases.bin").read_bytes(), profile)
    previous = None
    for event in events:
        lines = iv_trace.il_lines(event)
        if not lines:
            continue
        selected = [iv_trace.pretty_tuple(line) for line in lines if any(re.search(p, line) for p in patterns)]
        if selected != previous:
            print(f"== [{event['event']}] {event['boundary']} {event['name']}")
            for line in selected:
                print("   ", line)
            previous = selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--grep", nargs="*", default=[])
    args = parser.parse_args()
    manifest = trace(args.scratch, args.out)
    print(json.dumps({"out": str(args.out), "events": manifest["events"], "metrics": manifest["metrics"]}))
    if args.grep:
        grep(args.out, args.grep)


if __name__ == "__main__":
    main()
