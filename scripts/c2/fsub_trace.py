"""Trace forward_substitute_single_def_ranges 0x107306c1 per live range (diagnostic only; no match credit).

Runs a scratch through the preserving observer (`crimson match c2-trace`, via il_stage_trace.py) with:

- IL dumps at the entry of every stock pass hook from address-mode selection to local colouring
  (`addr`, `lower`, `phomes`, `blr`, `fpo`, `coalesce`, `fsub` = 0x306c1 entry, `blockregs` = after it,
  `local`);
- four event hooks inside 0x306c1: phase-2 candidacy (the `bitset_test` call at 0x107308fd, reached
  only by ranges that phase 1 did not exclude), the base and index `has_intervening_base_definition`
  results (0x1073091c and 0x1073097d, return value in eax) and the substitution call (0x1073094b).

The report prints the IL at the chosen stages for `--lines` (C2 line labels, i.e. function-relative),
then one line per live range that reached phase 2: range id, the symbols seen on that range in the
`fsub` dump, the definition line, and the verdict (`substituted`, `kept: base/index check`). Ranges that
are defined by a `lea` at `fsub` but never reach phase 2 are listed as `kept: phase 1` (value use, use
before definition, a second definition with another tree, or an unfoldable definition).

    uv run python scripts/c2/fsub_trace.py <scratch-dir> --out <new-dir> [--lines 885-975]
    uv run python scripts/c2/fsub_trace.py --reuse <trace-dir> [--lines A-B] [--symbols auto_aim,target_position]

`--symbols` also reports the named ranges that never reached phase 2 although their first definition is
a copy (for example a pointer copied from an unfoldable `lea` temporary).

See tools/match/c2/compiler/unfolded-field-pointers.md.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import il_stage_trace as stage

stage.STOCK_NAMES = {
    0: "glob",
    3: "addr",
    4: "lower",
    5: "phomes",
    6: "blr",
    7: "fpo",
    8: "coalesce",
    9: "fsub",
    10: "blockregs",
    11: "local",
}
EVENTS = ("p2cand", "base", "index", "subst")
stage.PRESETS["fsub"] = (
    (0x107308FD, 0x1070251D, "p2cand", False, 0),
    (0x1073091C, 0x10731A50, "base", True, 0),
    (0x1073097D, 0x10731A50, "index", True, 0),
    (0x1073094B, 0x1071F578, "subst", False, 0),
)
RANGE = re.compile(r"#(\d+)c\d+(?:\^\d+\+\d+)?z\d+/[0-9a-f.]+(?:@a\d+)?(?:'(\S+?))? @#(\d+)c2")
DEF = re.compile(r"^T \w+ op=(\w+) .*? ln=(\d+) .*?\| \[[^\]]*? @#(\d+)c2[^\]]*\] <=")
_observer_source = stage.observer_source


def observer_source(iv):
    inner = _observer_source(iv)

    def source(profile):
        text = inner(profile)
        return text.replace(
            '    s(" args=");',
            '    if (index >= 12 && r[1]) { s(" lr="); dec(W(r[1], 0x1c)); }\n    s(" args=");',
            1,
        )

    return source


def fsub_dump(events) -> list[str]:
    for event in events:
        if event["name"] == "fsub" and event["boundary"] == "entry":
            return [line for line in event["body"].splitlines() if line.startswith("T ")]
    return []


def range_names(il: list[str]) -> tuple[dict[str, set[str]], dict[str, tuple[str, str]]]:
    """Symbols seen on each live range, and each range's first definition (opcode, C2 line)."""
    names: dict[str, set[str]] = {}
    defs: dict[str, tuple[str, str]] = {}
    for line in il:
        for sym, name, lr in RANGE.findall(line):
            names.setdefault(lr, set()).add(name or f"#{sym}")
        m = DEF.match(line)
        if m:
            defs.setdefault(m.group(3), ("lea" if m.group(1) == "12" else f"op{m.group(1)}", m.group(2)))
    return names, defs


def report(events, lines, ordinal):
    stage_report(events, lines, ordinal)
    names, defs = range_names(fsub_dump(events))
    verdict: dict[str, str] = {}
    for event in events:
        if event["name"] not in EVENTS:
            continue
        fields = stage.head_fields(event)
        lr = fields.get("lr", "?")
        if event["name"] == "p2cand":
            verdict.setdefault(lr, "kept: base/index check")
        elif event["name"] == "subst":
            verdict[lr] = "substituted"
        elif event["boundary"] == "return" and fields.get("eax", "0") != "0":
            verdict[lr] = f"kept: {event['name']} check returned 1"
    for lr, (op, _line) in defs.items():
        if op == "lea" or names.get(lr, set()) & WATCH:
            verdict.setdefault(lr, "kept: phase 1 (not a phase-2 candidate)")
    print("=== forward_substitute_single_def_ranges verdicts (lr, symbols, first def, verdict)")
    for lr in sorted(verdict, key=int):
        label = ",".join(sorted(names.get(lr, {"?"})))
        op, line = defs.get(lr, ("-", "-"))
        print(f"lr {lr:>5}  {label[:40]:<40} {op:>6} ln {line:>5}  {verdict[lr]}")


WATCH: set[str] = set()
stage_report = stage.report
stage.observer_source = observer_source
stage.report = report

if __name__ == "__main__":
    argv = sys.argv[1:]
    if "--symbols" in argv:
        at = argv.index("--symbols")
        WATCH.update(f"_{name.lstrip('_')}" for name in argv[at + 1].split(","))
        del argv[at : at + 2]
    sys.argv = [sys.argv[0], *argv, "--preset", "fsub"]
    stage.main()
