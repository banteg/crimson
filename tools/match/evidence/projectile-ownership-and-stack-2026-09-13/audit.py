"""Rebuild the experiment graph and inspect local sequences without matching credit."""

import argparse
import json
import re
from dataclasses import replace
from pathlib import Path

from recover import HERE, recover, sha

from crimson import match
from crimson.match_diagnostics import residual_summary_payload

WINDOWS = {
    "impulse": (0x42150F, 0x4215A7),
    "seeker-velocity": (0x421CC2, 0x421D56),
    "jitter": (0x4211BF, 0x4211EE),
    "distance": (0x4211EE, 0x42124C),
    "ion-chain": (0x4212A0, 0x42130B),
    "plasma": (0x421370, 0x4213E8),
    "pulse": (0x421480, 0x4214D9),
    "sound": (0x42190F, 0x42194F),
    "particle-age": (0x42283F, 0x42285D),
}
STACK = re.compile(r"\[esp(?:\+0x([0-9a-f]+))?\]")
BRANCH = re.compile(r"(j[a-z]+) L([0-9a-f]+)")


def shape(lines):
    """Preserve register roles and internal branch topology; map local stack homes."""
    offsets = {line.offset: i for i, line in enumerate(lines)}
    offsets[lines[-1].offset + lines[-1].size] = len(lines)
    homes, sequence, delta = {}, [], 0
    for line in lines:
        text = line.text
        branch = BRANCH.fullmatch(text)
        if branch:
            destination = int(branch[2], 16)
            if destination not in offsets:
                return None
            text = f"{branch[1]} W{offsets[destination]}"

        def stack(found, delta=delta):
            home = int(found[1] or "0", 16) + delta
            if home not in homes:
                homes[home] = len(homes)
            return f"[HOME{homes[home]}]"

        sequence.append(STACK.sub(stack, text))
        if text.startswith("push "):
            delta -= 4
        elif text.startswith("pop "):
            delta += 4
        elif update := re.fullmatch(r"(add|sub) esp, 0x([0-9a-f]+)", text):
            delta += int(update[2], 16) * (1 if update[1] == "add" else -1)
    return sequence, list(homes)


def windows(result):
    rows = {}
    for name, (start, end) in WINDOWS.items():
        native = [line for line in result.target_disassembly if start <= line.address < end]
        expected = shape(native)
        hits = []
        if expected is not None:
            for index in range(len(result.candidate_disassembly) - len(native) + 1):
                candidate = result.candidate_disassembly[index : index + len(native)]
                actual = shape(candidate)
                if actual is None or actual[0] != expected[0]:
                    continue
                pairs = [(a.masked_references, b.masked_references) for a, b in zip(native, candidate, strict=True)]
                if not all(
                    len(left) == len(right)
                    and all(
                        a.explained and b.explained and set(a.keys).intersection(b.keys)
                        for a, b in zip(left, right, strict=True)
                    )
                    for left, right in pairs
                ):
                    continue
                hits.append(
                    {
                        "candidate_offset": candidate[0].offset,
                        "native_stack_homes": expected[1],
                        "candidate_stack_homes": actual[1],
                    },
                )
        rows[name] = {"start": hex(start), "end": hex(end), "instructions": len(native), "hits": hits}
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    graph = json.loads((HERE / "experiments.json").read_text())
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    rows = []
    for index, name in enumerate(("before", *graph["experiments"])):
        source = recover(name)
        expected = graph["before_body_sha256"] if name == "before" else graph["experiments"][name]["body_sha256"]
        directory = args.out / str(index)
        directory.mkdir(exist_ok=True)
        (directory / "scratch.cpp").write_text(source)
        obj = match.compile_scratch(replace(config, directory=directory))
        body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), config.symbol)
        assert sha(body.data) == expected, name
        row = {"name": name, "source_sha256": sha(source.encode()), "body_sha256": sha(body.data)}
        if name == graph["final"]:
            result = match.run_match(
                obj_path=obj,
                function=config.function,
                symbol_name=config.symbol,
                reference_aliases=config.reference_aliases,
            )
            assert not result.exact and not result.body_byte_exact
            row.update(
                {
                    "local_windows": windows(result),
                    "residual": residual_summary_payload(result, limit=500),
                    "exact": result.exact,
                    "body_byte_exact": result.body_byte_exact,
                    "frame": result.candidate_lines[0],
                },
            )
        rows.append(row)
        print(index + 1, name, "PASS", flush=True)
    record = {
        "rows": rows,
        "new_exact_matches": 0,
        "scope": "Window navigation preserves instruction order, register roles, internal branch topology, explained positional references, and consistent local stack-home mapping. It does not compare instruction encodings or prove cross-window stack lifetimes. Windows containing external branches are left unmatched. Native replays are separate bounded evidence.",
        "harness_sha256": {
            path.name: sha(path.read_bytes())
            for path in (HERE / "audit.py", HERE / "recover.py", HERE / "experiments.json", HERE / "before.cpp")
        },
    }
    (args.out / "results.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
