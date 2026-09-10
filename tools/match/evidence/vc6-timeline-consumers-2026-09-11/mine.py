"""Rebuild the recorded 98 controls and inspect stack overwrites and addresses.

The overwrite screen stops at branches and calls, tracks ESP across pushes, and
rejects an intervening direct read of the same frame slot. It is a bounded
screen, not alias analysis or a semantic proof; reported hits need manual review.
All computed addresses and register-to-frame writes are also retained for review.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import probes

from crimson import match


def stack_pairs(lines):
    lines = list(lines)
    pending = {}
    sp = 0
    pairs = []
    for i, line in enumerate(lines):
        mnemonic = line.split(" ", 1)[0]
        if mnemonic.startswith("j") or mnemonic in ("call", "ret", "retn", "leave"):
            pending = {}
        # Matcher-normalized frame address is tracked across pushes/cleanup.
        tokens = re.findall(r"\[(esp|ebp)([+-](?:0x[0-9a-f]+|[0-9]+))?\]", line)
        refs = []
        for base, off in tokens:
            value = int(off or "0", 0) + (sp if base == "esp" else 0)
            refs.append((base, value))
        dest = re.fullmatch(r"mov dword \[(esp|ebp)([+-](?:0x[0-9a-f]+|[0-9]+))?\], (.+)", line)
        if dest:
            key = (dest[1], int(dest[2] or "0", 0) + (sp if dest[1] == "esp" else 0))
            if key in pending:
                prev = pending[key]
                pairs.append({"first_index": prev, "second_index": i, "context": lines[prev : i + 1]})
            pending[key] = i
            # Any source frame read prevents using its earlier write as dead.
            for key2 in refs[1:]:
                pending.pop(key2, None)
        else:
            for key in refs:
                pending.pop(key, None)
        if mnemonic == "push":
            sp -= 4
        elif mnemonic == "pop":
            sp += 4
        adjust = re.fullmatch(r"(add|sub) esp, (0x[0-9a-f]+|[0-9]+)", line)
        if adjust:
            sp += int(adjust[2], 0) * (1 if adjust[1] == "add" else -1)
    return pairs


def screen(lines):
    return {
        "same_block_stack_overwrites": stack_pairs(lines),
        "computed_addresses": [
            {"instruction_index": i, "instruction": line} for i, line in enumerate(lines) if line.startswith("lea ")
        ],
        "register_stack_stores": [
            {"instruction_index": i, "instruction": line}
            for i, line in enumerate(lines)
            if re.fullmatch(r"mov dword \[(?:esp|ebp)[^\]]*\], e\w+", line)
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
    generator = config.directory / "source-boundary-controls-2026-09-11.py"
    plan_path = out / "plan.json"
    subprocess.run([sys.executable, str(generator), str(plan_path)], check=True)
    assert (
        hashlib.sha256(plan_path.read_bytes()).hexdigest()
        == "4ed2622a03304b4f58577a953297d1509b4a520bd26d8b3c68e475bcba2ac98a"
    )
    controls = json.loads(plan_path.read_text())["sites"][0]["replacements"]
    assert len(controls) == 98

    def run(item):
        row, _, _ = probes.build(config, out, item["name"], item["text"])
        lines = (out / item["name"] / "candidate.asm").read_text().splitlines()
        row.update(screen(lines))
        return row

    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(run, controls))
    baseline = (config.directory / config.source).read_text()
    _, _, obj = probes.build(config, out, "baseline", baseline)
    result = match.run_match(
        obj_path=obj,
        function=config.function,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    native_screen = screen(result.target_lines)
    assert native_screen["same_block_stack_overwrites"] == [
        {"first_index": 53, "second_index": 54, "context": ["mov dword [esp+0x10], edi", "mov dword [esp+0x10], ebx"]},
    ]
    (out / "target.asm").write_text("\n".join(result.target_lines) + "\n")
    record = {
        "canonical_source_sha256": probes.SOURCE_SHA,
        "controls": len(rows),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "probe_builder_sha256": hashlib.sha256(Path(probes.__file__).read_bytes()).hexdigest(),
        "source_generator_sha256": hashlib.sha256(generator.read_bytes()).hexdigest(),
        "native_positive_screen": native_screen,
        "results": rows,
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(
        "Rebuilt",
        len(rows),
        "controls;",
        sum(bool(row["same_block_stack_overwrites"]) for row in rows),
        "same-block stack-overwrite candidates for manual review",
        flush=True,
    )


if __name__ == "__main__":
    main()
