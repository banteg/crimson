"""Reproduce a plain-source timeline dead store; no compiler decisions are changed."""

import argparse
import difflib
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CANONICAL = ROOT / "tools/match/scratches/quest_spawn_timeline_update"
sys.path.insert(0, str(ROOT / "scripts/c2"))
import const_trace
import iv_trace
import residual_map

BASE_SHA = "a448391479030f257a8e5626e795be585674e2b4ec3e0fdb5e95ff9a08ff44d9"
WITNESS_SHA = "ca9ac4167854d337abc5aebb4ef726134bf63c9e3decc57497fda2bfcbcb4d89"
GUARD = "            if (template_id != 0 && entry->count <= 0) return;\n"
TRIPLET = [
    "lea edi, dword [esi+0xc]",
    "mov dword [esp+0x10], edi",
    "mov dword [esp+0x10], ebx",
]


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def cases():
    baseline = (CANONICAL / "scratch.cpp").read_text()
    witness = (HERE / "witness.cpp").read_text()
    assert sha(baseline) == BASE_SHA
    assert sha(witness) == WITNESS_SHA
    scoped = (
        witness.replace("    int spawn_index = 0;\n", "", 1)
        .replace(
            "        quest_timeline_vec2_t offset = zero_offset;",
            "        quest_timeline_vec2_t offset = zero_offset;\n        int spawn_index = 0;",
        )
        .replace("        spawn_index = 0;\n", "")
    )
    y_pointer = (
        witness.replace(
            "        quest_timeline_vec2_t offset = zero_offset;",
            "        float *yp = &entry->position.y;\n        quest_timeline_vec2_t offset = zero_offset;",
        )
        .replace("offset.x + entry->position.x", "offset.x + yp[-1]")
        .replace(
            "offset.y + entry->position.y",
            "offset.y + *yp",
        )
    )
    return {
        "canonical": baseline,
        "plain_guard": witness,
        "delete_guard": witness.replace(GUARD, ""),
        "reverse_guard": witness.replace(
            "template_id != 0 && entry->count <= 0",
            "entry->count <= 0 && template_id != 0",
        ),
        "live_named_pointer": witness.replace(
            "                    entry->template_id,",
            "                    *template_id,",
        ),
        "direct_address": witness.replace("template_id != 0 &&", "&entry->template_id != 0 &&"),
        "equal_count": witness.replace(
            "template_id != 0 && entry->count <= 0",
            "template_id != 0 && entry->count == 0",
        ),
        "less_than_one": witness.replace(
            "template_id != 0 && entry->count <= 0",
            "template_id != 0 && entry->count < 1",
        ),
        "live_null_check": witness.replace(
            "template_id != 0 && entry->count <= 0",
            "template_id == 0 || entry->count <= 0",
        ),
        "scoped_counter": scoped,
        "y_pointer": y_pointer,
    }


def build(name, source, out):
    scratch = out / name
    scratch.mkdir()
    (scratch / "scratch.cpp").write_text(source)
    (scratch / "scratch.conf").write_text((CANONICAL / "scratch.conf").read_text())
    result = residual_map.build(scratch)
    audit = result.masked_operand_audit
    lines = list(result.candidate_lines)
    row = {
        "source_sha256": sha(source),
        "ratio": result.ratio,
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
        "instructions": len(lines),
        "prefix": result.prefix_instructions,
        "references": [audit.ok_count, audit.unresolved_count, audit.mismatch_count],
        "triplet": any(lines[i : i + 3] == TRIPLET for i in range(len(lines) - 2)),
        "frame": next(line for line in lines if line.startswith("sub esp,")),
        "different_instructions": [
            {"target": a, "candidate": b} for a, b in zip(result.target_lines, lines, strict=False) if a != b
        ]
        if len(lines) == len(result.target_lines)
        else None,
    }
    (scratch / "candidate.asm").write_text("\n".join(lines) + "\n")
    (scratch / "native.diff").write_text(
        "\n".join(
            difflib.unified_diff(
                result.target_lines,
                lines,
                "native",
                name,
                lineterm="",
            ),
        )
        + "\n",
    )
    return row


def trace(scratch, out):
    path = HERE.parent / "quest-history-sources-2026-09-28/globopt_tail_trace.py"
    spec = importlib.util.spec_from_file_location("timeline_tail_trace", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tail = out / "tail"
    tail_receipt = module.trace(scratch, tail)
    profile = json.loads((tail / "profile.json").read_text())
    events = iv_trace.decode((tail / "observed/phases.bin").read_bytes(), profile)
    # In this pinned witness the unsigned comparison temporary is #326. It is
    # created by merge #2, not the front-end named local _template_id.
    transitions = []
    for event in events:
        if event["boundary"] != "return" or event["name"] not in (
            "merge_parallel_induction_variables#2",
            "strength_reduce_address_operands",
            "globopt_dead_code_elim_last",
            "rebuild_flow_graph_after_dce",
        ):
            continue
        selected = [iv_trace.pretty_tuple(line) for line in iv_trace.il_lines(event) if "#326c" in line]
        if selected:
            transitions.append({"pass": event["name"], "tuples": selected})
    before = next(row for row in transitions if row["pass"] == "globopt_dead_code_elim_last")
    after = next(row for row in transitions if row["pass"] == "rebuild_flow_graph_after_dce")
    assert len(before["tuples"]) == 2 and any("cmp " in line for line in before["tuples"])
    assert len(after["tuples"]) == 1 and "#216c" in after["tuples"][0]
    const_out = out / "demotion"
    const_receipt = const_trace.trace(scratch, const_out)
    raw = (const_out / "observed/phases.bin").read_bytes().decode("latin-1")
    demotions = [line for line in raw.splitlines() if "DEMOTE #326c3z4" in line]
    assert len(demotions) == 1 and "[1:2004 #216c3z4" in demotions[0]
    for receipt in (tail_receipt, const_receipt):
        assert receipt["whole_coff_equal_except_timestamp"]
        assert receipt["missing_stream_rejected"]
        assert not receipt["compiler_decisions_modified"]
    return {
        "transitions": transitions,
        "demotion": re.sub(r"T [0-9a-f]+ ", "T ", demotions[0]),
        "receipts": [
            {
                key: receipt[key]
                for key in (
                    "source_sha256",
                    "normalized_coff_sha256",
                    "whole_coff_equal_except_timestamp",
                    "missing_stream_rejected",
                    "compiler_decisions_modified",
                    "metrics",
                )
            }
            for receipt in (tail_receipt, const_receipt)
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--trace", action="store_true")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    results = {name: build(name, source, args.out) for name, source in cases().items()}
    witness = results["plain_guard"]
    assert witness["triplet"] and witness["frame"] == "sub esp, 0x1c"
    assert witness["instructions"] == 115 and witness["prefix"] == 88
    assert witness["references"] == [13, 0, 0]
    assert witness["different_instructions"] == [
        {
            "target": "fadd dword [esi+0x4]",
            "candidate": "fadd dword [edi+-0x8]",
        },
    ]
    assert results["y_pointer"]["different_instructions"] == [
        {
            "target": "mov eax, dword [edi+-0x4]",
            "candidate": "mov eax, dword [esi+0x8]",
        },
    ]
    for name in ("delete_guard", "reverse_guard", "live_named_pointer", "live_null_check"):
        assert not results[name]["triplet"], name
    assert all(not row["body_byte_exact"] for row in results.values())
    if args.trace:
        results["trace"] = trace(args.out / "plain_guard", args.out)
    (args.out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    for name, row in results.items():
        if name != "trace":
            print(
                f"{name:20} {row['ratio']:.6%} {row['instructions']} insns prefix {row['prefix']} triplet={row['triplet']}",
            )


if __name__ == "__main__":
    main()
