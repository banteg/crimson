"""Bounded, heuristic residual views. Nothing here participates in match scoring."""

from __future__ import annotations

import difflib
import re
from collections import Counter, defaultdict
from typing import Any

from .match import DisassemblyLine, MatchResult

_STACK_OPERAND = re.compile(r"\[(esp|ebp)((?:\+?-|\+)(?:0x[0-9a-f]+|[0-9]+))?\]")
_LOCAL_BRANCH = re.compile(r"^((?:j[a-z]+|loop[a-z]*) )L([0-9a-f]+)$")
_METHOD = (
    "Diagnostic only: monotonic SequenceMatcher alignment after masking simple esp/ebp "
    "displacements and direct local branch labels; all other operands are preserved. "
    "Repeated matching runs are flagged as ambiguous. Branch offsets are grouped only "
    "when their instruction destinations agree under an unambiguous diagnostic pairing."
)
_CAVEAT = (
    "Observed displacements are not equivalent variables or proven stack homes: esp moves, "
    "ebp may be a general register, and lifetimes can reuse slots. Alignment is heuristic; "
    "scoring, exactness, reference audits, body identity, and acceptance are unchanged."
)


def _shape(line: str) -> str:
    line = _STACK_OPERAND.sub(lambda match: f"[{match[1]}+DISP]", line)
    return _LOCAL_BRANCH.sub(r"\1LOCAL", line)


def _slots(line: str) -> tuple[str, ...]:
    return tuple(match[0] for match in _STACK_OPERAND.finditer(line))


def _repeated_run(lines: tuple[str, ...], run: tuple[str, ...]) -> bool:
    matches = 0
    for index in range(len(lines) - len(run) + 1):
        if lines[index] == run[0] and lines[index : index + len(run)] == run:
            matches += 1
            if matches == 2:
                return True
    return False


def _checked_disassembly(
    lines: tuple[str, ...],
    disassembly: tuple[DisassemblyLine, ...],
) -> tuple[DisassemblyLine, ...]:
    # Synthetic/incomplete results must not attach an unrelated address to a line.
    return disassembly if tuple(line.text for line in disassembly) == lines else ()


def _line_payload(
    lines: tuple[str, ...],
    disassembly: tuple[DisassemblyLine, ...],
    index: int,
) -> dict[str, Any]:
    instruction = disassembly[index] if disassembly else None
    return {
        "index": index,
        "text": lines[index],
        "offset": instruction.offset if instruction else None,
        "address": instruction.address if instruction else None,
    }


def _context_payload(
    lines: tuple[str, ...],
    disassembly: tuple[DisassemblyLine, ...],
    start: int,
    end: int,
    context: int,
) -> dict[str, Any]:
    indices = list(range(max(0, start - context), min(len(lines), end + context)))
    # Large replacements stay bounded even when there are no useful anchors.
    limit = 2 * context + 12
    omitted = max(0, len(indices) - limit)
    if omitted:
        half = limit // 2
        indices = indices[:half] + indices[-(limit - half) :]
    return {
        "start": start,
        "end": end,
        "omitted_lines": omitted,
        "lines": [{**_line_payload(lines, disassembly, index), "changed": start <= index < end} for index in indices],
    }


def residual_summary_payload(
    result: MatchResult,
    *,
    context: int = 4,
    limit: int = 8,
) -> dict[str, Any]:
    """Explain patterns without substituting a more permissive MatchResult."""
    if context < 0 or limit < 1:
        raise ValueError("context must be non-negative and limit must be positive")
    target, candidate = result.target_lines, result.candidate_lines
    target_asm = _checked_disassembly(target, result.target_disassembly)
    candidate_asm = _checked_disassembly(candidate, result.candidate_disassembly)
    target_shapes = tuple(map(_shape, target))
    candidate_shapes = tuple(map(_shape, candidate))
    opcodes = difflib.SequenceMatcher(a=target_shapes, b=candidate_shapes, autojunk=False).get_opcodes()
    pairs: dict[int, int] = {}
    ambiguous: set[int] = set()
    remaining: list[tuple[str, int, int, int, int]] = []
    for tag, a0, a1, b0, b1 in opcodes:
        if tag != "equal":
            remaining.append((f"instruction-or-operand-{tag}", a0, a1, b0, b1))
            continue
        pairs.update(zip(range(a0, a1), range(b0, b1), strict=True))
        run = target_shapes[a0:a1]
        if _repeated_run(target_shapes, run) or _repeated_run(candidate_shapes, run):
            ambiguous.update(range(a0, a1))

    target_offsets = {line.offset: index for index, line in enumerate(target_asm)}
    candidate_offsets = {line.offset: index for index, line in enumerate(candidate_asm)}
    counts: Counter[str] = Counter()
    observations: dict[tuple[str, str], list[tuple[int, int]]] = defaultdict(list)
    for a, b in pairs.items():
        for left, right in zip(_slots(target[a]), _slots(candidate[b]), strict=True):
            observations[left, right].append((a, b))
        target_branch = _LOCAL_BRANCH.fullmatch(target[a])
        candidate_branch = _LOCAL_BRANCH.fullmatch(candidate[b])
        if target_branch and candidate_branch:
            destination_a = target_offsets.get(int(target_branch[2], 16))
            destination_b = candidate_offsets.get(int(candidate_branch[2], 16))
            mapped = pairs.get(destination_a) if destination_a is not None else None
            if destination_a in ambiguous or a in ambiguous or mapped is None or destination_b is None:
                kind = "branch-destination-unchecked"
            elif mapped != destination_b:
                kind = "branch-destination-conflict"
            else:
                kind = "branch-offset-only" if target[a] != candidate[b] else "identical"
            # Also expose same-label branches whose destinations no longer align.
            if kind.startswith("branch-destination"):
                remaining.append((kind, a, a + 1, b, b + 1))
        elif target[a] == candidate[b]:
            kind = "identical"
        else:
            kind = "stack-displacement-only"
        counts[kind] += 1

    forward: dict[str, set[str]] = defaultdict(set)
    reverse: dict[str, set[str]] = defaultdict(set)
    changed_slots: set[str] = set()
    for left, right in observations:
        forward[left].add(right)
        reverse[right].add(left)
        if left != right:
            changed_slots.update((left, right))
    relationships: list[dict[str, Any]] = []
    for (left, right), samples in observations.items():
        if left == right and left not in changed_slots:
            continue
        mapping = f"{'many' if len(reverse[right]) > 1 else 'one'}-to-{'many' if len(forward[left]) > 1 else 'one'}"
        selected = [samples[0]] if len(samples) == 1 else [samples[0], samples[-1]]
        relationships.append(
            {
                "target": left,
                "candidate": right,
                "observations": len(samples),
                "mapping": mapping,
                "conflicting": mapping != "one-to-one",
                "ambiguous_observations": sum(a in ambiguous for a, _ in samples),
                "samples": [
                    {
                        "target": _line_payload(target, target_asm, a),
                        "candidate": _line_payload(candidate, candidate_asm, b),
                    }
                    for a, b in selected
                ],
            },
        )
    relationships.sort(key=lambda row: (not row["conflicting"], -row["observations"], row["target"], row["candidate"]))
    remaining.sort(key=lambda span: (span[1], span[3]))
    problems = [entry for entry in result.masked_operand_audit.entries if entry.status != "ok"]
    return {
        "method": _METHOD,
        "caveat": _CAVEAT,
        "summary": {
            "aligned_pairs": len(pairs),
            "identical_pairs": counts["identical"],
            "stack_displacement_pairs": counts["stack-displacement-only"],
            "branch_offset_pairs": counts["branch-offset-only"],
            "ambiguous_pairs": len(ambiguous),
            "remaining_spans": len(remaining),
            "remaining_target_instructions": sum(a1 - a0 for _, a0, a1, _, _ in remaining),
            "remaining_candidate_instructions": sum(b1 - b0 for _, _, _, b0, b1 in remaining),
            "stack_relationships": len(relationships),
            "conflicting_stack_relationships": sum(row["conflicting"] for row in relationships),
            "reference_problems": len(problems),
        },
        "stack_relationships": relationships[:limit],
        "omitted_stack_relationships": max(0, len(relationships) - limit),
        "remaining": [
            {
                "kind": kind,
                "target": _context_payload(target, target_asm, a0, a1, context),
                "candidate": _context_payload(candidate, candidate_asm, b0, b1, context),
            }
            for kind, a0, a1, b0, b1 in remaining[:limit]
        ],
        "omitted_remaining_spans": max(0, len(remaining) - limit),
        "reference_problems": [
            {
                "status": entry.status,
                "target_address": entry.target_address,
                "candidate_offset": entry.candidate_offset,
                "instruction": entry.instruction,
                "target_keys": [list(ref.keys) for ref in entry.target_references],
                "candidate_keys": [list(ref.keys) for ref in entry.candidate_references],
            }
            for entry in problems[:limit]
        ],
        "omitted_reference_problems": max(0, len(problems) - limit),
    }


def _location(line: dict[str, Any], *, target: bool) -> str:
    value = line["address" if target else "offset"]
    address = (f"0x{value:08x}" if target else f"+0x{value:x}") if value is not None else "address unavailable"
    return f"[{line['index']}] {address} {line['text']}"


def render_residual_summary(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "residual summary (diagnostic only)",
        payload["method"],
        payload["caveat"],
        (
            f"aligned={summary['aligned_pairs']} identical={summary['identical_pairs']} "
            f"stack-displacement-only={summary['stack_displacement_pairs']} "
            f"branch-offset-only={summary['branch_offset_pairs']} ambiguous={summary['ambiguous_pairs']} "
            f"remaining-insns={summary['remaining_target_instructions']}/{summary['remaining_candidate_instructions']}"
        ),
    ]
    for index, span in enumerate(payload["remaining"], start=1):
        lines.append(f"\nresidual {index}: {span['kind']}")
        for side, marker in (("target", "-"), ("candidate", "+")):
            view = span[side]
            lines.append(f"  {side} changed={view['start']}:{view['end']}")
            previous = None
            for line in view["lines"]:
                if previous is not None and line["index"] != previous + 1:
                    lines.append(f"    ... {view['omitted_lines']} instructions omitted ...")
                prefix = marker if line["changed"] else " "
                lines.append(f"  {prefix} {_location(line, target=side == 'target')}")
                previous = line["index"]
    if payload["omitted_remaining_spans"]:
        lines.append(f"  ... {payload['omitted_remaining_spans']} more residual spans (increase --max-regions)")
    lines.append(
        f"\nstack displacement relationships: {summary['stack_relationships']} "
        f"({summary['conflicting_stack_relationships']} conflicting; observations, not variable mappings)",
    )
    for row in payload["stack_relationships"]:
        lines.append(
            f"  {row['target']} -> {row['candidate']}: n={row['observations']} "
            f"{row['mapping']} observed{' CONFLICT' if row['conflicting'] else ''} "
            f"ambiguous={row['ambiguous_observations']}",
        )
        for sample in row["samples"]:
            lines.append(f"    - {_location(sample['target'], target=True)}")
            lines.append(f"    + {_location(sample['candidate'], target=False)}")
    if payload["omitted_stack_relationships"]:
        lines.append(f"  ... {payload['omitted_stack_relationships']} more relationships (increase --max-regions)")
    lines.append(f"\nreference audit problems: {summary['reference_problems']}")
    for entry in payload["reference_problems"]:
        lines.append(
            f"  {entry['status']} target=0x{entry['target_address']:08x} "
            f"candidate=+0x{entry['candidate_offset']:x} {entry['instruction']} "
            f"keys={entry['target_keys']} -> {entry['candidate_keys']}",
        )
    if payload["omitted_reference_problems"]:
        lines.append(f"  ... {payload['omitted_reference_problems']} more reference problems (increase --max-regions)")
    return "\n".join(lines)
