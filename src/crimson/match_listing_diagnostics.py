"""Optional stack observations tied to an object-equivalent compiler listing."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import match as matchlib
from .match_diagnostics import _checked_disassembly, _line_payload, _location, _residual_alignment, _slots

_PROC = re.compile(r"^(\S+)\s+PROC\b")
_DECLARATION = re.compile(r"^(\S+)\s*=\s*([+-]?\d+)\s*(?:;.*)?$")
_SOURCE = re.compile(r"^;\s*(\d+)\s+:")
_ROW = re.compile(r"^\s*([0-9a-fA-F]{5,8})\t(.*)$")
_INTEGER = r"(?:0[0-9a-fA-F]+H|\d+)"
_SIGNED_INTEGER = re.compile(rf"[+-]?{_INTEGER}$", re.IGNORECASE)
_STACK = re.compile(rf"([^\s,\[\]]*)\[(esp|ebp)([+-]{_INTEGER})?\]", re.IGNORECASE)
_NORMAL_STACK = re.compile(r"\[(esp|ebp)([+-](?:-)?(?:0x[0-9a-f]+|\d+))?\]")


@dataclass(frozen=True, slots=True)
class ListingInstruction:
    offset: int
    assembly: str
    source_lines: tuple[int, ...]
    listing_line: int


def parse_stack_listing(
    text: str,
    *,
    symbol: str,
) -> tuple[dict[str, int], dict[int, ListingInstruction]]:
    """Scope aliases and wrapped machine rows to exactly one selected PROC."""
    lines = text.splitlines()
    accepted = {symbol, symbol.removeprefix("_"), f"_{symbol.removeprefix('_')}"}
    starts = [i for i, line in enumerate(lines) if (m := _PROC.match(line)) and m[1] in accepted]
    if len(starts) != 1:
        raise ValueError("stack diagnostics require exactly one selected listing PROC")
    start = starts[0]
    proc_name = lines[start].split()[0]
    end = next(
        (i for i in range(start + 1, len(lines)) if re.match(rf"^{re.escape(proc_name)}\s+ENDP\b", lines[i])), None,
    )
    if end is None:
        raise ValueError("selected listing PROC has no ENDP")
    segment = max((i for i in range(start) if re.search(r"\bSEGMENT\b", lines[i])), default=-1)
    declarations: dict[str, int] = {}
    for line in lines[segment + 1 : start]:
        if m := _DECLARATION.fullmatch(line):
            if m[1] in declarations:
                raise ValueError(f"duplicate compiler stack declaration: {m[1]}")
            declarations[m[1]] = int(m[2])

    rows: dict[int, ListingInstruction] = {}
    offset: int | None = None
    pending_source: list[int] = []
    source_lines: tuple[int, ...] = ()
    for index in range(start + 1, end):
        line = lines[index]
        if m := _SOURCE.match(line):
            pending_source.append(int(m[1]))
            continue
        if m := _ROW.match(line):
            next_offset = int(m[1], 16)
            if offset is None and next_offset != 0:
                raise ValueError("stack diagnostics do not support a nonzero listing PROC origin")
            offset = next_offset
            line = m[2]
            if pending_source:
                source_lines = tuple(dict.fromkeys(pending_source))
                pending_source.clear()
        elif not line.startswith("\t"):
            continue
        # Long encoded instructions wrap: the mnemonic can occur on a byte-only
        # continuation row with no address of its own.
        tokens = line.partition(";")[0].split()
        byte_count = 0
        while byte_count < len(tokens) and re.fullmatch(r"[0-9a-fA-F]{2}", tokens[byte_count]):
            byte_count += 1
        if not byte_count or byte_count == len(tokens) or offset is None:
            continue
        if offset in rows:
            raise ValueError(f"duplicate compiler instruction offset: 0x{offset:x}")
        rows[offset] = ListingInstruction(offset, " ".join(tokens[byte_count:]), source_lines, index + 1)
    return declarations, rows


def _integer(text: str) -> int:
    return int(text[:-1], 16) if text.lower().endswith("h") else int(text)


def _listing_operand(match: re.Match[str], declarations: dict[str, int]) -> dict[str, Any]:
    expression, prefix, base = match[0], match[1].removesuffix("+"), match[2].lower()
    bias = _integer(match[3]) if match[3] else 0
    if not prefix:
        return {
            "kind": "unannotated",
            "name": None,
            "declared_offset": None,
            "base": base,
            "bias": bias,
            "effective_offset": bias,
            "expression": expression,
        }
    if _SIGNED_INTEGER.fullmatch(prefix):
        name, declared, kind = None, _integer(prefix), "unnamed_frame"
    else:
        matches = [
            name
            for name in declarations
            if prefix == name
            or (
                prefix.startswith(name)
                and prefix[len(name) :].startswith(("+", "-"))
                and _SIGNED_INTEGER.fullmatch(prefix[len(name) :])
            )
        ]
        if len(matches) != 1:
            raise ValueError("unknown or ambiguous compiler stack alias")
        name = matches[0]
        declared = declarations[name]
        if suffix := prefix[len(name) :]:
            bias += _integer(suffix)
        kind = "generated" if name.startswith("$T") else "named"
    return {
        "kind": kind,
        "name": name,
        "declared_offset": declared,
        "base": base,
        "bias": bias,
        "effective_offset": declared + bias,
        "expression": expression,
    }


def _normal_displacement(slot: str) -> tuple[str, int]:
    match = _NORMAL_STACK.fullmatch(slot)
    assert match is not None
    return match[1], int(match[2].replace("+-", "-"), 0) if match[2] else 0


def stack_local_observations_payload(
    result: matchlib.MatchResult,
    listing_text: str,
    *,
    symbol: str,
    limit: int = 12,
) -> dict[str, Any]:
    """Analyze verified listing text; use compiler_stack_residual_payload for file validation."""
    if limit < 1:
        raise ValueError("stack entry limit must be positive")
    target_asm = _checked_disassembly(result.target_lines, result.target_disassembly)
    candidate_asm = _checked_disassembly(result.candidate_lines, result.candidate_disassembly)
    if not target_asm or not candidate_asm:
        raise ValueError("stack diagnostics require complete target and candidate disassembly")
    declarations, rows = parse_stack_listing(listing_text, symbol=symbol)
    pairs, ambiguous, _ = _residual_alignment(result.target_lines, result.candidate_lines)
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    skipped: list[dict[str, Any]] = []
    paired_stack: set[int] = set()
    for a, b in pairs.items():
        target_slots, candidate_slots = _slots(result.target_lines[a]), _slots(result.candidate_lines[b])
        if not candidate_slots:
            continue
        sample = {
            "target": _line_payload(result.target_lines, target_asm, a),
            "candidate": _line_payload(result.candidate_lines, candidate_asm, b),
        }
        row = rows.get(candidate_asm[b].offset)
        if a in ambiguous:
            skipped.append({**sample, "reason": "ambiguous-instruction-pair"})
            continue
        reference_status = matchlib._masked_reference_status(
            target_asm[a].masked_references,
            candidate_asm[b].masked_references,
        )
        if reference_status != "ok":
            skipped.append({**sample, "reason": f"paired-reference-{reference_status}"})
            continue
        if row is None or row.assembly.split()[0].lower() != result.candidate_lines[b].split()[0]:
            skipped.append({**sample, "reason": "missing-or-inconsistent-listing-instruction"})
            continue
        try:
            operands = [_listing_operand(match, declarations) for match in _STACK.finditer(row.assembly)]
        except ValueError as exc:
            skipped.append({**sample, "reason": str(exc)})
            continue
        if len(operands) != len(candidate_slots) or any(
            (operand["base"], operand["effective_offset"]) != _normal_displacement(slot)
            for operand, slot in zip(operands, candidate_slots)
        ):
            skipped.append({**sample, "reason": "listing-displacement-does-not-match-candidate"})
            continue
        paired_stack.add(b)
        for operand, left, right in zip(operands, target_slots, candidate_slots, strict=True):
            delta = _normal_displacement(left)[1] - _normal_displacement(right)[1]
            # No frame offset is invented for a bare [esp+N]. Keep its grouping
            # explicitly tied to the observed displacement instead.
            key = (
                operand["kind"],
                operand["name"],
                operand["declared_offset"],
                operand["base"],
                operand["effective_offset"] if operand["kind"] == "unannotated" else None,
            )
            groups[key].append(
                {
                    **sample,
                    "delta": delta,
                    "source_lines": list(row.source_lines),
                    "listing_line": row.listing_line,
                    "listing_expression": operand["expression"],
                    "listing_bias": operand["bias"],
                },
            )

    sections: dict[str, list[dict[str, Any]]] = {"locals": [], "unnamed_frame_accesses": [], "unannotated_accesses": []}
    for (kind, name, declared, base, raw_offset), samples in groups.items():
        samples.sort(key=lambda sample: sample["candidate"]["index"])
        deltas: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for sample in samples:
            deltas[sample["delta"]].append(sample)
        delta_rows = [
            {"target_minus_candidate": delta, "observations": len(examples), "sample": examples[0]}
            for delta, examples in sorted(deltas.items(), key=lambda item: (-len(item[1]), item[0]))
        ]
        section = {"unnamed_frame": "unnamed_frame_accesses", "unannotated": "unannotated_accesses"}.get(kind, "locals")
        sections[section].append(
            {
                "kind": kind,
                "name": name,
                "declared_frame_offset": declared if name else None,
                "listing_frame_offset": declared,
                "base": base,
                "raw_candidate_displacement": raw_offset,
                "observations": len(samples),
                "changed_observations": sum(sample["delta"] != 0 for sample in samples),
                "conflicting_deltas": len(deltas) > 1,
                "deltas": delta_rows[:limit],
                "omitted_deltas": max(0, len(delta_rows) - limit),
                "access_span": {"first": samples[0], "last": samples[-1]},
                "accesses": samples[:limit],
                "omitted_accesses": max(0, len(samples) - limit),
            },
        )
    for entries in sections.values():
        entries.sort(key=lambda row: (not row["conflicting_deltas"], -row["changed_observations"], row["name"] or ""))
    candidate_stack = {i for i, line in enumerate(result.candidate_lines) if _slots(line)}
    return {
        "caveat": (
            "Diagnostic only: names and declared frame offsets belong to the candidate compiler listing. "
            "Pairing uses monotonic instruction-shape alignment; repeated matching runs are excluded. "
            "Deltas compare paired instruction displacements, not proven native variable homes. "
            "ESP movement, object fields, and lifetime reuse are not inferred; multiple observed deltas "
            "remain conflicts. Accesses are in instruction order; first/last observations bound a use span, "
            "not a live range. Bare stack accesses are not assigned a local name or a frame offset."
        ),
        "match": {
            "exact": result.exact,
            "body_byte_exact": result.body_byte_exact,
            "ratio": result.ratio,
            "prefix_instructions": result.prefix_instructions,
            "target_instructions": len(result.target_lines),
            "candidate_instructions": len(result.candidate_lines),
            "references": {
                "ok": result.masked_operand_audit.ok_count,
                "unresolved": result.masked_operand_audit.unresolved_count,
                "mismatch": result.masked_operand_audit.mismatch_count,
            },
        },
        "summary": {
            "declared_symbols": len(declarations),
            "candidate_stack_instructions": len(candidate_stack),
            "paired_stack_instructions": len(paired_stack),
            "unpaired_stack_instructions": len(candidate_stack - set(pairs.values())),
            "skipped_instructions": len(skipped),
            "skip_reasons": dict(Counter(row["reason"] for row in skipped)),
            **{section: len(entries) for section, entries in sections.items()},
        },
        **{section: entries[:limit] for section, entries in sections.items()},
        "omitted_entries": {section: max(0, len(entries) - limit) for section, entries in sections.items()},
        "skipped": skipped[:limit],
        "omitted_skipped": max(0, len(skipped) - limit),
    }


def compiler_stack_residual_payload(
    config: matchlib.ScratchConfig,
    listing: matchlib.CompilerListingResult,
    *,
    limit: int = 12,
) -> dict[str, Any]:
    """Bind listing observations to a snapshot of the proven candidate object."""
    metadata = json.loads(listing.metadata_path.read_text(encoding="utf-8"))
    listing_data = listing.listing_path.read_bytes()
    object_data = listing.canonical_object.read_bytes()
    if (
        metadata.get("object_function_equivalent") is not True
        or metadata.get("listing_sha256") != hashlib.sha256(listing_data).hexdigest()
        or metadata.get("canonical_object_sha256") != hashlib.sha256(object_data).hexdigest()
        or listing.canonical_object_sha256 != hashlib.sha256(object_data).hexdigest()
        or listing.scratch.resolve() != config.directory.resolve()
        or listing.function != config.function
    ):
        raise ValueError("stale or inconsistent verified compiler listing; regenerate with match listing")
    function = matchlib.extract_object_function(
        matchlib.parse_coff_object(object_data),
        config.symbol,
        extent=config.archive_extent,
        end_symbol=config.archive_end_symbol,
        size=config.archive_size,
    )
    if hashlib.sha256(function.data).hexdigest() != listing.function_sha256:
        raise ValueError("selected object function differs from the verified compiler listing")
    with tempfile.TemporaryDirectory(prefix="crimson-stack-listing-") as temp:
        obj = Path(temp) / "candidate.obj"
        obj.write_bytes(object_data)
        result = matchlib.run_match(
            obj_path=obj,
            function=config.function,
            image_path=matchlib.default_image_path(config.image),
            functions_path=matchlib.default_functions_path(config.image),
            metadata_path=matchlib.default_metadata_path(config.image),
            symbol_name=config.symbol,
            object_extent=config.archive_extent,
            object_end_symbol=config.archive_end_symbol,
            object_size=config.archive_size,
            end_va=config.end_va,
            reference_aliases=config.reference_aliases,
        )
    return stack_local_observations_payload(
        result,
        listing_data.decode("latin1"),
        symbol=config.symbol or config.function,
        limit=limit,
    )


def render_stack_local_observations(payload: dict[str, Any]) -> str:
    match, summary = payload["match"], payload["summary"]
    refs = match["references"]
    lines = [
        "stack locals (diagnostic only)",
        payload["caveat"],
        (
            f"match={match['ratio']:.2%} exact={match['exact']} body_byte_exact={match['body_byte_exact']} "
            f"insns={match['target_instructions']}/{match['candidate_instructions']} "
            f"refs={refs['ok']}/{refs['unresolved']}/{refs['mismatch']} "
            f"paired-stack={summary['paired_stack_instructions']}/{summary['candidate_stack_instructions']} "
            f"unpaired={summary['unpaired_stack_instructions']} skipped={summary['skipped_instructions']}"
        ),
    ]
    for section, title in (
        ("locals", "Compiler locals and temporaries"),
        ("unnamed_frame_accesses", "Unnamed frame accesses (possible spills or reused storage)"),
        ("unannotated_accesses", "Unannotated stack accesses (home unknown)"),
    ):
        lines.append(f"\n{title}: {summary[section]}")
        for row in payload[section]:
            name = row["name"] or row["base"]
            frame = (
                f"declared={row['declared_frame_offset']}"
                if row["name"]
                else f"expression-offset={row['listing_frame_offset']}"
                if row["kind"] == "unnamed_frame"
                else f"raw-offset={row['raw_candidate_displacement']} home=unknown"
            )
            lines.append(
                f"  {name} ({row['kind']}) {frame} "
                f"observations={row['observations']} changed={row['changed_observations']}"
                f"{' CONFLICTING DELTAS' if row['conflicting_deltas'] else ''}",
            )
            first, last = row["access_span"]["first"], row["access_span"]["last"]
            lines.append(
                f"    observed-use-span: native=0x{first['target']['address']:08x}"
                f"..0x{last['target']['address']:08x} "
                f"candidate=+0x{first['candidate']['offset']:x}..+0x{last['candidate']['offset']:x}",
            )
            for delta in row["deltas"]:
                sample = delta["sample"]
                lines.append(
                    f"    target-candidate={delta['target_minus_candidate']:+d} n={delta['observations']} "
                    f"source={sample['source_lines']} listing-line={sample['listing_line']} "
                    f"{sample['listing_expression']}",
                )
                lines.append(f"      - {_location(sample['target'], target=True)}")
                lines.append(f"      + {_location(sample['candidate'], target=False)}")
            if row["omitted_deltas"]:
                lines.append(f"    ... {row['omitted_deltas']} more deltas")
        if payload["omitted_entries"][section]:
            lines.append(f"  ... {payload['omitted_entries'][section]} more entries (increase --max-stack-entries)")
    for skipped in payload["skipped"]:
        lines.append(f"\nskipped: {skipped['reason']}")
        lines.append(f"  - {_location(skipped['target'], target=True)}")
        lines.append(f"  + {_location(skipped['candidate'], target=False)}")
    if payload["omitted_skipped"]:
        lines.append(f"  ... {payload['omitted_skipped']} more skipped instructions")
    return "\n".join(lines)
