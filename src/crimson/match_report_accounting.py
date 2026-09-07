"""Auditable measurement identities and diagnostics outside the objdiff schema."""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from . import match as matchlib
from . import match_toolchain

VERIFICATION = "source-bound local compilation; CI checks freshness and report consistency"
SCORING_POLICY = "normalized-positional-references-v1; relocation-audited-body-v1; full-compared-coverage-v1"
INVENTORY_POLICY = "curated-functions-v1; executable-gaps-unresolved-v1"


def native_id(row: dict[str, Any]) -> str:
    return f"{row['image']}/{row['address']:08x}"


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def identities(
    functions: list[dict[str, Any]], inputs: dict[str, str], external: dict[str, str],
    toolchains: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "target": {path: digest for path, digest in external.items() if path.startswith("game_bins/")},
        "inventory": _digest({
            "policy": INVENTORY_POLICY,
            "ranges": [(r["image"], r["address"], r["size"]) for r in functions],
            "ownership": {p: h for p, h in inputs.items() if p in {
                "analysis/matching_scope.json", "analysis/library_provenance.json"}},
        }),
        "scoring": _digest({"policy": SCORING_POLICY, "toolchains": toolchains or {}, "implementation": {
            p: h for p, h in inputs.items() if p.startswith("src/crimson/match") or p in {"pyproject.toml", "uv.lock"}
        }}),
        "inventory_policy": INVENTORY_POLICY,
        "scoring_policy": SCORING_POLICY,
    }


def candidate_evidence(status: matchlib.ScratchStatus | None) -> dict[str, Any]:
    if status is None:
        return {"proof": None}
    start = status.address
    end = start + status.target_size
    compared_end = end - status.target_padding_bytes
    entries = status.audit.entries
    positional = status.ratio == 1 and all(e.target_index == e.candidate_index for e in entries)
    object_hash = match_toolchain.file_sha256(matchlib._scratch_object_path(status.config))
    if object_hash is None:
        raise ValueError(f"missing candidate object: {status.config.function}")
    return {"proof": {
        "state": status.state,
        "target_size": status.target_size,
        "target_instructions": status.target_instructions,
        "candidate_instructions": status.candidate_instructions,
        "references": {"ok": status.masked_ok, "unresolved": status.masked_unresolved,
                       "mismatched": status.masked_mismatches, "positional": positional},
        "body_byte_exact": status.body_byte_exact,
        "candidate_object_sha256": object_hash,
        "compared_target_ranges": [[start, compared_end]] if compared_end > start else [],
        "excluded_target_ranges": ([{"start": compared_end, "end": end, "reason": "recognized terminal padding"}]
                                   if compared_end < end else []),
        "unexplained_target_ranges": [],
        "candidate_padding_bytes": status.candidate_padding_bytes,
    }}


def normalized_exact(row: dict[str, Any], *, ratio: float | None = None) -> bool:
    proof = row["proof"]
    if proof is None:
        return False
    refs = proof["references"]
    covered = sum(max(0, min(end, row["address"] + row["size"]) - max(start, row["address"]))
                  for start, end in proof["compared_target_ranges"])
    return bool((row["ratio"] if ratio is None else ratio) == 1 and refs["positional"]
                and not refs["unresolved"] and not refs["mismatched"]
                and covered == row["size"] and not proof["unexplained_target_ranges"])


def validate_function(row: dict[str, Any]) -> None:
    key = native_id(row)
    ratio = row["ratio"]
    if type(ratio) not in (int, float) or not math.isfinite(ratio) or not 0 <= ratio <= 1:
        raise ValueError(f"invalid ratio: {key}")
    proof = row["proof"]
    if proof is None:
        if row["candidate"] is not None or row["matched"] or ratio != 0 or row["source"] is not None:
            raise ValueError(f"missing candidate proof: {key}")
        return
    if row["candidate"] not in {"source", "archive", "import-thunk"}:
        raise ValueError(f"invalid candidate kind: {key}")
    if bool(row["source"]) != (row["candidate"] == "source"):
        raise ValueError(f"invalid candidate source: {key}")
    digest = proof["candidate_object_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError(f"invalid candidate object hash: {key}")
    refs = proof["references"]
    for value in [proof["target_size"], proof["target_instructions"], proof["candidate_instructions"],
                  proof["candidate_padding_bytes"], *(refs[k] for k in ("ok", "unresolved", "mismatched"))]:
        if type(value) is not int or value < 0:
            raise ValueError(f"invalid proof count: {key}")
    if type(refs["positional"]) is not bool or type(proof["body_byte_exact"]) is not bool:
        raise ValueError(f"invalid proof result: {key}")
    if refs["positional"] and (ratio != 1 or proof["target_instructions"] != proof["candidate_instructions"]):
        raise ValueError(f"invalid positional reference proof: {key}")
    expected_state = "wip" if ratio != 1 else "audit" if refs["unresolved"] or refs["mismatched"] else "match"
    if proof["state"] != expected_state:
        raise ValueError(f"inconsistent matching state: {key}")
    spans = [(start, end) for start, end in proof["compared_target_ranges"]]
    for excluded in proof["excluded_target_ranges"]:
        if excluded["reason"] != "recognized terminal padding":
            raise ValueError(f"unsupported exclusion: {key}")
        spans.append((excluded["start"], excluded["end"]))
    spans.extend(tuple(span) for span in proof["unexplained_target_ranges"])
    cursor = row["address"]
    for start, end in sorted(spans):
        if type(start) is not int or type(end) is not int or start != cursor or end <= start:
            raise ValueError(f"invalid compared coverage partition: {key}")
        cursor = end
    if cursor != row["address"] + proof["target_size"] or proof["target_size"] < row["size"]:
        raise ValueError(f"incomplete compared coverage: {key}")
    if type(row["matched"]) is not bool or row["matched"] != normalized_exact(row):
        raise ValueError(f"inconsistent normalized credit: {key}")
    if proof["body_byte_exact"] and (ratio != 1 or expected_state != "match" or not refs["positional"]):
        raise ValueError(f"inconsistent encoded-body proof: {key}")


def reconcile_sections(sections: list[dict[str, Any]], functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Partition executable virtual bytes; never guess that an uncovered gap is padding."""
    result = []
    assigned = set()
    section_ends: dict[str, int] = {}
    for section in sorted(sections, key=lambda r: (r["image"], r["address"])):
        start, end = section["address"], section["address"] + section["size"]
        if start < section_ends.get(section["image"], 0) or end <= start:
            raise ValueError("overlapping or empty executable sections")
        section_ends[section["image"]] = end
        cursor = start
        spans: list[dict[str, Any]] = []
        for row in sorted(functions, key=lambda r: (r["address"], r["size"])):
            if row["image"] != section["image"] or not start <= row["address"] < end:
                continue
            lo, hi = row["address"], row["address"] + row["size"]
            if lo < cursor or hi > end or row["size"] <= 0:
                raise ValueError(f"overlapping or invalid retained code: {native_id(row)}")
            if lo > cursor:
                spans.append({"start": cursor, "end": lo, "kind": "unresolved"})
            spans.append({"start": lo, "end": hi, "kind": "retained_code", "owner": native_id(row)})
            assigned.add(native_id(row))
            cursor = hi
        if cursor < end:
            spans.append({"start": cursor, "end": end, "kind": "unresolved"})
        totals = {kind: sum(s["end"] - s["start"] for s in spans if s["kind"] == kind)
                  for kind in ("retained_code", "embedded_data", "padding", "unresolved")}
        result.append({**section, "totals": totals, "ranges": spans})
    if len(assigned) != len(functions):
        raise ValueError("report functions are duplicated or outside executable sections")
    return result


def code_inventory(functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    import pefile

    sections = []
    for image in matchlib.TRACKED_IMAGE_NAMES:
        with pefile.PE(str(matchlib._paths_for_image(image)[0]), fast_load=True) as pe:
            for section in pe.sections:
                if section.Characteristics & 0x20000000 and section.Misc_VirtualSize:
                    sections.append({"image": image, "name": section.Name.rstrip(b"\0").decode("ascii"),
                                     "address": int(pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress),
                                     "size": int(section.Misc_VirtualSize)})
    return reconcile_sections(sections, functions)


def diagnostics(
    evidence: dict[str, Any], previous: dict[str, Any] | None = None, *, report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows = evidence["functions"]
    source_matches = [r for r in rows if r["candidate"] == "source" and r["matched"]]
    encoded = [r for r in source_matches if r["proof"]["body_byte_exact"]]
    unmatched = [r for r in rows if r not in source_matches]
    total = sum(r["size"] for r in rows)
    result = {
        "schema": 1, "verification": evidence["verification"], "identities": evidence["identities"],
        "total_code": total, "normalized_matched_code": sum(r["size"] for r in source_matches),
        "encoded_body_matched_code": sum(r["size"] for r in encoded),
        "encoded_body_matched_functions": len(encoded),
        "encoded_body_matched_percent": 100 * sum(r["size"] for r in encoded) / total if total else 0,
        "unmatched_code": sum(r["size"] for r in unmatched),
        "largest_unmatched": [{"id": native_id(r), "name": r["name"], "size": r["size"]}
                              for r in sorted(unmatched, key=lambda r: (-r["size"], native_id(r)))[:20]],
        "code_inventory": evidence["code_inventory"],
    }
    if report is not None:
        by_id = {native_id(r): r for r in rows}
        result["scopes"] = {}
        for category in report["categories"]:
            members = [by_id[u["name"]] for u in report["units"] if u["name"] in by_id
                       and category["id"] in u["metadata"]["progress_categories"]]
            size = sum(r["size"] for r in members)
            encoded_size = sum(r["size"] for r in members if r["candidate"] == "source" and r["matched"]
                               and r["proof"]["body_byte_exact"])
            result["scopes"][category["id"]] = {
                "total_code": size, "normalized_matched_code": int(category["measures"]["matched_code"]),
                "encoded_body_matched_code": encoded_size,
                "encoded_body_matched_percent": 100 * encoded_size / size if size else 0,
            }
    if previous is not None:
        old_ids = previous.get("identities", {})
        changes = [key for key in ("target", "inventory", "scoring") if old_ids.get(key) != evidence["identities"][key]]
        old = {native_id(r): r for r in previous["functions"]}
        newly = sum(r["size"] for r in source_matches
                    if native_id(r) not in old or not (old[native_id(r)]["matched"] and old[native_id(r)]["candidate"] == "source"))
        current = {native_id(r): r for r in source_matches}
        regressed = sum(r["size"] for r in old.values() if r["matched"] and r["candidate"] == "source"
                        and native_id(r) not in current)
        result["delta"] = {"measurement_changes": changes, "comparable": not changes,
                           "newly_matched_code": newly, "regressed_code": regressed,
                           "interpretation": "measurement baseline changed" if changes else "reconstruction progress"}
    return result
