"""Compare address-keyed native matching evidence across revisions."""

from __future__ import annotations

import json
import math
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FunctionMatch:
    address: int
    function: str
    target_size: int
    state: str
    ratio: float
    prefix: int
    target_instructions: int
    candidate_instructions: int
    resolved: int
    unresolved: int
    mismatches: int
    body_byte_exact: bool | None


@dataclass(frozen=True)
class Manifest:
    image: str
    scope: str
    reference_sha256: str
    functions: tuple[FunctionMatch, ...]


@dataclass(frozen=True)
class Regression:
    image: str
    address: int | None
    check: str
    detail: str
    waiver: str | None = None


@dataclass(frozen=True)
class MatchDelta:
    image: str
    address: int
    function: str
    before: FunctionMatch
    after: FunctionMatch


def _integer(row: dict[str, Any], key: str) -> int:
    value = row[key]
    if type(value) is not int or value < 0:
        raise ValueError(f"{key} must be a non-negative integer")
    return value


def parse_manifest(payload: dict[str, Any]) -> Manifest:
    if payload["kind"] != "crimson-native-object-manifest" or payload["schema"] != 2:
        raise ValueError("unsupported native object manifest")
    image, scope, reference = payload["image"], payload["scope"], payload["reference_image_sha256"]
    if not isinstance(image, str) or not image or scope not in ("port", "all"):
        raise ValueError("invalid manifest image or scope")
    if not isinstance(reference, str) or len(reference) != 64:
        raise ValueError("invalid reference image digest")
    functions: list[FunctionMatch] = []
    addresses: set[int] = set()
    for obj in payload["objects"]:
        for row in obj["functions"]:
            address = _integer(row, "address")
            if address in addresses:
                raise ValueError(f"duplicate function {image}:0x{address:08x}")
            addresses.add(address)
            match = row["match"]
            ratio = match["ratio"]
            state = match["state"]
            if type(ratio) not in (float, int) or not math.isfinite(ratio) or not 0 <= ratio <= 1:
                raise ValueError("invalid match ratio")
            unresolved, mismatches = _integer(match, "masked_unresolved"), _integer(match, "masked_mismatches")
            expected_state = "wip" if ratio != 1 else "audit" if unresolved or mismatches else "match"
            if state != expected_state:
                raise ValueError("match state is inconsistent with score and reference debt")
            body_exact = match.get("body_byte_exact")
            if body_exact is not None and type(body_exact) is not bool:
                raise ValueError("body_byte_exact must be a boolean or absent")
            if body_exact is True and state != "match":
                raise ValueError("body-byte identity requires a reference-clean normalized match")
            name = row["function"]
            if not isinstance(name, str) or not name:
                raise ValueError("invalid function name")
            functions.append(
                FunctionMatch(
                    address,
                    name,
                    _integer(row, "target_size"),
                    state,
                    float(ratio),
                    _integer(match, "prefix_instructions"),
                    _integer(match, "target_instructions"),
                    _integer(match, "candidate_instructions"),
                    _integer(match, "masked_ok"),
                    unresolved,
                    mismatches,
                    body_exact,
                ),
            )
    if len(functions) != _integer(payload, "function_count"):
        raise ValueError("manifest function count does not match function rows")
    return Manifest(image, scope, reference, tuple(functions))


def compare_manifests(before: Manifest, after: Manifest) -> tuple[list[Regression], list[MatchDelta]]:
    if before.image != after.image:
        raise ValueError("cannot compare different images")
    regressions: list[Regression] = []
    deltas: list[MatchDelta] = []
    if before.reference_sha256 != after.reference_sha256:
        raise ValueError(f"{before.image}: reference image changed; select a comparable baseline")
    if before.scope != after.scope:
        regressions.append(Regression(before.image, None, "scope-changed", f"{before.scope} -> {after.scope}"))
    current = {row.address: row for row in after.functions}
    for old in before.functions:
        new = current.get(old.address)
        if new is None:
            regressions.append(Regression(before.image, old.address, "target-removed", old.function))
            continue
        changes: list[tuple[str, str]] = []
        if old.target_size != new.target_size:
            changes.append(("extent-changed", f"{old.target_size} -> {new.target_size} bytes"))
        if old.state == "match" and new.state != "match":
            changes.append(("exact-lost", f"match -> {new.state}"))
        if new.unresolved > old.unresolved:
            changes.append(("unresolved-increased", f"{old.unresolved} -> {new.unresolved}"))
        if new.mismatches > old.mismatches:
            changes.append(("mismatches-increased", f"{old.mismatches} -> {new.mismatches}"))
        if old.body_byte_exact is True and new.body_byte_exact is not True:
            changes.append(("body-byte-exact-lost", "encoded body identity lost"))
        regressions.extend(Regression(before.image, old.address, check, detail) for check, detail in changes)
        if old != new:
            deltas.append(MatchDelta(before.image, old.address, new.function, old, new))
    return regressions, deltas


def apply_waivers(
    regressions: list[Regression],
    payload: dict[str, Any],
    *,
    base_commit: str,
) -> list[Regression]:
    from dataclasses import replace

    if payload["schema"] != 1 or payload["base_commit"] != base_commit:
        raise ValueError("regression waivers must name this exact base commit (schema 1)")
    waivers: dict[tuple[str, int | None, str], str] = {}
    for row in payload["waivers"]:
        address = row["address"]
        if address is not None and (type(address) is not int or address < 0):
            raise ValueError("waiver address must be a non-negative integer or null")
        reason = row["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("every regression waiver needs a reason")
        key = (row["image"], address, row["check"])
        if key in waivers:
            raise ValueError(f"duplicate regression waiver: {key}")
        waivers[key] = reason.strip()
    result = [replace(row, waiver=waivers.pop((row.image, row.address, row.check), None)) for row in regressions]
    if waivers:
        raise ValueError(f"unused regression waivers: {list(waivers)}")
    return result


def check_revision(
    base: str,
    *,
    repo_root: Path,
    git: str,
    images: tuple[str, ...],
    waivers: Path | None = None,
) -> dict[str, Any]:
    base_commit = subprocess.run(
        [git, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    regressions: list[Regression] = []
    deltas: list[MatchDelta] = []
    for image in images:
        relative = Path("analysis/native") / image / "objects.json"
        previous = subprocess.run(
            [git, "show", f"{base_commit}:{relative.as_posix()}"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        before = parse_manifest(json.loads(previous))
        after = parse_manifest(json.loads((repo_root / relative).read_text()))
        if before.image != image or after.image != image:
            raise ValueError(f"{relative}: unexpected image identity")
        found, changed = compare_manifests(before, after)
        regressions.extend(found)
        deltas.extend(changed)
    if waivers is None:
        saved = repo_root / "tools/match/regression-waivers.json"
        if saved.exists():
            payload = json.loads(saved.read_text())
            if payload["base_commit"] == base_commit:
                waivers = saved
    if waivers is not None:
        regressions = apply_waivers(regressions, json.loads(waivers.read_text()), base_commit=base_commit)
    return {
        "base_commit": base_commit,
        "regressions": [asdict(row) for row in regressions],
        "deltas": [asdict(row) for row in deltas],
        "errors": sum(row.waiver is None for row in regressions),
    }
