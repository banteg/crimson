"""Publish full-image matching evidence in decomp.dev's objdiff v2 format.

Refresh on a machine with the pinned matching toolchain. CI checks the saved
evidence against its inputs and emits the report without distributing compilers.
"""

from __future__ import annotations

import json
import math
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from . import match as matchlib
from . import match_toolchain

VERSION = "1.9.93"
DEFAULT_EVIDENCE = matchlib.REPO_ROOT / "analysis" / "decomp" / f"{VERSION}.json"
DEFAULT_REPORT = matchlib.REPO_ROOT / "artifacts" / "decomp" / "report.json"


def _input_path(path: str) -> bool:
    """Pin relevant code/config, including newly added or removed scratches."""
    p = Path(path)
    if path in {"pyproject.toml", "uv.lock", "analysis/library_provenance.json"}:
        return True
    if path.startswith("src/crimson/") and p.suffix == ".py":
        return p.stem.startswith(("match", "library"))
    if path.startswith(("tools/match/", "tools/native/", "third_party/")):
        return p.suffix in {".c", ".cpp", ".cc", ".h", ".hpp", ".inc", ".conf", ".sh", ".py"} or (
            path.startswith("tools/native/") and p.suffix == ".json"
        )
    return path.startswith("analysis/ghidra/maps/") or (
        path.startswith("analysis/ida/raw/") and p.name in {"functions.json", "metadata.json", "imports.json"}
    )


def repository_inputs(root: Path = matchlib.REPO_ROOT) -> dict[str, str]:
    git = shutil.which("git")
    if git is None:
        raise ValueError("git not found")
    result = subprocess.run(
        [git, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    paths = sorted({p for p in result.stdout.decode().split("\0") if p and _input_path(p)})
    return {p: _required_hash(root / p) for p in paths}


def _required_hash(path: Path) -> str:
    digest = match_toolchain.file_sha256(path)
    if digest is None:
        raise ValueError(f"missing report input: {path}")
    return digest


def _inventory() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for image_name in matchlib.TRACKED_IMAGE_NAMES:
        image_path, functions_path, metadata_path = matchlib._paths_for_image(image_name)
        manifest = matchlib.load_function_manifest(
            functions_path,
            metadata_path=metadata_path,
            image_name=image_name,
            scope="all",
        )
        image = matchlib.load_image(image_path, manifest.image_base)
        for function in manifest.functions:
            rows.append(
                {
                    "image": image_name,
                    "address": function.address,
                    "name": function.name,
                    "size": len(image.function_bytes(function.address, function.end)),
                },
            )
    return rows


def _external_inputs(
    configs: list[matchlib.ScratchConfig], tracked: dict[str, str],
) -> tuple[dict[str, str], dict[str, Any]]:
    files: dict[str, str] = {}
    toolchains: dict[str, Any] = {}
    resolver = matchlib._ScratchIncludeResolver(matchlib.DEFAULT_MATCH_ROOT)
    for config in configs:
        compiler = (
            matchlib._compiler_executable_path(config, matchlib.DEFAULT_MATCH_ROOT)
            if config.archive is None and config.import_thunk is None else None
        )
        for path in matchlib._scratch_build_dependencies(
            config, matchlib.DEFAULT_MATCH_ROOT, include_resolver=resolver,
        ):
            path = path.resolve()
            # Compiler trees have their own location-independent fingerprint;
            # the resolver may find them in a sibling checkout or an env path.
            if compiler is not None and path.is_relative_to(compiler.parent.parent.resolve()):
                continue
            relative = path.relative_to(matchlib.REPO_ROOT).as_posix()
            if relative not in tracked:
                files[relative] = _required_hash(path)
        if compiler is not None and config.compiler not in toolchains:
            toolchains[config.compiler] = {
                "config": (config.directory / "scratch.conf").relative_to(matchlib.REPO_ROOT).as_posix(),
                "fingerprint": match_toolchain.scratch_toolchain_fingerprint(compiler, matchlib.DEFAULT_MATCH_ROOT),
            }
    for image_name in matchlib.TRACKED_IMAGE_NAMES:
        path = matchlib._paths_for_image(image_name)[0]
        files[path.relative_to(matchlib.REPO_ROOT).as_posix()] = _required_hash(path)
    return dict(sorted(files.items())), toolchains


def refresh_evidence(*, jobs: int = matchlib.DEFAULT_MATCH_JOBS) -> dict[str, Any]:
    before = repository_inputs()
    configs = [
        matchlib.load_scratch_config(p.parent)
        for p in sorted(matchlib.DEFAULT_MATCH_ROOT.glob("scratches/*/scratch.conf"))
    ]
    external, toolchains = _external_inputs(configs, before)
    inventory = _inventory()
    statuses = matchlib.collect_scratch_statuses(scope="all", jobs=jobs)
    errors = [s for s in statuses if s.error]
    if errors:
        raise ValueError("matching failed: " + "; ".join(f"{s.config.function}: {s.error}" for s in errors))
    selected: dict[tuple[str, int], matchlib.ScratchStatus] = {}
    for status in statuses:
        key = status.config.image, status.address
        if key in selected:
            raise ValueError(f"duplicate report candidate: {key}")
        selected[key] = status
    inventory_keys = {(row["image"], row["address"]) for row in inventory}
    if selected.keys() - inventory_keys:
        raise ValueError("report candidates are absent from the full function inventory")
    for row in inventory:
        status = selected.get((row["image"], row["address"]))
        row.update({"candidate": None, "source": None, "ratio": 0.0, "matched": False, "linked": False})
        if status is None:
            continue
        if status.target_size < row["size"]:
            raise ValueError(f"partial function extent in report: {row['name']}")
        config = status.config
        kind = "archive" if config.archive else "import-thunk" if config.import_thunk else "source"
        source = (
            None
            if kind != "source"
            else (config.directory / config.source).resolve().relative_to(matchlib.REPO_ROOT).as_posix()
        )
        row.update(
            {
                "candidate": kind,
                "source": source,
                "ratio": status.ratio,
                "matched": status.state == "match",
            },
        )
    if repository_inputs() != before or _external_inputs(configs, before) != (external, toolchains):
        raise ValueError("report inputs changed during evaluation; refresh again")
    return {
        "schema": 1,
        "version": VERSION,
        "scope": "all",
        "inputs": before,
        "external_inputs": dict(sorted(external.items())),
        "toolchains": toolchains,
        "functions": inventory,
    }


def validate_evidence(evidence: dict[str, Any]) -> None:
    if evidence.get("schema") != 1 or evidence.get("version") != VERSION or evidence.get("scope") != "all":
        raise ValueError("unsupported decomp.dev evidence")
    current = repository_inputs()
    recorded = evidence["inputs"]
    changed = sorted(p for p in current.keys() | recorded.keys() if current.get(p) != recorded.get(p))
    if changed:
        raise ValueError("stale decomp.dev evidence; run `crimson match report --refresh`: " + ", ".join(changed[:8]))
    for path, digest in evidence["external_inputs"].items():
        actual = match_toolchain.file_sha256(matchlib.REPO_ROOT / path)
        # CI requires the reference images; ignored compilers and archives may
        # be absent. If present, none may drift from the recorded build.
        if (actual is not None or path.startswith("game_bins/")) and actual != digest:
            raise ValueError(f"report artifact changed or missing: {path}")
    for toolchain in evidence["toolchains"].values():
        config = matchlib.load_scratch_config((matchlib.REPO_ROOT / toolchain["config"]).parent)
        compiler = matchlib._compiler_executable_path(config, matchlib.DEFAULT_MATCH_ROOT)
        if (
            compiler.is_file()
            and match_toolchain.scratch_toolchain_fingerprint(compiler, matchlib.DEFAULT_MATCH_ROOT)
            != toolchain["fingerprint"]
        ):
            raise ValueError(f"report toolchain changed: {compiler}")
    inventory = [{k: row[k] for k in ("image", "address", "name", "size")} for row in evidence["functions"]]
    if inventory != _inventory():
        raise ValueError("report denominator differs from the full function inventory")


def _category_definitions() -> tuple[dict[str, str], list[tuple[str, int, int, str]]]:
    labels = {"exe": "Crimsonland EXE", "dll": "Grim2D DLL", "libs": "Libraries"}
    library_labels = {"d3dx8": "D3DX8", "msvc6-crt": "MSVC6 runtime"}
    provenance = json.loads((matchlib.REPO_ROOT / "analysis/library_provenance.json").read_text())
    ranges = []
    for artifact in provenance["artifacts"]:
        if artifact["id"] not in matchlib.TRACKED_IMAGE_NAMES:
            continue
        for component in artifact.get("components", []):
            for region in component.get("ranges", []):
                category = f"libs.{component['id']}"
                labels[category] = library_labels.get(component["id"], component["id"])
                ranges.append((artifact["id"], int(region["start"], 0), int(region["end"], 0), category))
    return labels, ranges


def _sum_measures(measures: list[dict[str, Any]]) -> dict[str, Any]:
    total = sum(int(m["total_code"]) for m in measures)
    return _measures(
        total,
        sum(int(m["matched_code"]) for m in measures),
        sum(int(m["complete_code"]) for m in measures),
        sum(int(m["total_code"]) * m["fuzzy_match_percent"] for m in measures) / total if total else 0.0,
        sum(m["total_functions"] for m in measures),
        sum(m["matched_functions"] for m in measures),
        sum(m["total_units"] for m in measures),
        sum(m["complete_units"] for m in measures),
    )


def build_report(functions: list[dict[str, Any]]) -> dict[str, Any]:
    """One function per unit, with overlapping image and proven library filters."""
    labels, library_ranges = _category_definitions()
    names = Counter(row["name"] for row in functions)
    seen: set[tuple[str, int]] = set()
    units: list[dict[str, Any]] = []
    total = matched = complete = matched_functions = complete_units = 0
    fuzzy = 0.0
    for row in functions:
        key = row["image"], row["address"]
        if key in seen:
            raise ValueError(f"duplicate report function: {key}")
        seen.add(key)
        size, ratio = row["size"], row["ratio"]
        if type(size) is not int or size < 0 or not math.isfinite(ratio) or not 0 <= ratio <= 1:
            raise ValueError(f"invalid matching measures: {key}")
        if row["matched"] and ratio != 1:
            raise ValueError(f"matched function has a partial score: {key}")
        if row["linked"]:
            raise ValueError("linked credit is not established by the structural linker")
        eligible = row["candidate"] == "source"
        is_matched = eligible and row["matched"]
        is_complete = eligible and row["linked"]
        # objdiff's treemap paints 100% green. An unresolved-reference 100%
        # instruction score must remain visibly partial, like our `audit` state.
        percent = (100.0 if is_matched else min(ratio * 100, 99.99)) if eligible else 0.0
        measures = _measures(
            size,
            size if is_matched else 0,
            size if is_complete else 0,
            percent,
            1,
            int(is_matched),
            1,
            int(is_complete),
        )
        name = row["name"] if names[row["name"]] == 1 else f"{row['name']}@{row['address']:08x}"
        metadata: dict[str, Any] = {"complete": is_complete}
        categories = [{"crimsonland.exe": "exe", "grim.dll": "dll"}[row["image"]]]
        libraries = sorted({
            category for image, start, end, category in library_ranges
            if image == row["image"] and start <= row["address"] < end
        })
        if libraries:
            categories.extend(["libs", *libraries])
        metadata["progress_categories"] = categories
        if row["source"]:
            metadata["source_path"] = row["source"]
        if row["candidate"] in {"archive", "import-thunk"}:
            metadata["auto_generated"] = True
        units.append(
            {
                "name": name,
                "measures": measures,
                "functions": [
                    {
                        "name": row["name"],
                        "size": str(size),
                        "fuzzy_match_percent": percent,
                        "metadata": {"virtual_address": str(row["address"])},
                    },
                ],
                "metadata": metadata,
            },
        )
        total += size
        matched += size if is_matched else 0
        complete += size if is_complete else 0
        matched_functions += int(is_matched)
        complete_units += int(is_complete)
        fuzzy += size * percent
    return {
        "version": 2,
        "measures": _measures(
            total,
            matched,
            complete,
            fuzzy / total if total else 0.0,
            len(functions),
            matched_functions,
            len(units),
            complete_units,
        ),
        "units": units,
        "categories": [
            {
                "id": category,
                "name": label,
                "measures": _sum_measures([
                    unit["measures"] for unit in units if category in unit["metadata"]["progress_categories"]
                ]),
            }
            for category, label in labels.items()
        ],
    }


def _measures(
    total: int,
    matched: int,
    complete: int,
    fuzzy: float,
    functions: int,
    matched_functions: int,
    units: int,
    complete_units: int,
) -> dict[str, Any]:
    return {
        "total_code": str(total),
        "matched_code": str(matched),
        "complete_code": str(complete),
        "matched_code_percent": 100 * matched / total if total else 0.0,
        "complete_code_percent": 100 * complete / total if total else 0.0,
        "fuzzy_match_percent": fuzzy,
        "total_functions": functions,
        "matched_functions": matched_functions,
        "matched_functions_percent": 100 * matched_functions / functions if functions else 0.0,
        "total_units": units,
        "complete_units": complete_units,
    }
