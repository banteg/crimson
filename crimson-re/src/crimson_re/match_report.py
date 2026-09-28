"""Publish full-image matching evidence in decomp.dev's objdiff v2 format.

Refresh on a machine with the pinned matching toolchain. CI checks the saved
evidence against its inputs and emits the report without distributing compilers.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import re
import shutil
import subprocess
import sys
import tomllib
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Any

from . import match as matchlib
from . import match_builds, match_data_report, match_toolchain
from . import match_report_accounting as accounting

# The canonical build: curated inventory, data evidence and the ownership ranges every build reuses.
VERSION = "1.9.93"
DEFAULT_REPORTS = matchlib.REPO_ROOT / "artifacts" / "decomp"
BUILD_MAP_RE = re.compile(r"analysis/decomp/[^/]+/[^/]+/(?:functions|data|imports|metadata)\.json")


def evidence_path(version: str) -> Path:
    return matchlib.REPO_ROOT / "analysis" / "decomp" / f"{version}.json"


def _input_path(path: str) -> bool:
    """Pin relevant code/config, including newly staged or removed scratches."""
    p = Path(path)
    if path in {"analysis/library_provenance.json", "analysis/matching_scope.json", "crimson-re/src/crimson_re/native_link.py"}:
        return True
    if path.startswith("crimson-re/src/crimson_re/") and p.suffix == ".py":
        return p.stem.startswith(("match", "library"))
    if path.startswith(("tools/match/", "tools/native/", "third_party/", "decomp/")):
        return p.suffix in {".c", ".cpp", ".cc", ".h", ".hpp", ".inc", ".conf", ".sh", ".py"} or (
            path.startswith(("tools/native/", "decomp/")) and p.suffix == ".json"
        )
    return path.startswith("analysis/ghidra/maps/") or BUILD_MAP_RE.fullmatch(path) is not None or (
        path.startswith("analysis/ida/raw/") and p.name in {"functions.json", "metadata.json", "imports.json"}
    )


def _git_input_paths(root: Path, *selection: str) -> list[str]:
    git = shutil.which("git")
    if git is None:
        raise ValueError("git not found")
    result = subprocess.run([git, "ls-files", *selection, "-z"], cwd=root, capture_output=True, check=True)
    return sorted({p for p in result.stdout.decode().split("\0") if p and _input_path(p)})


def repository_inputs(root: Path = matchlib.REPO_ROOT) -> dict[str, str]:
    """Hash tracked inputs only, so another checkout user's uncommitted files never enter the evidence.

    Python inputs hash by syntax tree, so formatting, comments and docstrings do not
    invalidate evidence. Instead of the whole lockfile, only the locked versions of the
    libraries those inputs import (and their dependencies) are pinned.
    """
    paths = _git_input_paths(root, "--cached")
    inputs = {p: _python_digest(root / p) if p.endswith(".py") else _required_hash(root / p) for p in paths}
    inputs[accounting.SCORING_DEPENDENCIES_INPUT] = _scoring_dependencies_digest(
        root, [root / p for p in paths if p.endswith(".py")],
    )
    return inputs


def _python_digest(path: Path) -> str:
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                node.body = node.body[1:] or [ast.Pass()]
    return hashlib.sha256(ast.dump(tree).encode()).hexdigest()


def _distribution_key(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def _scoring_dependencies_digest(root: Path, python_inputs: list[Path]) -> str:
    imported: set[str] = set()
    for path in python_inputs:
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])
    packages: dict[str, list[dict[str, Any]]] = {}
    for package in tomllib.loads((root / "uv.lock").read_text()).get("package", ()):
        packages.setdefault(_distribution_key(package["name"]), []).append(package)
    pending = [_distribution_key(name) for name in imported - set(sys.stdlib_module_names)]
    pinned: dict[str, list[str]] = {}
    while pending:
        key = pending.pop()
        if key in pinned or key not in packages:
            continue
        pinned[key] = sorted(str(package.get("version", package.get("source"))) for package in packages[key])
        pending.extend(
            _distribution_key(dependency["name"])
            for package in packages[key]
            for dependency in package.get("dependencies", ())
        )
    return hashlib.sha256(json.dumps(pinned, sort_keys=True).encode()).hexdigest()


def untracked_inputs(root: Path = matchlib.REPO_ROOT) -> list[str]:
    return _git_input_paths(root, "--others", "--exclude-standard")


def _required_hash(path: Path) -> str:
    digest = match_toolchain.file_sha256(path)
    if digest is None:
        raise ValueError(f"missing report input: {path}")
    return digest


def _images(version: str) -> list[match_builds.BuildImage]:
    return [match_builds.load_registry().image(version, name) for name in matchlib.TRACKED_IMAGE_NAMES]


def _inventory(version: str = VERSION) -> list[dict[str, Any]]:
    """The version's function inventory: the curated one, or another build's map of it."""
    rows: list[dict[str, Any]] = []
    for build_image in _images(version):
        target = build_image.target
        manifest = matchlib.load_function_manifest(
            target.functions_path,
            metadata_path=target.metadata_path,
            image_name=target.image_name,
            scope="all",
        )
        image = matchlib.load_image(target.image_path, manifest.image_base)
        canonical = {} if build_image.is_canonical else {
            matchlib.parse_int(row["address"]): matchlib.parse_int(row["canonical_address"])
            for row in json.loads(target.functions_path.read_text(encoding="utf-8"))
        }
        for function in manifest.functions:
            row = {
                "image": build_image.name,
                "address": function.address,
                "name": function.name,
                "size": len(image.function_bytes(function.address, function.end)),
            }
            if canonical:
                row["canonical_address"] = canonical[function.address]
            rows.append(row)
    return rows


def _external_inputs(
    configs: list[matchlib.ScratchConfig], tracked: dict[str, str], version: str = VERSION,
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
    for build_image in _images(version):
        path = build_image.target.image_path
        files[path.relative_to(matchlib.REPO_ROOT).as_posix()] = _required_hash(path)
    return dict(sorted(files.items())), toolchains


def _image_paths(version: str) -> dict[str, Path]:
    return {build_image.name: build_image.target.image_path for build_image in _images(version)}


def _score(inventory: list[dict[str, Any]], statuses: list[matchlib.ScratchStatus]) -> None:
    """Attach each function's candidate evidence to its inventory row."""
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
        row.update(accounting.candidate_evidence(status))
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
                "matched": accounting.normalized_exact(row, ratio=status.ratio),
            },
        )


def refresh_evidence(version: str = VERSION, *, jobs: int = matchlib.DEFAULT_MATCH_JOBS) -> dict[str, Any]:
    """Score every function of ``version``; another build compiles each mapped scratch as that build."""
    if untracked := untracked_inputs():
        raise ValueError(
            "untracked report inputs would be evaluated but not pinned; stage or remove these files: "
            + ", ".join(untracked[:8]),
        )
    before = repository_inputs()
    inventory = _inventory(version)
    if version == VERSION:
        configs = [
            matchlib.load_scratch_config(p.parent)
            for p in sorted(matchlib.DEFAULT_MATCH_ROOT.glob("scratches/*/scratch.conf"))
        ]
        statuses = matchlib.collect_scratch_statuses(scope="all", jobs=jobs)
        if errors := [s for s in statuses if s.error]:
            raise ValueError("matching failed: " + "; ".join(f"{s.config.function}: {s.error}" for s in errors))
    else:
        # A canonical source that another build's compiler rejects leaves that function without a candidate.
        statuses = [
            row.status
            for row in match_builds.scan_build(match_builds.load_registry(), version, jobs=jobs)
            if row.status.error is None
        ]
        configs = [status.config for status in statuses]
    external, toolchains = _external_inputs(configs, before, version)
    _score(inventory, statuses)
    data = match_data_report.refresh_evidence(configs) if version == VERSION else None
    if repository_inputs() != before or _external_inputs(configs, before, version) != (external, toolchains):
        raise ValueError("report inputs changed during evaluation; refresh again")
    return {
        "schema": 3,
        "verification": accounting.VERIFICATION,
        "identities": accounting.identities(inventory, before, external, toolchains),
        "code_inventory": accounting.code_inventory(inventory, _image_paths(version)),
        "version": version,
        "scope": "all",
        "inputs": before,
        "external_inputs": dict(sorted(external.items())),
        "toolchains": toolchains,
        "functions": inventory,
        "data": data,
    }


def validate_evidence(evidence: dict[str, Any]) -> None:
    version = evidence.get("version")
    if (
        evidence.get("schema") != 3
        or version not in match_builds.load_registry().reported
        or evidence.get("scope") != "all"
    ):
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
    for profile, toolchain in evidence["toolchains"].items():
        # Another build compiles a scratch with its own profile, so resolve the recorded one.
        config = replace(matchlib.load_scratch_config((matchlib.REPO_ROOT / toolchain["config"]).parent), compiler=profile)
        compiler = matchlib._compiler_executable_path(config, matchlib.DEFAULT_MATCH_ROOT)
        if (
            compiler.is_file()
            and match_toolchain.scratch_toolchain_fingerprint(compiler, matchlib.DEFAULT_MATCH_ROOT)
            != toolchain["fingerprint"]
        ):
            raise ValueError(f"report toolchain changed: {compiler}")
    expected = _inventory(version)
    if len(evidence["functions"]) != len(expected):
        raise ValueError("report denominator differs from the full function inventory")
    inventory = [
        {key: row[key] for key in expected_row}
        for row, expected_row in zip(evidence["functions"], expected, strict=True)
    ]
    if inventory != expected:
        raise ValueError("report denominator differs from the full function inventory")
    for row in evidence["functions"]:
        accounting.validate_function(row)
    if evidence["verification"] != accounting.VERIFICATION:
        raise ValueError("unsupported evidence verification mode")
    if evidence["identities"] != accounting.identities(inventory, recorded, evidence["external_inputs"], evidence["toolchains"]):
        raise ValueError("report measurement identities differ")
    if evidence["code_inventory"] != accounting.code_inventory(inventory, _image_paths(version)):
        raise ValueError("executable inventory reconciliation differs")
    if version == VERSION:
        match_data_report.validate_evidence(evidence["data"])
    elif evidence["data"] is not None:
        raise ValueError("data evidence covers the canonical build only")


def _category_definitions() -> tuple[dict[str, str], list[tuple[str, int, int, str]]]:
    labels = {"game": "Game & Engine", "exe": "Crimsonland EXE", "dll": "Grim2D DLL", "libs": "Libraries",
              "unknown": "Unclassified ownership"}
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
        total_data=sum(int(m.get("total_data", 0)) for m in measures),
        matched_data=sum(int(m.get("matched_data", 0)) for m in measures),
    )


def build_report(functions: list[dict[str, Any]], *, data: dict[str, Any] | None = None) -> dict[str, Any]:
    """One function per unit, with overlapping image and proven library filters."""
    labels, library_ranges = _category_definitions()
    if data is not None and "ownership" in data:
        labels.update({"game.data": "Game & Engine + attributed data",
                       "libs.data": "Libraries + attributed data",
                       "data_unknown": "Unattributed data"})
    ownership = matchlib._load_matching_scope_definition("port")
    third_party = {
        (image, disposition.address)
        for image, dispositions in ownership.function_dispositions.items()
        for disposition in dispositions if disposition.disposition == "third-party"
    }
    labels["libs.other"] = "Other identified libraries"
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
        # Ownership is defined on the canonical image; another build's row carries its canonical address.
        owner_key = row["image"], row.get("canonical_address", row["address"])
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
        name = row["name"] if names[row["name"]] == 1 else f"{row['name']}@{accounting.native_id(row)}"
        metadata: dict[str, Any] = {"complete": is_complete}
        categories = [{"crimsonland.exe": "exe", "grim.dll": "dll"}[row["image"]]]
        libraries = sorted({
            category for image, start, end, category in library_ranges
            if image == row["image"] and start <= owner_key[1] < end
        })
        if owner_key in third_party and not libraries:
            libraries.append("libs.other")
        if not libraries and any(region.contains(owner_key[1]) for region in ownership.ranges[row["image"]]):
            categories.append("game")
        if libraries:
            categories.extend(["libs", *libraries])
        if "game" not in categories and "libs" not in categories:
            categories.append("unknown")
        if data is not None and "ownership" in data:
            if "game" in categories:
                categories.append("game.data")
            if "libs" in categories:
                categories.append("libs.data")
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
                        "name": accounting.native_id(row),
                        "size": str(size),
                        "fuzzy_match_percent": percent,
                        "metadata": {"virtual_address": str(row["address"]), "demangled_name": row["name"]},
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
    data_total = data_matched = 0
    for span in match_data_report.report_spans(data) if data is not None else []:
        size = span["size"]
        matched_size = size if span["matched"] else 0
        metadata = {
            "complete": False,
            "progress_categories": [{"crimsonland.exe": "exe", "grim.dll": "dll"}[span["image"]]],
        }
        if data is not None and "ownership" in data:
            metadata["progress_categories"].append(
                {"game": "game.data", "libraries": "libs.data", "unknown": "data_unknown"}[span["owner"]])
        if span["source"]:
            metadata["source_path"] = span["source"]
        units.append({
            "name": f"{span['image']}/data/{span['section']}/{span['name']}@{span['address']:08x}",
            "measures": _measures(0, 0, 0, 0.0, 0, 0, 1, 0, total_data=size, matched_data=matched_size),
            "sections": [{
                "name": span["section"], "size": str(size),
                "fuzzy_match_percent": 100.0 if span["matched"] else 0.0,
                "metadata": {"virtual_address": str(span["address"])},
            }],
            "functions": [], "metadata": metadata,
        })
        data_total += size
        data_matched += matched_size
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
            total_data=data_total,
            matched_data=data_matched,
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
    *,
    total_data: int = 0,
    matched_data: int = 0,
) -> dict[str, Any]:
    measures = {
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
    if total_data:
        measures.update({
            "total_data": str(total_data), "matched_data": str(matched_data),
            "matched_data_percent": 100 * matched_data / total_data,
            "complete_data": "0", "complete_data_percent": 0.0,
        })
    return measures
