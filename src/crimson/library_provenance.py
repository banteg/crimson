from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import match as matchlib

DEFAULT_PROVENANCE_PATH = matchlib.REPO_ROOT / "analysis" / "library_provenance.json"


@dataclass(frozen=True, slots=True)
class ProvenanceCheck:
    artifact: str
    component: str
    kind: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class ProvenanceReport:
    checks: tuple[ProvenanceCheck, ...]

    @property
    def ok(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failed(self) -> tuple[ProvenanceCheck, ...]:
        return tuple(check for check in self.checks if not check.passed)


@dataclass(slots=True)
class _LoadedArtifact:
    artifact_id: str
    path: Path
    data: bytes
    pe: Any
    mapped: bytes

    @property
    def image_base(self) -> int:
        return int(self.pe.OPTIONAL_HEADER.ImageBase)

    @property
    def image_end(self) -> int:
        return self.image_base + int(self.pe.OPTIONAL_HEADER.SizeOfImage)


def load_library_provenance(path: Path = DEFAULT_PROVENANCE_PATH) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != 1:
        raise ValueError(f"{path}: unsupported library provenance schema")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError(f"{path}: artifacts must be a non-empty list")
    artifact_ids = [str(artifact.get("id", "")) for artifact in artifacts]
    if any(not artifact_id for artifact_id in artifact_ids):
        raise ValueError(f"{path}: every artifact requires an id")
    if len(artifact_ids) != len(set(artifact_ids)):
        raise ValueError(f"{path}: duplicate artifact id")
    return payload


def _load_pe(path: Path) -> tuple[Any, bytes]:
    try:
        import pefile
    except ModuleNotFoundError as exc:
        raise RuntimeError("pefile is required for provenance checks; run `uv sync --dev`") from exc

    pe = pefile.PE(data=path.read_bytes(), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]],
    )
    return pe, pe.get_memory_mapped_image()


def _artifact_path(repo_root: Path, relative_path: str) -> Path:
    path = (repo_root / relative_path).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise ValueError(f"artifact path escapes repository: {relative_path}") from exc
    return path


def _normalize_module(name: str) -> str:
    normalized = Path(name.replace("\\", "/")).name.lower()
    return normalized.removesuffix(".dll")


def _pe_imports(artifact: _LoadedArtifact) -> dict[str, frozenset[str]]:
    imports: dict[str, set[str]] = defaultdict(set)
    for descriptor in getattr(artifact.pe, "DIRECTORY_ENTRY_IMPORT", ()):
        module = _normalize_module(descriptor.dll.decode("latin1"))
        for entry in descriptor.imports:
            if entry.name is not None:
                imports[module].add(entry.name.decode("latin1"))
            else:
                imports[module].add(f"ordinal:{entry.ordinal}")
    return {module: frozenset(symbols) for module, symbols in imports.items()}


def _expected_fingerprint_bytes(fingerprint: dict[str, Any]) -> bytes:
    encoding = str(fingerprint.get("encoding", "ascii"))
    value = str(fingerprint["value"])
    if encoding == "ascii":
        return value.encode("ascii")
    if encoding == "hex":
        return bytes.fromhex(value)
    raise ValueError(f"unsupported fingerprint encoding {encoding!r}")


def _fingerprint_offset(artifact: _LoadedArtifact, fingerprint: dict[str, Any]) -> tuple[int, str]:
    if "address" in fingerprint:
        address = matchlib.parse_int(fingerprint["address"])
        return address - artifact.image_base, f"VA 0x{address:08x}"
    if "file_offset" in fingerprint:
        offset = matchlib.parse_int(fingerprint["file_offset"])
        return offset, f"file+0x{offset:x}"
    raise ValueError("fingerprint requires address or file_offset")


def _check_artifact(
    artifact_row: dict[str, Any],
    *,
    repo_root: Path,
) -> tuple[_LoadedArtifact | None, list[ProvenanceCheck]]:
    artifact_id = str(artifact_row["id"])
    path = _artifact_path(repo_root, str(artifact_row["path"]))
    checks: list[ProvenanceCheck] = []
    if not path.is_file():
        checks.append(
            ProvenanceCheck(
                artifact=artifact_id,
                component="artifact",
                kind="exists",
                passed=False,
                detail=f"missing {path}",
            ),
        )
        return None, checks

    data = path.read_bytes()
    expected_size = int(artifact_row["size"])
    checks.append(
        ProvenanceCheck(
            artifact=artifact_id,
            component="artifact",
            kind="size",
            passed=len(data) == expected_size,
            detail=f"expected={expected_size} actual={len(data)}",
        ),
    )
    expected_sha256 = str(artifact_row["sha256"]).lower()
    actual_sha256 = hashlib.sha256(data).hexdigest()
    checks.append(
        ProvenanceCheck(
            artifact=artifact_id,
            component="artifact",
            kind="sha256",
            passed=actual_sha256 == expected_sha256,
            detail=f"expected={expected_sha256} actual={actual_sha256}",
        ),
    )
    try:
        pe, mapped = _load_pe(path)
    except Exception as exc:
        checks.append(
            ProvenanceCheck(
                artifact=artifact_id,
                component="artifact",
                kind="pe",
                passed=False,
                detail=str(exc),
            ),
        )
        return None, checks
    return _LoadedArtifact(artifact_id, path, data, pe, mapped), checks


def _check_component(
    artifact: _LoadedArtifact,
    component: dict[str, Any],
) -> list[ProvenanceCheck]:
    component_id = str(component["id"])
    checks: list[ProvenanceCheck] = []
    imports = _pe_imports(artifact)

    for range_row in component.get("ranges", []):
        start = matchlib.parse_int(range_row["start"])
        end = matchlib.parse_int(range_row["end"])
        passed = artifact.image_base <= start < end <= artifact.image_end
        checks.append(
            ProvenanceCheck(
                artifact=artifact.artifact_id,
                component=component_id,
                kind="range",
                passed=passed,
                detail=f"0x{start:08x}..0x{end:08x} ({end - start} bytes)",
            ),
        )

    for fingerprint in component.get("fingerprints", []):
        expected = _expected_fingerprint_bytes(fingerprint)
        offset, location = _fingerprint_offset(artifact, fingerprint)
        source = artifact.mapped if "address" in fingerprint else artifact.data
        actual = source[offset : offset + len(expected)] if offset >= 0 else b""
        checks.append(
            ProvenanceCheck(
                artifact=artifact.artifact_id,
                component=component_id,
                kind="fingerprint",
                passed=actual == expected,
                detail=f"{location} expected={expected!r} actual={actual!r}",
            ),
        )

    for import_row in component.get("imports", []):
        module = _normalize_module(str(import_row["module"]))
        expected_symbols = frozenset(map(str, import_row.get("symbols", [])))
        actual_symbols = imports.get(module, frozenset())
        missing = sorted(expected_symbols - actual_symbols)
        checks.append(
            ProvenanceCheck(
                artifact=artifact.artifact_id,
                component=component_id,
                kind="import",
                passed=module in imports and not missing,
                detail=(
                    f"module={module} symbols={','.join(sorted(expected_symbols)) or '-'}"
                    + (f" missing={','.join(missing)}" if missing else "")
                ),
            ),
        )
    return checks


def _normalized_endpoint(
    artifact: _LoadedArtifact,
    endpoint: dict[str, Any],
) -> tuple[str, ...]:
    start = matchlib.parse_int(endpoint["start"])
    end = matchlib.parse_int(endpoint["end"])
    data = artifact.mapped[start - artifact.image_base : end - artifact.image_base]
    return matchlib.normalize_function(
        data,
        address_range=(artifact.image_base, artifact.image_end),
        base_address=start,
    )


def _check_cross_image_match(
    match_row: dict[str, Any],
    artifacts: dict[str, _LoadedArtifact],
) -> ProvenanceCheck:
    component = str(match_row["component"])
    left_row = match_row["left"]
    right_row = match_row["right"]
    left_id = str(left_row["artifact"])
    right_id = str(right_row["artifact"])
    try:
        left = artifacts[left_id]
        right = artifacts[right_id]
    except KeyError as exc:
        return ProvenanceCheck(
            artifact=f"{left_id}<->{right_id}",
            component=component,
            kind="cross-image",
            passed=False,
            detail=f"artifact unavailable: {exc.args[0]}",
        )
    left_lines = _normalized_endpoint(left, left_row)
    right_lines = _normalized_endpoint(right, right_row)
    left_name = str(left_row.get("name", left_row["start"]))
    right_name = str(right_row.get("name", right_row["start"]))
    return ProvenanceCheck(
        artifact=f"{left_id}<->{right_id}",
        component=component,
        kind="cross-image",
        passed=left_lines == right_lines and bool(left_lines),
        detail=f"{left_name}<->{right_name} instructions={len(left_lines)}/{len(right_lines)}",
    )


def validate_library_provenance(
    path: Path = DEFAULT_PROVENANCE_PATH,
    *,
    repo_root: Path = matchlib.REPO_ROOT,
) -> ProvenanceReport:
    payload = load_library_provenance(path)
    checks: list[ProvenanceCheck] = []
    loaded: dict[str, _LoadedArtifact] = {}
    for artifact_row in payload["artifacts"]:
        artifact, artifact_checks = _check_artifact(artifact_row, repo_root=repo_root)
        checks.extend(artifact_checks)
        if artifact is None:
            continue
        loaded[artifact.artifact_id] = artifact
        for component in artifact_row.get("components", []):
            checks.extend(_check_component(artifact, component))

    for match_row in payload.get("cross_image_matches", []):
        checks.append(_check_cross_image_match(match_row, loaded))
    return ProvenanceReport(tuple(checks))


def provenance_report_payload(report: ProvenanceReport) -> dict[str, Any]:
    return {
        "ok": report.ok,
        "summary": {
            "checks": len(report.checks),
            "passed": len(report.checks) - len(report.failed),
            "failed": len(report.failed),
        },
        "checks": [
            {
                "artifact": check.artifact,
                "component": check.component,
                "kind": check.kind,
                "passed": check.passed,
                "detail": check.detail,
            }
            for check in report.checks
        ],
    }


def render_provenance_report(report: ProvenanceReport) -> str:
    state = "ok" if report.ok else "failed"
    lines = [f"provenance={state} checks={len(report.checks)} failed={len(report.failed)}"]
    grouped: dict[tuple[str, str], list[ProvenanceCheck]] = defaultdict(list)
    for check in report.checks:
        grouped[(check.artifact, check.component)].append(check)
    for (artifact, component), checks in grouped.items():
        failures = [check for check in checks if not check.passed]
        component_state = "ok" if not failures else "failed"
        lines.append(f"{artifact}:{component} {component_state} checks={len(checks)}")
        for check in failures:
            lines.append(f"  {check.kind}: {check.detail}")
    return "\n".join(lines)
