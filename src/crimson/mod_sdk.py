from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

from . import match as matchlib

DEFAULT_MOD_SDK_MANIFEST = matchlib.REPO_ROOT / "analysis" / "mod_sdk_provenance.json"
MOD_SDK_ENV = "CRIMSON_MOD_SDK"


@dataclass(frozen=True, slots=True)
class ModSdkCheck:
    component: str
    kind: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class ModSdkReport:
    source: Path
    source_kind: str
    checks: tuple[ModSdkCheck, ...]
    release: str
    oracle_scope: tuple[str, ...]
    excluded_claims: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failed(self) -> tuple[ModSdkCheck, ...]:
        return tuple(check for check in self.checks if not check.passed)


def _relative_path(value: object, *, label: str) -> str:
    path = PurePosixPath(str(value))
    if not path.parts or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must be a package-relative path")
    return path.as_posix()


def _sha256(value: object, *, label: str) -> str:
    digest = str(value)
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def load_mod_sdk_manifest(path: Path = DEFAULT_MOD_SDK_MANIFEST) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != 1 or payload.get("kind") != "crimsonland-mod-sdk-provenance":
        raise ValueError(f"{path}: unsupported MOD SDK provenance manifest")
    package = payload.get("package")
    if not isinstance(package, dict):
        raise TypeError(f"{path}: package must be an object")
    package = cast(dict[str, Any], package)
    _relative_path(package.get("root"), label="package.root")
    archive = package.get("archive")
    if not isinstance(archive, dict):
        raise TypeError(f"{path}: package.archive must be an object")
    archive = cast(dict[str, Any], archive)
    _relative_path(archive.get("filename"), label="package.archive.filename")
    _sha256(archive.get("sha256"), label="package.archive.sha256")
    if not isinstance(archive.get("size"), int):
        raise TypeError(f"{path}: package.archive.size must be an integer")

    artifacts = package.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError(f"{path}: package.artifacts must be a non-empty array")
    artifact_paths: set[str] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise TypeError(f"{path}: package.artifacts[{index}] must be an object")
        artifact = cast(dict[str, Any], artifact)
        artifact_path = _relative_path(
            artifact.get("path"),
            label=f"package.artifacts[{index}].path",
        )
        if artifact_path in artifact_paths:
            raise ValueError(f"{path}: duplicate package artifact {artifact_path!r}")
        artifact_paths.add(artifact_path)
        _sha256(artifact.get("sha256"), label=f"package.artifacts[{index}].sha256")
        size = artifact.get("size")
        if not isinstance(size, int) or size < 0:
            raise TypeError(f"{path}: package.artifacts[{index}].size must be non-negative")

    projects = payload.get("projects")
    if not isinstance(projects, list) or not projects:
        raise ValueError(f"{path}: projects must be a non-empty array")
    project_names: set[str] = set()
    for index, project in enumerate(projects):
        if not isinstance(project, dict):
            raise TypeError(f"{path}: projects[{index}] must be an object")
        project = cast(dict[str, Any], project)
        name = str(project.get("name", ""))
        if not name or name in project_names:
            raise ValueError(f"{path}: every project requires a unique name")
        project_names.add(name)
        source_files = project.get("source_files")
        if not isinstance(source_files, list) or not all(isinstance(value, str) for value in source_files):
            raise TypeError(f"{path}: project {name!r} source_files must be strings")
        referenced_paths = {
            _relative_path(project.get("binary"), label=f"projects[{index}].binary"),
            _relative_path(project.get("source"), label=f"projects[{index}].source"),
            *(
                _relative_path(value, label=f"projects[{index}].source_files")
                for value in source_files
            ),
        }
        unknown = sorted(referenced_paths - artifact_paths)
        if unknown:
            raise ValueError(f"{path}: project {name!r} references unpinned artifacts {unknown}")
        compiler = project.get("compiler")
        if not isinstance(compiler, dict):
            raise TypeError(f"{path}: project {name!r} requires compiler metadata")
        compiler = cast(dict[str, Any], compiler)
        flags = compiler.get("flags")
        if not isinstance(flags, list) or not all(isinstance(value, str) for value in flags):
            raise TypeError(f"{path}: project {name!r} compiler.flags must be strings")
        defines = compiler.get("defines")
        if not isinstance(defines, list) or not all(isinstance(value, str) for value in defines):
            raise TypeError(f"{path}: project {name!r} compiler.defines must be strings")
        rich_records = project.get("rich_records")
        if not isinstance(rich_records, list):
            raise TypeError(f"{path}: project {name!r} rich_records must be an array")
        for record in rich_records:
            if not isinstance(record, dict) or not all(
                isinstance(record.get(key), int) for key in ("product_id", "build", "count")
            ):
                raise TypeError(f"{path}: project {name!r} has invalid Rich record")
        exports = project.get("exports")
        if not isinstance(exports, list) or not exports:
            raise ValueError(f"{path}: project {name!r} requires export calibrations")
        if any(not isinstance(row, dict) or not row.get("name") or not row.get("symbol") for row in exports):
            raise ValueError(f"{path}: project {name!r} has invalid export calibration")

    calibration = payload.get("calibration")
    if not isinstance(calibration, dict):
        raise TypeError(f"{path}: calibration must be an object")
    for key in ("oracle_scope", "excluded_claims"):
        if not isinstance(calibration.get(key), list) or not all(
            isinstance(value, str) and value for value in calibration[key]
        ):
            raise TypeError(f"{path}: calibration.{key} must be non-empty strings")
    return payload


class _PackageReader:
    def __init__(self, source: Path, package_root: str) -> None:
        self.source = source.resolve()
        self.package_root = package_root
        if self.source.is_dir():
            nested = self.source / package_root
            self.root = nested if nested.is_dir() else self.source
            self.kind = "directory"
        elif self.source.is_file() and zipfile.is_zipfile(self.source):
            self.root = None
            self.kind = "archive"
        else:
            raise FileNotFoundError(f"MOD SDK source is not a directory or ZIP archive: {source}")

    def read(self, relative_path: str) -> bytes:
        path = PurePosixPath(relative_path)
        if self.kind == "directory":
            assert self.root is not None
            candidate = (self.root / Path(*path.parts)).resolve()
            try:
                candidate.relative_to(self.root.resolve())
            except ValueError as exc:
                raise ValueError(f"package path escapes source root: {relative_path}") from exc
            return candidate.read_bytes()
        member = f"{self.package_root}/{path.as_posix()}"
        with zipfile.ZipFile(self.source) as archive:
            try:
                return archive.read(member)
            except KeyError as exc:
                raise FileNotFoundError(f"{self.source}: missing {member}") from exc


def resolve_mod_sdk_source(source: Path | None = None) -> Path:
    if source is not None:
        return source.expanduser().resolve()
    configured = os.environ.get(MOD_SDK_ENV)
    candidates = [Path(configured).expanduser()] if configured else []
    candidates.extend(
        (
            Path.home() / "Downloads" / "cl_mod_sdk_v1",
            Path.home() / "Downloads" / "cl_mod_sdk_v1.zip",
        ),
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    raise FileNotFoundError(
        f"Crimsonland MOD SDK not found; pass --sdk or set {MOD_SDK_ENV}",
    )


def _check_bytes(
    *,
    component: str,
    data: bytes,
    expected_size: int,
    expected_sha256: str,
) -> tuple[ModSdkCheck, ModSdkCheck]:
    actual_sha256 = hashlib.sha256(data).hexdigest()
    return (
        ModSdkCheck(
            component=component,
            kind="size",
            passed=len(data) == expected_size,
            detail=f"expected={expected_size} actual={len(data)}",
        ),
        ModSdkCheck(
            component=component,
            kind="sha256",
            passed=actual_sha256 == expected_sha256,
            detail=f"expected={expected_sha256} actual={actual_sha256}",
        ),
    )


def _rich_records(data: bytes) -> Counter[tuple[int, int]]:
    try:
        import pefile
    except ModuleNotFoundError as exc:
        raise RuntimeError("pefile is required for MOD SDK calibration; run `uv sync --dev`") from exc

    pe = pefile.PE(data=data)
    values = getattr(getattr(pe, "RICH_HEADER", None), "values", None)
    if not isinstance(values, list) or len(values) % 2 or not all(isinstance(value, int) for value in values):
        raise ValueError("PE has no valid Rich record array")
    typed_values = cast(list[int], values)
    records: Counter[tuple[int, int]] = Counter()
    for comp_id, count in zip(typed_values[::2], typed_values[1::2], strict=True):
        records[(comp_id >> 16, comp_id & 0xFFFF)] += count
    return records


def _pe_linker_version(data: bytes) -> tuple[int, int]:
    try:
        import pefile
    except ModuleNotFoundError as exc:
        raise RuntimeError("pefile is required for MOD SDK calibration; run `uv sync --dev`") from exc

    pe = pefile.PE(data=data, fast_load=True)
    return int(pe.OPTIONAL_HEADER.MajorLinkerVersion), int(pe.OPTIONAL_HEADER.MinorLinkerVersion)


def _project_provenance_checks(
    project: dict[str, Any],
    *,
    reader: _PackageReader,
) -> list[ModSdkCheck]:
    name = str(project["name"])
    data = reader.read(str(project["binary"]))
    checks: list[ModSdkCheck] = []
    linker = _pe_linker_version(data)
    expected_linker = tuple(map(int, project["linker_version"]))
    checks.append(
        ModSdkCheck(
            component=name,
            kind="linker-version",
            passed=linker == expected_linker,
            detail=f"expected={expected_linker[0]}.{expected_linker[1]} actual={linker[0]}.{linker[1]}",
        ),
    )
    records = _rich_records(data)
    for record in project["rich_records"]:
        key = int(record["product_id"]), int(record["build"])
        expected = int(record["count"])
        actual = records[key]
        checks.append(
            ModSdkCheck(
                component=name,
                kind="rich-record",
                passed=actual == expected,
                detail=f"product={key[0]} build={key[1]} expected={expected} actual={actual}",
            ),
        )
    return checks


def _compile_project_checks(
    project: dict[str, Any],
    *,
    reader: _PackageReader,
    match_root: Path,
) -> list[ModSdkCheck]:
    name = str(project["name"])
    compiler = project["compiler"]
    with tempfile.TemporaryDirectory(prefix=f"crimson-{name}-") as temp_name:
        temp = Path(temp_name)
        for source_path in project["source_files"]:
            destination = temp / PurePosixPath(str(source_path)).name
            destination.write_bytes(reader.read(str(source_path)))
        binary_path = temp / PurePosixPath(str(project["binary"])).name
        binary_path.write_bytes(reader.read(str(project["binary"])))
        source_name = PurePosixPath(str(project["source"])).name
        command = [
            str(match_root.resolve() / "cl.sh"),
            "/c",
            *map(str, compiler["flags"]),
            *(
                argument
                for define in compiler["defines"]
                for argument in ("/D", str(define))
            ),
            source_name,
        ]
        environment = dict(os.environ)
        environment["MSVC_VER"] = str(compiler["profile"])
        environment["CRIMSON_MATCH_INCLUDE_OVERLAY"] = str(temp)
        completed = subprocess.run(
            command,
            cwd=temp,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        obj_path = temp / Path(source_name).with_suffix(".obj")
        if completed.returncode or not obj_path.is_file():
            detail = " ".join(line.strip() for line in (completed.stdout + completed.stderr).splitlines() if line.strip())
            return [
                ModSdkCheck(
                    component=name,
                    kind="compile",
                    passed=False,
                    detail=detail or f"compiler exited {completed.returncode}",
                ),
            ]

        obj = matchlib.parse_coff_object(obj_path.read_bytes())
        expected_comp_id = (int(compiler["product_id"]) << 16) | int(compiler["build"])
        comp_ids = [symbol.value for symbol in obj.symbols if symbol.name == "@comp.id"]
        checks = [
            ModSdkCheck(
                component=name,
                kind="compiler-record",
                passed=comp_ids == [expected_comp_id],
                detail=(
                    f"expected=0x{expected_comp_id:08x} actual="
                    + (",".join(f"0x{value:08x}" for value in comp_ids) or "missing")
                ),
            ),
        ]

        try:
            import pefile
        except ModuleNotFoundError as exc:
            raise RuntimeError("pefile is required for MOD SDK calibration; run `uv sync --dev`") from exc
        pe = pefile.PE(data=binary_path.read_bytes())
        image = matchlib.load_image(binary_path)
        export_directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        export_symbols = getattr(export_directory, "symbols", ())
        exports = {
            entry.name.decode("latin1"): int(pe.OPTIONAL_HEADER.ImageBase) + int(entry.address)
            for entry in export_symbols
            if entry.name is not None
        }
        for export in project["exports"]:
            export_name = str(export["name"])
            symbol = str(export["symbol"])
            try:
                target_va = exports[export_name]
                candidate = matchlib.extract_object_function(obj, symbol)
                target = image.function_bytes(target_va, target_va + len(candidate.data))
                result = matchlib.match_function(
                    target,
                    candidate,
                    image=image,
                    target_va=target_va,
                )
            except Exception as exc:  # noqa: BLE001 - surface a failed calibration as a check
                checks.append(
                    ModSdkCheck(
                        component=f"{name}:{export_name}",
                        kind="normalized-code",
                        passed=False,
                        detail=str(exc).splitlines()[0],
                    ),
                )
                continue
            checks.append(
                ModSdkCheck(
                    component=f"{name}:{export_name}",
                    kind="normalized-code",
                    passed=result.ratio == 1.0 and bool(result.target_lines),
                    detail=(
                        f"match={result.ratio:.2%} instructions="
                        f"{len(result.candidate_lines)}/{len(result.target_lines)} "
                        f"target=0x{target_va:08x}"
                    ),
                ),
            )
        return checks


def validate_mod_sdk(
    source: Path | None = None,
    *,
    manifest_path: Path = DEFAULT_MOD_SDK_MANIFEST,
    match_root: Path = matchlib.DEFAULT_MATCH_ROOT,
    compile_exports: bool = True,
) -> ModSdkReport:
    payload = load_mod_sdk_manifest(manifest_path)
    package = payload["package"]
    resolved_source = resolve_mod_sdk_source(source)
    reader = _PackageReader(resolved_source, str(package["root"]))
    checks: list[ModSdkCheck] = []
    if reader.kind == "archive":
        archive_data = resolved_source.read_bytes()
        checks.extend(
            _check_bytes(
                component=str(package["archive"]["filename"]),
                data=archive_data,
                expected_size=int(package["archive"]["size"]),
                expected_sha256=str(package["archive"]["sha256"]),
            ),
        )

    for artifact in package["artifacts"]:
        relative_path = str(artifact["path"])
        try:
            data = reader.read(relative_path)
        except OSError as exc:
            checks.append(
                ModSdkCheck(
                    component=relative_path,
                    kind="exists",
                    passed=False,
                    detail=str(exc),
                ),
            )
            continue
        checks.extend(
            _check_bytes(
                component=relative_path,
                data=data,
                expected_size=int(artifact["size"]),
                expected_sha256=str(artifact["sha256"]),
            ),
        )
    if any(not check.passed for check in checks):
        compile_exports = False
    for project in payload["projects"]:
        try:
            checks.extend(_project_provenance_checks(project, reader=reader))
            if compile_exports:
                checks.extend(
                    _compile_project_checks(
                        project,
                        reader=reader,
                        match_root=match_root,
                    ),
                )
        except Exception as exc:  # noqa: BLE001 - aggregate package failures in one report
            checks.append(
                ModSdkCheck(
                    component=str(project["name"]),
                    kind="calibration",
                    passed=False,
                    detail=str(exc).splitlines()[0],
                ),
            )

    calibration = payload["calibration"]
    return ModSdkReport(
        source=resolved_source,
        source_kind=reader.kind,
        checks=tuple(checks),
        release=str(package["release"]),
        oracle_scope=tuple(map(str, calibration["oracle_scope"])),
        excluded_claims=tuple(map(str, calibration["excluded_claims"])),
    )


def mod_sdk_report_payload(report: ModSdkReport) -> dict[str, Any]:
    return {
        "ok": report.ok,
        "source": str(report.source),
        "source_kind": report.source_kind,
        "release": report.release,
        "oracle_scope": list(report.oracle_scope),
        "excluded_claims": list(report.excluded_claims),
        "summary": {
            "checks": len(report.checks),
            "passed": len(report.checks) - len(report.failed),
            "failed": len(report.failed),
        },
        "checks": [
            {
                "component": check.component,
                "kind": check.kind,
                "passed": check.passed,
                "detail": check.detail,
            }
            for check in report.checks
        ],
    }


def render_mod_sdk_report(report: ModSdkReport) -> str:
    state = "ok" if report.ok else "failed"
    lines = [
        f"mod-sdk={state} release={report.release} source={report.source} ({report.source_kind})",
        f"checks={len(report.checks)} failed={len(report.failed)}",
    ]
    grouped: dict[str, list[ModSdkCheck]] = {}
    for check in report.checks:
        grouped.setdefault(check.component, []).append(check)
    for component, checks in grouped.items():
        failures = [check for check in checks if not check.passed]
        component_state = "ok" if not failures else "failed"
        lines.append(f"{component} {component_state} checks={len(checks)}")
        for check in checks:
            if check.kind in {"compiler-record", "normalized-code", "linker-version", "rich-record"} or not check.passed:
                lines.append(f"  {check.kind}: {check.detail}")
    lines.append("oracle scope:")
    lines.extend(f"  + {claim}" for claim in report.oracle_scope)
    lines.append("excluded claims:")
    lines.extend(f"  - {claim}" for claim in report.excluded_claims)
    return "\n".join(lines)
