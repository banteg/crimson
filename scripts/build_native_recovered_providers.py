from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, cast

from crimson import match as matchlib
from crimson import native_link
from crimson.library_match import match_coff_archive

REPO_ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_PATH = REPO_ROOT / "analysis/library_provenance.json"
MATCH_ROOT = REPO_ROOT / "tools/match"
DERIVED_ID = "crimsonland-recovered-platform-vc6-provider"
OUTPUT = Path("crimsonland-platform/crimsonland-platform.lib")
IMAGE = "crimsonland.exe"
SCRATCHES = (
    "dx_get_version",
    "dx_get_version_from_dxdiag",
    "win32_file_get_version_words",
    "dx_version_pack_4x16",
    "dx_version_compare_4x16",
    "reg_read_dword_default",
    "reg_write_dword",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _derived_row() -> dict[str, Any]:
    payload = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
    rows = payload.get("derived_artifacts")
    if not isinstance(rows, list):
        raise TypeError("derived_artifacts must be an array")
    matches = [
        row
        for row in rows
        if isinstance(row, dict) and row.get("id") == DERIVED_ID
    ]
    if len(matches) != 1:
        raise ValueError(f"derived_artifacts must contain one {DERIVED_ID!r} row")
    return cast(dict[str, Any], matches[0])


def _verify_file(path: Path, row: dict[str, Any]) -> None:
    expected_size = int(row["size"])
    expected_sha256 = str(row["sha256"])
    actual_size = path.stat().st_size
    actual_sha256 = _sha256(path)
    if actual_size != expected_size or actual_sha256 != expected_sha256:
        raise ValueError(
            f"{DERIVED_ID} mismatch: "
            f"size={actual_size}/{expected_size} "
            f"sha256={actual_sha256}/{expected_sha256}",
        )


def _run(argv: list[str], *, cwd: Path) -> None:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=os.environ.copy(),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode:
        detail = "\n".join(
            part.strip()
            for part in (completed.stdout, completed.stderr)
            if part.strip()
        )
        raise RuntimeError(
            f"{' '.join(argv)} failed ({completed.returncode})\n{detail}",
        )


def _toolchain(derived: dict[str, Any]) -> tuple[Path, Path]:
    compiler_root = MATCH_ROOT / "compilers/msvc6.5"
    library_tool = compiler_root / "Bin/LIB.EXE"
    wibo = MATCH_ROOT / "bin/wibo"
    if not library_tool.is_file() or not wibo.is_file():
        raise FileNotFoundError("MSVC 6.5 LIB.EXE and wibo are required")
    tools = derived.get("tools")
    if not isinstance(tools, dict):
        raise TypeError(f"{DERIVED_ID}: tools must be an object")
    for name, path in (("lib", library_tool), ("wibo", wibo)):
        expected = tools.get(f"{name}_sha256")
        actual = _sha256(path)
        if actual != expected:
            raise ValueError(
                f"{DERIVED_ID}: {name} sha256={actual}/{expected}",
            )
    return library_tool, wibo


def _compile_exact_scratch(name: str) -> Path:
    config = matchlib.load_scratch_config(MATCH_ROOT / "scratches" / name)
    if config.image != IMAGE:
        raise ValueError(f"{name}: targets {config.image!r}, expected {IMAGE!r}")
    object_path = matchlib.compile_scratch(config, MATCH_ROOT, force=True)
    result = matchlib.run_match(
        obj_path=object_path,
        function=config.function,
        image_path=matchlib.default_image_path(IMAGE),
        functions_path=matchlib.default_functions_path(IMAGE),
        metadata_path=matchlib.default_metadata_path(IMAGE),
        symbol_name=config.symbol,
        end_va=config.end_va,
        reference_aliases=config.reference_aliases,
        scope="all",
    )
    if not result.exact:
        raise ValueError(
            f"{name}: recovered provider is not exact "
            f"({result.ratio:.6%}, references="
            f"{result.masked_operand_audit.ok_count}/"
            f"{result.masked_operand_audit.unresolved_count}/"
            f"{result.masked_operand_audit.mismatch_count})",
        )
    return object_path


def _require_archive_match(archive: Path, name: str) -> None:
    manifest = matchlib.load_function_manifest(
        matchlib.default_functions_path(IMAGE),
        metadata_path=matchlib.default_metadata_path(IMAGE),
        image_name=IMAGE,
        scope="all",
    )
    function = manifest.by_name[name]
    config = matchlib.load_scratch_config(MATCH_ROOT / "scratches" / name)
    report = match_coff_archive(
        archive,
        image_path=matchlib.default_image_path(IMAGE),
        functions_path=matchlib.default_functions_path(IMAGE),
        metadata_path=matchlib.default_metadata_path(IMAGE),
        range_start=function.address,
        range_end=function.address + 1,
    )
    candidates = [
        candidate
        for match in report.matches
        if match.address == function.address
        for candidate in match.candidates
        if candidate.symbol == f"_{config.symbol}"
        and candidate.member == f"{name}.obj"
    ]
    if len(candidates) != 1:
        raise ValueError(
            f"{archive.name}: no unique {name} match at "
            f"0x{function.address:08x}",
        )


def build_recovered_providers(output_root: Path) -> Path:
    derived = _derived_row()
    library_tool, wibo = _toolchain(derived)
    with tempfile.TemporaryDirectory(
        prefix="crimson-recovered-providers-",
    ) as raw_temp:
        temporary = Path(raw_temp)
        object_names: list[str] = []
        for name in SCRATCHES:
            source = _compile_exact_scratch(name)
            destination = temporary / f"{name}.obj"
            destination.write_bytes(source.read_bytes())
            object_names.append(destination.name)

        archive = temporary / OUTPUT.name
        _run(
            [
                str(wibo),
                str(library_tool),
                "/nologo",
                f"/out:{archive.name}",
                *object_names,
            ],
            cwd=temporary,
        )
        archive.write_bytes(
            native_link.normalize_coff_archive_timestamps(
                archive.read_bytes(),
            ),
        )
        for name in SCRATCHES:
            _require_archive_match(archive, name)
        _verify_file(archive, derived)

        output = output_root / OUTPUT
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary_output = output.with_suffix(f"{output.suffix}.tmp")
        shutil.copyfile(archive, temporary_output)
        temporary_output.replace(output)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build the byte-proven Crimsonland platform-provider archive."
        ),
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=REPO_ROOT / "tools/native/providers/build",
        help="provider build directory",
    )
    args = parser.parse_args()
    output = build_recovered_providers(args.output_root.resolve())
    try:
        label = output.relative_to(REPO_ROOT)
    except ValueError:
        label = output
    print(
        f"{label} size={output.stat().st_size} sha256={_sha256(output)}",
    )


if __name__ == "__main__":
    main()
