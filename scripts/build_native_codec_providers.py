from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any, cast

from crimson import native_link
from crimson.library_match import match_coff_archive

REPO_ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_PATH = REPO_ROOT / "analysis/library_provenance.json"
MATCH_ROOT = REPO_ROOT / "tools/match"
JPEG_DERIVED_ID = "ijg-libjpeg-6a-vc6-jaz-provider"
ZLIB_DERIVED_ID = "zlib-1.1.3-vc6-provider"
JPEG_SOURCE_ID = "ijg-libjpeg-6a"
ZLIB_SOURCE_ID = "zlib-1.1.3"
JPEG_OUTPUT = Path("ijg-libjpeg-6a/libjpeg.lib")
ZLIB_OUTPUT = Path("zlib-1.1.3/zlib.lib")
JPEG_FLAGS = ("/O2", "/GB", "/W3", "/MD")
JPEG_G6_FLAGS = ("/O2", "/G6", "/W3", "/MD")
ZLIB_FLAGS = ("/O2", "/GB", "/W3", "/MD")
JPEG_ARCHIVE_SOURCES = (
    "jdapimin.c",
    "jdapistd.c",
    "jdtrans.c",
    "jdatasrc.c",
    "jdmaster.c",
    "jdinput.c",
    "jdmarker.c",
    "jdhuff.c",
    "jdphuff.c",
    "jdmainct.c",
    "jdcoefct.c",
    "jdpostct.c",
    "jddctmgr.c",
    "jidctfst.c",
    "jidctflt.c",
    "jidctint.c",
    "jidctred.c",
    "jdsample.c",
    "jdcolor.c",
    "jquant1.c",
    "jquant2.c",
    "jdmerge.c",
    "jcomapi.c",
    "jutils.c",
    "jerror.c",
    "jmemmgr.c",
    "jmemnobs.c",
    "grim_jpeg_memory_src.c",
)
JPEG_G6_SOURCES = (
    "jdmarker.c",
    "jcomapi.c",
    "grim_jpeg_memory_src.c",
)
JPEG_BLEND_SOURCES = tuple(source for source in JPEG_ARCHIVE_SOURCES if source not in JPEG_G6_SOURCES)
JPEG_REQUIRED_MATCHES = (
    (0x10009A50, "_jpeg_CreateDecompress", "jdapimin.obj"),
    (0x10009B20, "_jpeg_destroy_decompress", "jdapimin.obj"),
    (0x10009B30, "_jpeg_read_header", "jdapimin.obj"),
    (0x10009BA0, "_jpeg_consume_input", "jdapimin.obj"),
    (0x10009C60, "_default_decompress_parms", "jdapimin.obj"),
    (0x10009E00, "_jpeg_finish_decompress", "jdapimin.obj"),
    (0x10009EC0, "_jpeg_start_decompress", "jdapistd.obj"),
    (0x10009FA0, "_output_pass_setup", "jdapistd.obj"),
    (0x1000A070, "_jpeg_read_scanlines", "jdapistd.obj"),
    (0x1003A990, "_grim_jpeg_memory_src", "grim_jpeg_memory_src.obj"),
    (0x1003AA10, "_init_source", "grim_jpeg_memory_src.obj"),
    (0x1003AA20, "_fill_input_buffer", "grim_jpeg_memory_src.obj"),
    (0x1003AAC0, "_skip_input_data", "grim_jpeg_memory_src.obj"),
    (0x1003AB00, "_term_source", "grim_jpeg_memory_src.obj"),
    (0x1003AB10, "_jpeg_std_error", "jerror.obj"),
    (0x1003B560, "_jpeg_resync_to_restart", "jdmarker.obj"),
    (0x1003DD00, "_jpeg_abort", "jcomapi.obj"),
    (0x1003DD30, "_jpeg_destroy", "jcomapi.obj"),
)
ZLIB_SOURCES = (
    "adler32.c",
    "compress.c",
    "crc32.c",
    "gzio.c",
    "uncompr.c",
    "deflate.c",
    "trees.c",
    "zutil.c",
    "inflate.c",
    "infblock.c",
    "inftrees.c",
    "infcodes.c",
    "infutil.c",
    "inffast.c",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row_by_id(rows: object, row_id: str, *, label: str) -> dict[str, Any]:
    if not isinstance(rows, list):
        raise TypeError(f"{label} must be an array")
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == row_id]
    if len(matches) != 1:
        raise ValueError(f"{label} must contain one {row_id!r} row")
    return cast(dict[str, Any], matches[0])


def _verify_file(path: Path, row: dict[str, Any], *, label: str) -> None:
    expected_size = int(row["size"])
    expected_sha256 = str(row["sha256"])
    actual_size = path.stat().st_size
    actual_sha256 = _sha256(path)
    if actual_size != expected_size or actual_sha256 != expected_sha256:
        raise ValueError(
            f"{label} mismatch: size={actual_size}/{expected_size} sha256={actual_sha256}/{expected_sha256}",
        )


def _run(argv: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode:
        detail = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
        raise RuntimeError(f"{' '.join(argv)} failed ({completed.returncode})\n{detail}")


def _toolchain(derived: dict[str, Any]) -> tuple[Path, Path, Path, dict[str, str]]:
    compiler_roots = (
        MATCH_ROOT / "compilers/msvc6.5",
        REPO_ROOT.parent / "snail-mail/tools/match/compilers/msvc6.5",
    )
    compiler_root = next(
        (root for root in compiler_roots if (root / "Bin/CL.EXE").is_file() and (root / "Bin/LIB.EXE").is_file()),
        None,
    )
    if compiler_root is None:
        raise FileNotFoundError("MSVC 6.5 CL.EXE and LIB.EXE are required")
    cl = compiler_root / "Bin/CL.EXE"
    library_tool = compiler_root / "Bin/LIB.EXE"
    wibo = MATCH_ROOT / "bin/wibo"
    if not wibo.is_file():
        raise FileNotFoundError(f"missing {wibo}")
    tools = derived.get("tools")
    if not isinstance(tools, dict):
        raise TypeError(f"{derived['id']}: tools must be an object")
    for name, path in (("cl", cl), ("lib", library_tool), ("wibo", wibo)):
        expected = tools.get(f"{name}_sha256")
        actual = _sha256(path)
        if actual != expected:
            raise ValueError(f"{derived['id']}: {name} sha256={actual}/{expected}")
    env = os.environ.copy()
    env["CRIMSON_MSVC_ROOT"] = str(compiler_root)
    env["MSVC_VER"] = "msvc6.5"
    return MATCH_ROOT / "cl.sh", library_tool, wibo, env


def _compile(
    source_root: Path,
    sources: tuple[str, ...],
    flags: tuple[str, ...],
    *,
    cl_wrapper: Path,
    env: dict[str, str],
) -> None:
    _run([str(cl_wrapper), "/c", *flags, *sources], cwd=source_root, env=env)


def _build_archive(
    source_root: Path,
    output_name: str,
    objects: tuple[str, ...],
    *,
    library_tool: Path,
    wibo: Path,
) -> Path:
    output = source_root / output_name
    _run(
        [
            str(wibo),
            str(library_tool),
            "/nologo",
            f"/out:{output.name}",
            *objects,
        ],
        cwd=source_root,
    )
    output.write_bytes(native_link.normalize_coff_archive_timestamps(output.read_bytes()))
    return output


def _extract_source(
    archive: Path,
    source_row: dict[str, Any],
    destination: Path,
    *,
    label: str,
) -> Path:
    _verify_file(archive, source_row, label=label)
    with tarfile.open(archive, "r:gz") as source:
        source.extractall(destination, filter="data")
    candidates = [path for path in destination.iterdir() if path.is_dir()]
    if len(candidates) != 1:
        raise ValueError(f"{label}: expected one extracted source directory")
    return candidates[0]


def _required_match(archive: Path, address: int, symbol: str, member: str | None = None) -> None:
    report = match_coff_archive(
        archive,
        image_path=REPO_ROOT / "game_bins/crimsonland/1.9.93-gog/grim.dll",
        functions_path=REPO_ROOT / "analysis/ida/raw/grim.dll/functions.json",
        metadata_path=REPO_ROOT / "analysis/ida/raw/grim.dll/metadata.json",
        range_start=address,
        range_end=address + 1,
    )
    candidates = [
        candidate
        for match in report.matches
        if match.address == address
        for candidate in match.candidates
        if candidate.symbol == symbol and (member is None or candidate.member == member)
    ]
    if len(candidates) != 1:
        suffix = f" in {member}" if member is not None else ""
        raise ValueError(f"{archive.name}: no unique {symbol}{suffix} match at 0x{address:08x}")


def _configure_jpeg_boolean(source_root: Path) -> None:
    path = source_root / "jmorecfg.h"
    original = "typedef int boolean;"
    replacement = "typedef unsigned char boolean;"
    source = path.read_text(encoding="ascii")
    if source.count(original) != 1 or replacement in source:
        raise ValueError(f"{path}: expected the stock IJG 6a boolean typedef")
    path.write_text(source.replace(original, replacement), encoding="ascii")


def _publish(source: Path, destination: Path, derived: dict[str, Any]) -> None:
    _verify_file(source, derived, label=str(derived["id"]))
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(f"{destination.suffix}.tmp")
    temporary.write_bytes(source.read_bytes())
    temporary.replace(destination)


def build_codec_providers(jpeg_tar: Path, zlib_tar: Path, output_root: Path) -> tuple[Path, Path]:
    provenance = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
    jpeg_source = _row_by_id(provenance.get("source_artifacts"), JPEG_SOURCE_ID, label="source_artifacts")
    zlib_source = _row_by_id(provenance.get("source_artifacts"), ZLIB_SOURCE_ID, label="source_artifacts")
    jpeg_derived = _row_by_id(
        provenance.get("derived_artifacts"),
        JPEG_DERIVED_ID,
        label="derived_artifacts",
    )
    zlib_derived = _row_by_id(
        provenance.get("derived_artifacts"),
        ZLIB_DERIVED_ID,
        label="derived_artifacts",
    )
    cl_wrapper, library_tool, wibo, env = _toolchain(jpeg_derived)
    _toolchain(zlib_derived)

    with tempfile.TemporaryDirectory(prefix="crimson-codec-providers-") as raw_temp:
        temporary = Path(raw_temp)
        jpeg_root = _extract_source(jpeg_tar, jpeg_source, temporary / "jpeg", label=JPEG_SOURCE_ID)
        zlib_root = _extract_source(zlib_tar, zlib_source, temporary / "zlib", label=ZLIB_SOURCE_ID)

        shutil.copy2(jpeg_root / "jconfig.bcc", jpeg_root / "jconfig.h")
        _configure_jpeg_boolean(jpeg_root)
        shutil.copy2(
            REPO_ROOT / "tools/native/providers/sources/ijg-libjpeg-6a/grim_jpeg_memory_src.c",
            jpeg_root / "grim_jpeg_memory_src.c",
        )
        _compile(
            jpeg_root,
            JPEG_BLEND_SOURCES,
            JPEG_FLAGS,
            cl_wrapper=cl_wrapper,
            env=env,
        )
        _compile(
            jpeg_root,
            JPEG_G6_SOURCES,
            JPEG_G6_FLAGS,
            cl_wrapper=cl_wrapper,
            env=env,
        )
        jpeg_archive = _build_archive(
            jpeg_root,
            "libjpeg.lib",
            tuple(Path(source).with_suffix(".obj").name for source in JPEG_ARCHIVE_SOURCES),
            library_tool=library_tool,
            wibo=wibo,
        )

        _compile(zlib_root, ZLIB_SOURCES, ZLIB_FLAGS, cl_wrapper=cl_wrapper, env=env)
        zlib_archive = _build_archive(
            zlib_root,
            "zlib.lib",
            tuple(Path(source).with_suffix(".obj").name for source in ZLIB_SOURCES),
            library_tool=library_tool,
            wibo=wibo,
        )

        for address, symbol, member in JPEG_REQUIRED_MATCHES:
            _required_match(jpeg_archive, address, symbol, member)
        _required_match(zlib_archive, 0x10046400, "_uncompress")

        jpeg_output = output_root / JPEG_OUTPUT
        zlib_output = output_root / ZLIB_OUTPUT
        _publish(jpeg_archive, jpeg_output, jpeg_derived)
        _publish(zlib_archive, zlib_output, zlib_derived)
    return jpeg_output, zlib_output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build byte-proven Grim IJG JPEG 6a and zlib 1.1.3 provider archives.",
    )
    parser.add_argument("--jpeg-tar", type=Path, required=True, help="path to jpegsrc.v6a.tar.gz")
    parser.add_argument("--zlib-tar", type=Path, required=True, help="path to zlib-1.1.3.tar.gz")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=REPO_ROOT / "tools/native/providers/build",
        help="provider build directory",
    )
    args = parser.parse_args()
    jpeg_output, zlib_output = build_codec_providers(
        args.jpeg_tar.resolve(),
        args.zlib_tar.resolve(),
        args.output_root.resolve(),
    )
    for output in (jpeg_output, zlib_output):
        try:
            label = output.relative_to(REPO_ROOT)
        except ValueError:
            label = output
        print(f"{label} size={output.stat().st_size} sha256={_sha256(output)}")


if __name__ == "__main__":
    main()
