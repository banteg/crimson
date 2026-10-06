"""The resolved-name audit: names the curated maps have replaced must not linger in live files.

Two kinds of stale identity are flagged:

- analyzer placeholders (`FUN_00401000`, `DAT_00405000`, `nullsub_3`) at an address the
  name or data map already names;
- superseded names, which each map row records in `formerly` when it is renamed.

Only live files count: code, headers, maps, the decomp, tests, the core and docs. Dated
investigation records (match evidence, scratch notes and experiment logs, archived captures)
keep the names they were written with. `--rewrite` replaces every unambiguous hit, so a rename
is: change the map row's `name`, add the old one to `formerly`, rewrite. A line that has to
keep an old name, such as a serialized key, carries `name-audit: keep`.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter, defaultdict
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from . import match as matchlib

IDENTIFIER_TOKEN_RE = re.compile(r"(?<![0-9a-z_])[a-z_][a-z0-9_]*(?![0-9a-z_])", re.IGNORECASE)
ADDRESS_DERIVED_IDENTITY_RE = re.compile(
    r"^(?:j_(?:FUN|sub)_|FUN_|sub_|DAT_|data_|LAB_|loc_|PTR_|"
    r"(?:switchD|caseD|lookup_table)_|(?:byte|word|dword|qword|off|unk|field)_)[0-9a-f]+$|"
    r"^(?:j_)?nullsub_[0-9]+$|^unknown(?:_libname)?(?:_[0-9]+)?$",
    re.IGNORECASE,
)
ADDRESS_DERIVED_REFERENCE_RE = re.compile(
    r"(?<![0-9a-z_])(?P<token>_?(?P<prefix>j_FUN|j_sub|FUN|sub|DAT|data|LAB|loc|PTR|"
    r"switchD|caseD|lookup_table|byte|word|dword|qword|off|unk|field)_"
    r"(?P<address>[0-9a-f]{6,16}))(?![0-9a-z_])",
    re.IGNORECASE,
)
FUNCTION_REFERENCE_PREFIXES = frozenset({"j_fun", "j_sub", "fun", "sub"})
AUDIT_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".conf",
        ".cpp",
        ".h",
        ".hpp",
        ".inc",
        ".js",
        ".json",
        ".md",
        ".py",
        ".sh",
        ".toml",
        ".ts",
        ".yaml",
        ".yml",
        ".zig",
    },
)
PRUNED_DIRECTORIES = frozenset(
    {
        ".cache",
        ".git",
        ".mypy_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "node_modules",
    },
)


AUDIT_ROOTS = ("analysis", "crimson-core", "crimson-re", "decomp", "docs", "scripts", "src", "tests", "third_party/headers", "tools")
# Generated outputs and dated history: names there are as of when they were written.
HISTORY_PATHS = (
    "analysis/archive",
    "analysis/binary_ninja",
    "analysis/decomp",
    "analysis/frida",
    "analysis/ghidra/raw",
    "analysis/historical",
    "analysis/ida",
    "analysis/native",
    "analysis/reviews",
    "crimson-core/results",
    "tools/match/c2",
    "tools/match/evidence",
)
_DATED_RECORD_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


# A line that must keep an old name on purpose (a wire format, say) says so.
KEEP_MARKER = "name-audit: keep"
# Tests of the naming tools build placeholder and superseded names as fixtures.
NAMING_FIXTURES = ("tests/test_analysis_view.py", "tests/test_match.py", "tests/test_name_audit.py")


def _live(relative: str) -> bool:
    if relative.startswith(HISTORY_PATHS) or relative in NAMING_FIXTURES:
        return False
    if relative.startswith("tools/match/scratches/"):
        return relative.endswith("/scratch.conf")
    # Dated reports such as tools/match/EXACT-MATCHES-2026-09-07.md.
    return _DATED_RECORD_RE.search(Path(relative).name) is None


def audit_files(repo_root: Path) -> tuple[Path, ...]:
    files: list[Path] = []
    for relative_root in AUDIT_ROOTS:
        source_root = repo_root / relative_root
        if not source_root.is_dir():
            continue
        for current_root, directories, filenames in os.walk(source_root):
            directories[:] = sorted(directory for directory in directories if directory not in PRUNED_DIRECTORIES)
            current_path = Path(current_root)
            for filename in sorted(filenames):
                path = current_path / filename
                if path.suffix.casefold() not in AUDIT_SUFFIXES:
                    continue
                if _live(path.relative_to(repo_root).as_posix()):
                    files.append(path)
    return tuple(files)


@dataclass(frozen=True, slots=True)
class ResolvedNameReferenceRow:
    path: str
    line: int
    source: str
    token: str
    image: str
    address: int
    canonical_names: tuple[str, ...]


def _stronger_identity_names(
    names: Collection[str],
    *,
    token: str,
) -> tuple[str, ...]:
    folded_token = token.casefold()
    return tuple(
        dict.fromkeys(
            name
            for name in names
            if name.casefold() != folded_token and ADDRESS_DERIVED_IDENTITY_RE.fullmatch(name) is None
        ),
    )


def collect_resolved_name_references(
    *,
    repo_root: Path = matchlib.REPO_ROOT,
    name_map_path: Path = matchlib.DEFAULT_NAME_MAP_PATH,
    data_map_path: Path = matchlib.DEFAULT_DATA_MAP_PATH,
) -> list[ResolvedNameReferenceRow]:
    """Find placeholder and superseded identities in live files."""

    function_names: dict[tuple[str, int], list[str]] = defaultdict(list)
    current: dict[str, set[str]] = defaultdict(set)
    formerly: list[tuple[str, str, int]] = []
    for row in matchlib.load_name_map_rows(name_map_path):
        key = (str(row.get("program", "")), matchlib.parse_int(row["address"]))
        name = str(row.get("name", ""))
        function_names[key].append(name)
        current[key[0]].add(name.casefold())
        current[key[0]].update(str(alias).casefold() for alias in row.get("aliases", ()) if isinstance(alias, str))
        formerly.extend((str(old), *key) for old in row.get("formerly", ()))

    data_payload = json.loads(data_map_path.read_text(encoding="utf-8"))
    raw_data_rows = data_payload.get("entries") if isinstance(data_payload, dict) else None
    if not isinstance(raw_data_rows, list):
        raise TypeError(f"{data_map_path}: data map must contain an entries array")
    data_names: dict[tuple[str, int], list[str]] = defaultdict(list)
    data_formerly: list[tuple[str, str, int]] = []
    for index, raw_row in enumerate(raw_data_rows):
        if not isinstance(raw_row, dict):
            raise TypeError(f"{data_map_path}: data-map row {index} must be an object")
        row = cast(dict[str, Any], raw_row)
        key = (str(row.get("program", "")), matchlib.parse_int(row["address"]))
        data_names[key].append(str(row.get("name", "")))
        current[key[0]].add(str(row.get("name", "")).casefold())
        data_formerly.extend((str(old), *key) for old in row.get("formerly", ()))

    function_by_address: dict[int, list[tuple[str, tuple[str, ...]]]] = defaultdict(list)
    for (image, address), names in function_names.items():
        function_by_address[address].append((image, tuple(names)))
    data_by_address: dict[int, list[tuple[str, tuple[str, ...]]]] = defaultdict(list)
    for (image, address), names in data_names.items():
        data_by_address[address].append((image, tuple(names)))

    # A former name still current elsewhere in its image is not stale.
    superseded: dict[str, list[tuple[str, str, int, tuple[str, ...]]]] = defaultdict(list)
    for entries, names_by_key in ((formerly, function_names), (data_formerly, data_names)):
        for old, image, address in entries:
            if old.casefold() in current[image]:
                continue
            canonical_names = _stronger_identity_names(names_by_key[(image, address)], token=old)
            if canonical_names:
                superseded[old.casefold()].append((old, image, address, canonical_names))

    rows: list[ResolvedNameReferenceRow] = []
    seen: set[tuple[str, int, str, str, int]] = set()
    native_definitions_root = repo_root / "tools" / "native" / "data_definitions"

    def append_row(
        *,
        path: Path,
        line: int,
        source: str,
        token: str,
        image: str,
        address: int,
        names: Collection[str],
    ) -> None:
        canonical_names = _stronger_identity_names(names, token=token)
        if not canonical_names:
            return
        try:
            display_path = path.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            display_path = path.as_posix()
        key = (display_path, line, token, image, address)
        if key in seen:
            return
        seen.add(key)
        rows.append(
            ResolvedNameReferenceRow(
                path=display_path,
                line=line,
                source=source,
                token=token,
                image=image,
                address=address,
                canonical_names=canonical_names,
            ),
        )

    # The maps record their own former names.
    record_paths = {name_map_path.resolve(), data_map_path.resolve()}
    for path in audit_files(repo_root):
        if path.is_relative_to(native_definitions_root):
            continue
        records_names = path.resolve() in record_paths
        try:
            contents = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(contents.splitlines(), start=1):
            if KEEP_MARKER in line:
                continue
            for match in ADDRESS_DERIVED_REFERENCE_RE.finditer(line):
                token = match.group("token")
                address = int(match.group("address"), 16)
                prefix = match.group("prefix").casefold()
                candidates = (
                    function_by_address.get(address, ())
                    if prefix in FUNCTION_REFERENCE_PREFIXES
                    else data_by_address.get(address, ())
                )
                for image, names in candidates:
                    append_row(path=path, line=line_number, source="text", token=token, image=image, address=address, names=names)
            for match in () if records_names else IDENTIFIER_TOKEN_RE.finditer(line):
                for token, image, address, names in superseded.get(match.group(0).casefold(), ()):
                    append_row(
                        path=path, line=line_number, source="superseded-identity",
                        token=token, image=image, address=address, names=names,
                    )

    if native_definitions_root.is_dir():
        for path in sorted(native_definitions_root.glob("*.json")):
            contents = path.read_text(encoding="utf-8")
            lines = contents.splitlines()
            payload = json.loads(contents)
            image = str(payload.get("image", "")) if isinstance(payload, dict) else ""
            raw_entries = payload.get("entries") if isinstance(payload, dict) else None
            if not isinstance(raw_entries, list):
                raise TypeError(f"{path}: native data definitions require an entries array")
            location_offsets: dict[tuple[str, str], int] = defaultdict(int)
            for entry in raw_entries:
                if not isinstance(entry, dict):
                    continue
                initializer_symbols = entry.get("initializer_symbols", ())
                if not isinstance(initializer_symbols, list):
                    continue
                for raw_symbol in initializer_symbols:
                    if not isinstance(raw_symbol, list) or len(raw_symbol) not in {2, 3}:
                        continue
                    address_text, token = raw_symbol[-2:]
                    if not isinstance(address_text, str) or not isinstance(token, str):
                        continue
                    address = matchlib.parse_int(address_text)
                    names = function_names.get((image, address), ())
                    if not names:
                        names = data_names.get((image, address), ())
                    if not names:
                        continue
                    is_address_derived = ADDRESS_DERIVED_IDENTITY_RE.fullmatch(token) is not None
                    is_superseded = any(
                        candidate_image == image and candidate_address == address
                        for _, candidate_image, candidate_address, _ in superseded.get(
                            token.casefold(),
                            (),
                        )
                    )
                    if not is_address_derived and not is_superseded:
                        continue
                    location_key = (address_text.casefold(), token)
                    occurrence = location_offsets[location_key]
                    matching_lines = [
                        index
                        for index, line in enumerate(lines, start=1)
                        if json.dumps(address_text) in line and json.dumps(token) in line
                    ]
                    line_number = (
                        matching_lines[min(occurrence, len(matching_lines) - 1)]
                        if matching_lines
                        else 1
                    )
                    location_offsets[location_key] += 1
                    append_row(
                        path=path,
                        line=line_number,
                        source="native-initializer",
                        token=token,
                        image=image,
                        address=address,
                        names=names,
                    )

    return sorted(rows, key=lambda row: (row.path, row.line, row.token, row.image, row.address))


def rewrite_resolved_name_references(
    rows: Collection[ResolvedNameReferenceRow],
    *,
    repo_root: Path = matchlib.REPO_ROOT,
) -> dict[str, int]:
    """Replace unambiguous analyzer labels with their curated identities.

    When the canonical identity is already present on the same line, retain the
    useful address as a plain hexadecimal literal instead of duplicating the
    name. Rows with multiple curated identities are left for manual review.
    """

    rows_by_path: dict[str, list[ResolvedNameReferenceRow]] = defaultdict(list)
    for row in rows:
        rows_by_path[row.path].append(row)

    files_updated = 0
    references_updated = 0
    rows_skipped = 0
    for display_path, path_rows in sorted(rows_by_path.items()):
        path = Path(display_path)
        if not path.is_absolute():
            path = repo_root / path
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        rows_by_line: dict[int, list[ResolvedNameReferenceRow]] = defaultdict(list)
        native_rows: list[ResolvedNameReferenceRow] = []
        for row in path_rows:
            if row.source == "native-initializer":
                native_rows.append(row)
            else:
                rows_by_line[row.line].append(row)

        file_updated = False
        for line_number, line_rows in sorted(rows_by_line.items()):
            if line_number < 1 or line_number > len(lines):
                rows_skipped += len(line_rows)
                continue
            original_line = lines[line_number - 1]
            rewritten_line = original_line
            for row in sorted(line_rows, key=lambda candidate: candidate.token):
                if len(row.canonical_names) != 1:
                    rows_skipped += 1
                    continue
                canonical = row.canonical_names[0]
                canonical_pattern = re.compile(
                    rf"(?<![0-9A-Za-z_]){re.escape(canonical)}(?![0-9A-Za-z_])",
                )
                replacement = (
                    f"0x{row.address:08x}"
                    if canonical_pattern.search(original_line) is not None
                    else canonical
                )
                token_pattern = re.compile(
                    rf"(?<![0-9A-Za-z_]){re.escape(row.token)}(?![0-9A-Za-z_])",
                )
                rewritten_line, replacement_count = token_pattern.subn(replacement, rewritten_line)
                if replacement_count == 0:
                    rows_skipped += 1
                    continue
                references_updated += replacement_count
                file_updated = True
            lines[line_number - 1] = rewritten_line
        rewritten_contents = "".join(lines)
        for row in native_rows:
            if len(row.canonical_names) != 1:
                rows_skipped += 1
                continue
            quoted_token = json.dumps(row.token)
            quoted_canonical = json.dumps(row.canonical_names[0])
            replacement_count = rewritten_contents.count(quoted_token)
            if replacement_count == 0:
                rows_skipped += 1
                continue
            rewritten_contents = rewritten_contents.replace(quoted_token, quoted_canonical)
            references_updated += replacement_count
            file_updated = True
        if file_updated:
            path.write_text(rewritten_contents, encoding="utf-8")
            files_updated += 1

    return {
        "files_updated": files_updated,
        "references_updated": references_updated,
        "rows_skipped": rows_skipped,
    }


def rewrite_superseded_identity_references(
    replacements_by_image: dict[str, dict[str, str]],
    *,
    repo_root: Path,
    match_root: Path,
    excluded_paths: Collection[Path] = (),
) -> int:
    """Rewrite semantic identities while the superseded names are still known."""

    targets_by_token: dict[str, dict[str, str]] = defaultdict(dict)
    spelling_by_token: dict[str, str] = {}
    for image in sorted(replacements_by_image):
        for old_name, canonical_name in sorted(replacements_by_image[image].items()):
            if old_name.casefold() == canonical_name.casefold():
                continue
            folded_old = old_name.casefold()
            spelling_by_token.setdefault(folded_old, old_name)
            targets_by_token[folded_old].setdefault(canonical_name.casefold(), canonical_name)
    global_replacements = {
        spelling_by_token[folded_old]: next(iter(targets.values()))
        for folded_old, targets in targets_by_token.items()
        if len(targets) == 1
    }

    excluded = {path.resolve() for path in excluded_paths}
    scratch_root = (match_root / "scratches").resolve()
    references_updated = 0
    for path in audit_files(repo_root):
        resolved_path = path.resolve()
        if resolved_path in excluded:
            continue
        replacements = global_replacements
        if resolved_path.is_relative_to(scratch_root):
            relative = resolved_path.relative_to(scratch_root)
            if len(relative.parts) >= 2:
                config_path = scratch_root / relative.parts[0] / "scratch.conf"
                if config_path.is_file():
                    image = matchlib.load_scratch_config(config_path.parent).image
                    replacements = replacements_by_image.get(image, {})
        if not replacements:
            continue
        original = path.read_text(encoding="utf-8")
        rewritten, count = matchlib._replace_identity_tokens(original, replacements)
        if rewritten == original:
            continue
        path.write_text(rewritten, encoding="utf-8")
        references_updated += count
    return references_updated


def resolved_name_reference_payload(row: ResolvedNameReferenceRow) -> dict[str, Any]:
    return {
        "path": row.path,
        "line": row.line,
        "source": row.source,
        "token": row.token,
        "image": row.image,
        "address": row.address,
        "canonical_names": list(row.canonical_names),
    }


def resolved_name_reference_summary_payload(
    rows: Collection[ResolvedNameReferenceRow],
) -> dict[str, Any]:
    sources = Counter(row.source for row in rows)
    return {
        "row_count": len(rows),
        "sources": {source: sources[source] for source in sorted(sources)},
    }


def render_resolved_name_reference_summary(
    rows: Collection[ResolvedNameReferenceRow],
) -> str:
    summary = resolved_name_reference_summary_payload(rows)
    return f"rows={summary['row_count']}; sources=" + ",".join(
        f"{source}:{count}" for source, count in summary["sources"].items()
    )


def render_resolved_name_reference_table(
    rows: Collection[ResolvedNameReferenceRow],
) -> str:
    header = ("path", "line", "source", "token", "canonical")
    rendered = [
        header,
        *(
            (
                row.path,
                str(row.line),
                row.source,
                row.token,
                "|".join(row.canonical_names),
            )
            for row in rows
        ),
    ]
    widths = [max(len(row[column]) for row in rendered) for column in range(len(header))]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip() for row in rendered]
    lines.append(f"\n{render_resolved_name_reference_summary(rows)}")
    return "\n".join(lines)
