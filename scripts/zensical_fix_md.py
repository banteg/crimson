#!/usr/bin/env python3
"""Fix common Zensical Markdown issues in docs."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys


LIST_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<marker>(?:[-+*])|(?:\d+[.)]))\s+")
FENCE_RE = re.compile(r"^(?P<indent>[ \t]{0,3})(?P<fence>`{3,}|~{3,})")
HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+")
HR_RE = re.compile(r"^\s{0,3}(?:-{3,}|_{3,}|\*{3,})\s*$")

SKIP_DIRS = {".git", "_site"}


@dataclass(frozen=True)
class Issue:
    path: Path
    line_no: int
    message: str


def _indent_width(text: str) -> int:
    width = 0
    for ch in text:
        if ch == "\t":
            width += 4
        elif ch == " ":
            width += 1
        else:
            break
    return width


def is_list_item(line: str) -> bool:
    match = LIST_RE.match(line)
    if not match:
        return False
    indent = _indent_width(match.group("indent"))
    return indent <= 3


def is_heading(line: str) -> bool:
    return bool(HEADING_RE.match(line))


def is_horizontal_rule(line: str) -> bool:
    return bool(HR_RE.match(line))


def is_fence(line: str) -> re.Match[str] | None:
    return FENCE_RE.match(line)


def detect_newline(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def iter_md_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for candidate in path.rglob("*.md"):
                if SKIP_DIRS.intersection(candidate.parts):
                    continue
                files.append(candidate)
        elif path.suffix == ".md":
            files.append(path)
    return sorted(set(files))


def fix_file(path: Path, apply_fixes: bool) -> tuple[list[Issue], bool]:
    text = path.read_text(encoding="utf-8")
    newline = detect_newline(text)
    lines = text.splitlines(keepends=True)

    issues: list[Issue] = []
    output: list[str] = []

    in_fence = False
    fence_marker: str | None = None
    in_front_matter = False
    front_matter_done = False

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not front_matter_done and idx == 1 and stripped == "---":
            in_front_matter = True
            output.append(line)
            continue

        if in_front_matter:
            output.append(line)
            if stripped == "---":
                in_front_matter = False
                front_matter_done = True
            continue

        fence_match = is_fence(line)
        if fence_match:
            fence = fence_match.group("fence")
            if not in_fence:
                in_fence = True
                fence_marker = fence
            else:
                if fence_marker and fence[0] == fence_marker[0] and len(fence) >= len(
                    fence_marker
                ):
                    in_fence = False
                    fence_marker = None

        if not in_fence and is_list_item(line):
            prev_line = output[-1] if output else None
            if prev_line is not None:
                prev_stripped = prev_line.strip()
                if (
                    prev_stripped
                    and not is_list_item(prev_line)
                    and not is_heading(prev_line)
                    and not is_horizontal_rule(prev_line)
                ):
                    issues.append(
                        Issue(
                            path=path,
                            line_no=idx,
                            message="insert blank line before list",
                        )
                    )
                    if apply_fixes:
                        output.append(newline)

        output.append(line)

    changed = output != lines
    if apply_fixes and changed:
        path.write_text("".join(output), encoding="utf-8")
    return issues, changed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fix common Zensical Markdown issues (blank lines before lists)."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["docs"],
        help="Files or directories to scan (default: docs).",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Report issues without writing.")
    mode.add_argument("--fix", action="store_true", help="Apply fixes in-place.")
    args = parser.parse_args()

    apply_fixes = not args.check
    files = iter_md_files(args.paths)
    if not files:
        print("No markdown files found.", file=sys.stderr)
        return 1

    all_issues: list[Issue] = []
    changed_files: list[Path] = []

    for path in files:
        issues, changed = fix_file(path, apply_fixes=apply_fixes)
        all_issues.extend(issues)
        if changed:
            changed_files.append(path)

    for issue in all_issues:
        print(f"{issue.path}:{issue.line_no}: {issue.message}")

    if args.check:
        return 1 if all_issues else 0

    if changed_files:
        print(f"Updated {len(changed_files)} file(s).")
    else:
        print("No changes needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
