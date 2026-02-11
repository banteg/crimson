#!/usr/bin/env python3
"""Docs consistency checks.

Checks:
- internal markdown links resolve
- nav coverage includes all docs markdown files
- pages have frontmatter tags, with explicit temporary allowlist
"""

from __future__ import annotations

import argparse
import re
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any


LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate docs links, nav coverage, and frontmatter tags.")
    parser.add_argument("--docs-dir", default="docs", help="Docs root directory.")
    parser.add_argument("--config", default="zensical.toml", help="Site config containing nav.")
    parser.add_argument(
        "--tags-allowlist",
        default="docs/.frontmatter_tags_allowlist",
        help="Files allowed to omit frontmatter tags.",
    )
    return parser.parse_args()


def collect_docs(docs_dir: Path) -> list[Path]:
    return sorted(path for path in docs_dir.rglob("*.md") if path.is_file())


def walk_nav(node: Any, out: list[str]) -> None:
    if isinstance(node, str):
        if node.endswith(".md"):
            out.append(node)
        return
    if isinstance(node, list):
        for item in node:
            walk_nav(item, out)
        return
    if isinstance(node, dict):
        for value in node.values():
            walk_nav(value, out)


def parse_nav(config_path: Path) -> list[str]:
    config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    nav = config["project"]["nav"]
    entries: list[str] = []
    walk_nav(nav, entries)
    return entries


def normalize_target(raw_target: str) -> str:
    target = raw_target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    # Keep markdown links simple; title suffix is not used in this repo.
    return target.split(maxsplit=1)[0]


def is_external_link(target: str) -> bool:
    if target.startswith("#"):
        return True
    external_prefixes = (
        "http://",
        "https://",
        "mailto:",
        "tel:",
        "ftp://",
        "data:",
    )
    return target.startswith(external_prefixes)


def find_broken_markdown_links(docs_dir: Path, docs_files: list[Path]) -> list[str]:
    errors: list[str] = []
    docs_root = docs_dir.resolve()

    for source in docs_files:
        content = source.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(content):
            raw_target = match.group(1)
            target = normalize_target(raw_target)
            if not target or is_external_link(target):
                continue

            path_part = target.split("#", 1)[0].split("?", 1)[0]
            if not path_part:
                continue
            if not path_part.endswith(".md"):
                continue

            if path_part.startswith("/"):
                resolved = (docs_root / path_part.lstrip("/")).resolve()
            else:
                resolved = (source.parent / path_part).resolve()

            # links must stay inside docs and point to an existing markdown page
            if not str(resolved).startswith(str(docs_root)) or not resolved.exists():
                src_rel = source.relative_to(docs_root)
                errors.append(f"{src_rel}: broken link '{raw_target}'")

    return errors


def has_frontmatter_tags(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return False
    end = text.find("\n---\n", 4)
    if end == -1:
        return False
    frontmatter = text[4:end]
    return "tags:" in frontmatter


def load_allowlist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    items: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        items.add(item)
    return items


def main() -> int:
    args = parse_args()

    root = Path.cwd()
    docs_dir = (root / args.docs_dir).resolve()
    config_path = (root / args.config).resolve()
    allowlist_path = (root / args.tags_allowlist).resolve()

    docs_files = collect_docs(docs_dir)
    docs_rel = sorted(str(path.relative_to(docs_dir)) for path in docs_files)
    docs_rel_set = set(docs_rel)

    nav_entries = parse_nav(config_path)
    nav_counts = Counter(nav_entries)
    nav_set = set(nav_entries)

    broken_links = find_broken_markdown_links(docs_dir, docs_files)

    nav_missing = sorted(nav_set - docs_rel_set)
    nav_orphans = sorted(docs_rel_set - nav_set)
    nav_duplicates = sorted(path for path, count in nav_counts.items() if count > 1)

    allowlist = load_allowlist(allowlist_path)
    missing_tags = sorted(rel for rel, path in zip(docs_rel, docs_files) if not has_frontmatter_tags(path))
    unexpected_missing_tags = sorted(rel for rel in missing_tags if rel not in allowlist)
    stale_allowlist = sorted(rel for rel in allowlist if rel not in set(missing_tags))

    has_errors = False

    if broken_links:
        has_errors = True
        print(f"Broken markdown links ({len(broken_links)}):")
        for error in broken_links:
            print(f"  - {error}")

    if nav_missing or nav_orphans or nav_duplicates:
        has_errors = True
        print("Navigation coverage issues:")
        if nav_missing:
            print(f"  - Nav entries with missing files ({len(nav_missing)}):")
            for rel in nav_missing:
                print(f"    - {rel}")
        if nav_orphans:
            print(f"  - Docs missing from nav ({len(nav_orphans)}):")
            for rel in nav_orphans:
                print(f"    - {rel}")
        if nav_duplicates:
            print(f"  - Duplicate nav entries ({len(nav_duplicates)}):")
            for rel in nav_duplicates:
                print(f"    - {rel}")

    if unexpected_missing_tags or stale_allowlist:
        has_errors = True
        print("Frontmatter/tag issues:")
        if unexpected_missing_tags:
            print(f"  - Missing tags outside allowlist ({len(unexpected_missing_tags)}):")
            for rel in unexpected_missing_tags:
                print(f"    - {rel}")
        if stale_allowlist:
            print(f"  - Stale allowlist entries ({len(stale_allowlist)}):")
            for rel in stale_allowlist:
                print(f"    - {rel}")

    if has_errors:
        return 1

    print(
        f"Docs checks passed: {len(docs_rel)} markdown files, {len(nav_entries)} nav entries, "
        f"{len(missing_tags)} allowlisted missing-tags pages."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
