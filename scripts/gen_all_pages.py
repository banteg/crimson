from __future__ import annotations

from pathlib import Path


def extract_title(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem.replace("-", " ").title()


def main() -> int:
    docs_dir = Path("docs")
    all_pages_path = docs_dir / "all-pages.md"
    pages = []
    for path in docs_dir.rglob("*.md"):
        if path == all_pages_path:
            continue
        pages.append(path)

    pages.sort(key=lambda p: str(p.relative_to(docs_dir)))

    lines = [
        "# All pages",
        "",
        "This page is generated. Run `uv run python scripts/gen_all_pages.py` to update.",
        "",
    ]
    for path in pages:
        rel = path.relative_to(docs_dir).as_posix()
        title = extract_title(path)
        lines.append(f"- [{title}]({rel})")
    lines.append("")
    lines.append("")

    all_pages_path.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
