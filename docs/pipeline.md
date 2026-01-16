# Extraction pipeline

**Status:** In progress

The extractor walks the `game/` directory, finds all `.paq` archives, and
writes files under `assets/{paq_name}/...` while applying a couple of format
conversions.

## Command

```bash
uv run paq extract game assets
```

## Output rules

- `.jaz` → decode and save a single composite PNG (RGB + alpha).
- `.tga` → convert to PNG.
- everything else → write as raw bytes.

The extractor normalizes path separators and rejects `.`/`..` segments to
avoid directory traversal.

## Implementation

- CLI: `src/crimson/cli.py`
- PAQ parser: `src/crimson/paq.py`
- JAZ decoder: `src/crimson/jaz.py`
- Atlas slicing helpers: `src/crimson/atlas.py`
