---
tags:
  - status-parity
---

# Extraction pipeline
The extractor walks the `game_bins/` directory, finds all `.paq` archives, and
writes files under `artifacts/assets/{paq_name}/...` while applying a couple of format
conversions.

## Command

```bash
uv run crimson extract game_bins/crimsonland/1.9.93-gog artifacts/assets
```

## Output rules

- `.jaz` → decode and save a single composite PNG (RGB + alpha).
- `.tga` → convert to PNG.
- everything else → write as raw bytes.
The extractor normalizes path separators and rejects `.`/`..` segments to
avoid directory traversal.

## Implementation

- CLI: `src/crimson/cli.py`
- PAQ parser: `src/grim/paq.py`
- JAZ decoder: `src/grim/jaz.py`
- Atlas slicing helpers: `src/crimson/atlas.py`
