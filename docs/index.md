# Crimsonland reverse engineering notes

This site tracks the file formats and asset pipeline we have verified from the
decompiled Crimsonland v1.9.93 executable and game data.

## Quick start

```bash
uv run paq extract game assets
```

This scans `game/` for `.paq` archives and extracts them under:

```
assets/{paq_name}/{path}
```

Special handling during extraction:
- `.jaz` files are decoded to a single composite PNG (RGB + alpha).
- `.tga` files are converted to PNG.
- Everything else is written as raw bytes.

## What is documented

- [PAQ archives](formats/paq.md)
- [JAZ textures](formats/jaz.md)
- [Sprite atlas cutting](atlas.md)
- [Extraction pipeline](pipeline.md)
