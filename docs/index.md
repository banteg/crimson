# Crimsonland reverse engineering notes

This site tracks the file formats and asset pipeline we have verified from the
decompiled Crimsonland v1.9.93 executable and game data.

Overall naming coverage: 16.6% (295 / 1778 functions named or inferred).

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

- [PAQ archives](formats/paq.md) — Completed
- [JAZ textures](formats/jaz.md) — Completed
- [Small font (smallFnt.dat)](formats/font.md) — Draft
- [Sprite atlas cutting](atlas.md) — In progress
- [Extraction pipeline](pipeline.md) — In progress
- [Weapon table](weapon-table.md) — In progress
- [Progress metrics](metrics.md) — Tracking
- [Creature struct](creature-struct.md) — Tracking
- [Projectile struct](projectile-struct.md) — Tracking
- [Effects pools](effects-struct.md) — Tracking
- [Perk ID map](perk-id-map.md) — Tracking
- [Bonus ID map](bonus-id-map.md) — Tracking
- [SFX ID map](sfx-id-map.md) — Tracking
- [SFX usage](sfx-usage.md) — Tracking
- [SFX labels](sfx-labels.md) — Tracking
- [Game mode map](game-mode-map.md) — Tracking
- [Detangling notes](detangling.md) — In progress
- [Entrypoint trace](entrypoint.md) — In progress
- [Crimsonland.exe overview](crimsonland-exe.md) — Draft
- [Refactor attempt](refactor.md) — Planned
- [All pages](all-pages.md) — Index
- [Modern Linux build name mining](modern-linux.md) — Reference
- [Modern Android build name mining](modern-android.md) — Reference
- [Grim2D overview](grim2d-overview.md) — Draft
- [Grim2D API vtable](grim2d-api.md) — Draft
- [Grim2D API evidence](grim2d-api-evidence.md) — Draft
