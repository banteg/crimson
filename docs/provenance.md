---
tags:
  - status-tracking
---

# Build provenance and hashes

This repo currently decompiles the GOG Crimsonland Classic build whose
`whatsupdated.txt` reports version **1.9.93**. That file lives alongside the
runtime binaries in the bin below.

## Runtime files (1.9.93-gog)

| File | SHA-256 |
| --- | --- |
| `crimsonland.exe` | `771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4` |
| `grim.dll` | `373f1304511c2cdb06a36447cc96f281a270bfe96957ca8ff03e19cf03dc8e70` |
| `crimson.paq` | `900068cbb0e6fc6d43a2558cdcb183d967a7966f3517123a76880ad60229a679` |
| `sfx.paq` | `268eb26c8d494719eb84ed2fd75d5c82d50dc424a17eda465daeb93627750535` |
| `whatsupdated.txt` | `861b38cfff5157ccba74ae1c0b5347ab4ed097d9c4d95b43b59ba376ad41a8ae` |

## Installer provenance (GOG)

Installer file: `setup_crimsonland_classic_2.0.0.4.exe` (from gog.com)

| File | SHA-256 |
| --- | --- |
| `setup_crimsonland_classic_2.0.0.4.exe` | `fd51c739647630d12728cac2313349b90afa43a946d707ef9ad79a8a6c4d6c03` |

## Recompute hashes

```bash
sha256sum game_bins/crimsonland/1.9.93-gog/crimsonland.exe \
  game_bins/crimsonland/1.9.93-gog/grim.dll \
  game_bins/crimsonland/1.9.93-gog/crimson.paq \
  game_bins/crimsonland/1.9.93-gog/sfx.paq \
  game_bins/crimsonland/1.9.93-gog/whatsupdated.txt
sha256sum game_bins/crimsonland/1.9.93-gog/setup_crimsonland_classic_2.0.0.4.exe
```
