# Timeline historical bodies and bounded source controls

`quest_spawn_timeline_update` remains **91.228070%**, 113/115 instructions,
prefix 51, 13/0/0 references, and a non-exact body. No canonical source or
compiler setting is changed by this investigation.

## The pointer store predates the target release

[historical.py](historical.py) extracts the repository's local historical
installers as data. It never executes an installer. It repairs stale Inno
loader offsets only in temporary copies, extracts the game executables with
`innoextract`, and pins both package and extracted-image SHA-256 identities.
The loader layouts follow [innoextract's offset reader](https://github.com/dscharrer/innoextract/blob/master/src/loader/offsets.cpp).

[historical.json](historical.json) records these function bodies:

| Version | Function VA | Bytes | Instructions | Pointer-store triplet | Owned C++ Rich build |
|---|---|---:|---:|---|---|
| 1.9.1 | `0x430aa0` | 368 | 115 | Present, offset `0xa4` | 8966 |
| 1.9.8 | `0x4338c0` | 367 | 113 | Absent | 9044, product 49 |
| 1.9.9 | `0x434370` | 368 | 115 | Present, offset `0xa4` | 9782 |
| 1.9.93 target | `0x434250` | 368 | 115 | Present, offset `0xa4` | 9782 |

The relevant literal bytes in the three positive bodies are:

```asm
lea edi, [esi + 0xc]
mov [esp + 0x10], edi
mov [esp + 0x10], ebx
```

Their **complete instruction sequences agree after masking absolute image
addresses and the external call target**, while retaining local branch offsets.
This comparison does not audit external reference identities and is not a
whole-function byte-exact matching claim. A control that changes the dead store
to `[esp+0x14]` fails both the literal-triplet and instruction-sequence checks.

The 1.9.9 game code is in `crimsonland.RWG`; its `crimsonland.exe` is a wrapper.
The 1.9.8 body uses a count-field induction base and separate zero materialization.
Its compiler provenance agrees with the Processor Pack profile, but compiling
the current scratch under that profile does not reproduce that historical body.
The historical comparison therefore does not prove that compiler version alone
accounts for every difference, nor does it recover the source of the dead store.
It does show that the store is not unique to the later target executable.

## Sixty source controls

[controls.json](controls.json) stores exact source edits against canonical SHA-256
`a448391479030f257a8e5626e795be585674e2b4ec3e0fdb5e95ff9a08ff44d9`.
[verify_controls.py](verify_controls.py) reconstructs and rebuilds every source
with the stock compiler; [results.json](results.json) records the results.

| Family | Cases | Canonical body | Regressions |
|---|---:|---:|---:|
| Count guards, conditional pointer selection, assumptions and lazy initialization | 11 | 7 | 4 |
| Vector API value/reference boundaries and component indexing, including one baseline | 19 | 13 | 6 |
| Pointer-to-member fields, generic accessors and entry/relative heading loads | 16 | 16 | 0 |
| Register declarations on pointer, counters and cursors, with both heading forms | 14 | 14 | 0 |
| Total | **60** | **50** | **10** |

The vector family checks whether the API sensitivity that completed
[`projectile_render`](../projectile-vector-api-2026-09-28/README.md) transfers to
this function. It does not in these cases. Every member-pointer and register
form is also byte-neutral to the canonical candidate. No control improves the
match, and no behavioral claim is made for an unretained regressed source.

The earlier [dead-store mechanism](../../c2/compiler/qst-dead-store.md) remains
the useful constraint: find a credible source whose pointer definition survives
the last global dead-code pass while its final use disappears later. These
bounded negative results do not establish that all possible source forms are
exhausted.

## Reproduce

Use fresh output directories from the repository root:

```sh
uv run python tools/match/evidence/quest-history-controls-2026-09-28/historical.py \
  --out /tmp/quest-history
uv run python tools/match/evidence/quest-history-controls-2026-09-28/verify_controls.py \
  --out /tmp/quest-source-controls
```

The historical verifier requires the three existing packages under
`game_bins/crimsonland/historical/shareware` and `innoextract`. Binaries remain
local and are not included in this evidence package.
