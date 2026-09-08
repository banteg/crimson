# Codec data evidence, 2026-09-08

32 previously unbounded mapped objects in `grim.dll` have independently recovered
extents and exact source-compiled initializers: **14,179 bytes**. Their owner is
`libraries`. The two copies of the inflate tables and JPEG natural-order table
are verified separately at their native addresses.

## Evidence and acceptance

The wrappers in `tools/match/data/*zlib*.c` and `*jpeg_utils.c` include the existing
pinned zlib 1.1.3 and IJG libjpeg 6a source files. They rename only the selected data
identifiers to their curated map names. The original declarations, initializers,
static linkage, and consuming functions remain intact. These are data-verification
wrappers; they do not establish original game translation-unit boundaries or
replace the native codec providers.

`match_data_report.refresh_evidence` compiles each wrapper with VC6 (`msvc6.5`),
`/c /O2 /Zl`, and a generated `sizeof` assertion for every object. `.c` wrappers use
a C harness. Manifest `internal_symbols` entries must name selected C objects;
the COFF check requires class STATIC for those objects and EXTERNAL otherwise.
An internal declaration cannot be accepted as common storage. Missing, duplicate,
wrong-linkage, truncated, executable, or incorrectly initialized storage fails.
The existing symbolic pointer checks also apply. All 32 objects have no PE base
relocations and no compiler relocations within their extents.

Bounds come from original declarations or the number of original initialized
records, never neighboring labels. VC6's 32-bit `int`, `uInt`, and `unsigned long`
are four bytes; `uch` is one byte. `inflate_huft` is an eight-byte record with its
base at offset four. `ct_data` is four bytes with its second unsigned-short union
at offset two. The wrappers assert those record layouts. The map now describes
these records instead of treating Huffman tables as opaque byte/word arrays;
the plain `inflate_mask` also retains its original non-const declaration.

`jpeg_natural_order` contains 64 permutation entries plus 16 safety entries set
to 63, as explained in `jutils.c`; those 16 entries are part of the object.
`trees.h` is the original generated fixed-tree header selected by the normal
STDC build of `trees.c`. `inffixed.h` supplies the fixed inflate tables.
The literal PE initializer bytes in native definitions are the expected output,
not input to the C wrappers. The report fingerprints all sources, headers,
wrapper code, manifest, verifier, compiler, and native binaries.

The pinned source provenance is recorded in `analysis/library_provenance.json`;
`third_party/sources/zlib-1.1.3`, `third_party/sources/ijg-libjpeg-6a`, and
`third_party/headers` contain the actual compiler inputs.

## Verified objects

| Native address | Curated object | Original definition/bound | Bytes | Linkage |
| --- | --- | --- | ---: | --- |
| `0x1004e8c0` | `d3dx_jpeg_natural_order` | `jpeg_natural_order[DCTSIZE2+16=80]` | 320 | external |
| `0x1004ef90` | `d3dx_zlib_crc_table` | `crc_table[256]` | 1024 | static |
| `0x1004f6e0` | `d3dx_zlib_inflate_border` | `border 19 initialized uInt elements` | 76 | static |
| `0x1004f868` | `d3dx_zlib_cplens` | `cplens[31]` | 124 | static |
| `0x1004f8e8` | `d3dx_zlib_cplext` | `cplext[31]` | 124 | static |
| `0x1004f968` | `d3dx_zlib_cpdist` | `cpdist[30]` | 120 | static |
| `0x1004f9e0` | `d3dx_zlib_cpdext` | `cpdext[30]` | 120 | static |
| `0x10050550` | `grim_jpeg_natural_order` | `jpeg_natural_order[DCTSIZE2+16=80]` | 320 | external |
| `0x10050a24` | `zlib_extra_literal_bits` | `extra_lbits[LENGTH_CODES=29]` | 116 | static |
| `0x10050a98` | `zlib_extra_distance_bits` | `extra_dbits[D_CODES=30]` | 120 | static |
| `0x10050b5c` | `zlib_bit_length_order` | `bl_order[BL_CODES=19]` | 19 | static |
| `0x10050b70` | `zlib_static_literal_tree` | `trees.h static_ltree[L_CODES+2=288] ct_data records` | 1152 | static |
| `0x10050ff0` | `zlib_static_distance_tree` | `trees.h static_dtree[D_CODES=30] ct_data records` | 120 | static |
| `0x10051068` | `zlib_distance_code` | `trees.h _dist_code[DIST_CODE_LEN=512]` | 512 | external |
| `0x10051268` | `zlib_length_code` | `trees.h _length_code[MAX_MATCH-MIN_MATCH+1=256]` | 256 | external |
| `0x10051368` | `zlib_base_length` | `trees.h base_length[LENGTH_CODES=29]` | 116 | static |
| `0x100513dc` | `zlib_base_distance` | `trees.h base_dist[D_CODES=30]` | 120 | static |
| `0x10051454` | `zlib_inflate_border` | `border 19 initialized uInt elements` | 76 | static |
| `0x100514d0` | `zlib_cplens` | `cplens[31]` | 124 | static |
| `0x1005154c` | `zlib_cplext` | `cplext[31]` | 124 | static |
| `0x100515c8` | `zlib_cpdist` | `cpdist[30]` | 120 | static |
| `0x10051640` | `zlib_cpdext` | `cpdext[30]` | 120 | static |
| `0x10055f18` | `d3dx_zlib_fixed_literal_bits` | `inffixed.h fixed_bl scalar` | 4 | static |
| `0x10055f1c` | `d3dx_zlib_fixed_distance_bits` | `inffixed.h fixed_bd scalar` | 4 | static |
| `0x10055f20` | `d3dx_zlib_fixed_literal_tree` | `inffixed.h fixed_tl 512 inflate_huft records` | 4096 | static |
| `0x10056f20` | `d3dx_zlib_fixed_distance_tree` | `inffixed.h fixed_td 32 inflate_huft records` | 256 | static |
| `0x10057020` | `d3dx_zlib_inflate_mask` | `inflate_mask[17]` | 68 | external |
| `0x10058410` | `zlib_fixed_literal_bits` | `inffixed.h fixed_bl scalar` | 4 | static |
| `0x10058414` | `zlib_fixed_distance_bits` | `inffixed.h fixed_bd scalar` | 4 | static |
| `0x10058418` | `zlib_fixed_literal_tree` | `inffixed.h fixed_tl 512 inflate_huft records` | 4096 | static |
| `0x10059418` | `zlib_fixed_distance_tree` | `inffixed.h fixed_td 32 inflate_huft records` | 256 | static |
| `0x10059608` | `zlib_inflate_mask` | `inflate_mask[17]` | 68 | external |

## Scope of the gain

This work establishes data bounds, ownership, and exact initializers. It does not
claim a new function match, a new original translation unit, or runtime parity.
The remaining mapped labels without independent extents and the remaining
unassigned section bytes stay visible in `analysis/decomp/data-inventory.json`.

## Reproduction

```sh
.venv/bin/pytest -q tests/test_match_data_report.py
.venv/bin/crimson match provenance --check
.venv/bin/crimson native audit --image grim.dll --require-game-closure
.venv/bin/crimson native link --image grim.dll
.venv/bin/crimson native verify --require-game-closure
.venv/bin/crimson match report --refresh -j 8
.venv/bin/crimson match checkpoint --base 2e9dd0590 -j 8
```

## Validation results

Against `2e9dd0590`:

- Source-compiled data: **312,613 → 326,792 / 517,738 bytes** (63.1192%).
- Source-built data candidates: **197 → 229**; the additions are 26 static and six external objects.
- Mapped objects without independent extents: **130 → 98**.
- Bytes outside recorded object extents: **114,229 → 100,050**.
- Library-owned data: **27,299 → 41,478 bytes**; unknown ownership:
  **143,170 → 128,991 bytes**. Game-owned data stays at 347,269 bytes.
- All 2,437 full-report function rows retain their metrics, identities, extents,
  instruction counts, reference checks, and encoded-body results. Only 652
  rebuilt candidate-object hashes differ. No function-evidence field other than
  that hash changed.
- Game/engine scope remains **793/810 normalized exact**, **791/810 encoded-body
  exact**, with all 810 candidates present. Public source-only code credit stays
  **1,265/2,437 functions**, **354,464/718,801 bytes**; archive proofs are excluded
  from that credit.
- Both native audits preserve game-owned closure, with no function debt or hard
  duplicates: EXE 671 functions / 570 objects / 28 clusters; Grim 139 functions /
  132 objects / four clusters. Grim now has 384 fully specified mapped data objects.
- Both structural links rebuild successfully with zero retained placeholders:
  EXE 612 inputs (10 configured placeholders discarded); Grim 167 inputs
  (no configured placeholders). These are structural link results, with no
  runtime-parity claim.
- 156 focused tests pass. All 98 provenance checks, Ruff, type checks, import
  contracts, and documentation checks pass. The checkpoint against `2e9dd0590`
  has zero regression, scope, claim, evaluation, metadata, experiment,
  strict-experiment, and native errors.

Runtime behavior of the structurally linked images has not been tested here.
