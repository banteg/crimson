---
tags:
  - status-analysis
---

# Native linking

Function matching proves individual recovered translation units against
reference instruction streams. It does not prove that those objects close
over symbols, share a compatible ABI, or can reproduce a PE image. The native
linker track makes those remaining obligations explicit.

## Image audits

Both `grim.dll` and `crimsonland.exe` have native audit tracks. Their active
port scopes have one canonical scratch for every owned function. Isolated
one-function translation units remain the default so pooling, inlining,
constructor ordering, and static symbol changes cannot disturb established
evidence.

The executable has three explicitly modeled exceptions in
`tools/native/translation_units/crimsonland.exe.json`. VC6 generates each
quest, bonus, or perk metadata array's initializer, registrar, and finalizer
as four COFF-local functions in the translation unit that owns the global
array. Compiling those functions separately turns the registrar's local
finalizer relocation into a false external game-function dependency. The
translation-unit config binds the four recovered native functions to their
actual `$E4/$E1/$E3/$E2` members and includes the physical object once.

Every configured member is still compared independently with its reference
function using the canonical scratch boundaries. The audit rejects a cluster
that lowers the byte ratio or adds unresolved or mismatched references. This
is source-provenance modeling, not a linker alias: the object retains the
compiler-generated local symbols and local relocations.

The Grim configuration also models three proven source islands. The JAZ island
combines its contiguous constructor, zlib-status helper, allocation method,
and payload method in native address order under one `/GX /MD` provider. Each
member remains an exact match against its isolated baseline, and the combined
COFF object internalizes the helper-to-method calls without changing the
function inventory.

Grim has one explicit link-time exception in
`tools/native/linker_aliases/grim.dll.json`. Both native cleanup calls in
`grim_decode_jaz_texture` pass the decode-scope address in `ecx` and branch to
the selected one-byte `grim_noop` function. The audit verifies those direct
call instructions in the pinned DLL, the exact `_grim_noop` object definition
at the recorded target address, and the decoder's exact decorated destructor
reference. It then emits a deterministic i386 COFF weak-external alias object
for `GrimJazDecodeScope::~GrimJazDecodeScope -> _grim_noop`. No destructor body
is invented and the canonical noop retains its recovered identity.

Generate the checked-in reports:

```bash
just native-audit grim.dll
just native-audit crimsonland.exe
```

The equivalent direct command is:

```bash
uv run crimson native audit \
  --image grim.dll \
  --scope port \
  --out-dir analysis/native/grim.dll
```

The command compiles the canonical scratch set with each scratch's recorded
VC6 profile, forcing an isolated rebuild rather than accepting cached object
provenance. It compiles the Grim ABI assertion unit, parses the resulting i386
COFF objects, and writes:

- an address-ordered canonical object manifest and link list;
- a `.def` file mapping the reference export name and ordinal to its decorated
  object symbol;
- exact decorated symbol definitions and references;
- strong duplicate and COMDAT/coalescible definition inventories;
- linker directives and requested default libraries;
- explicit weak-external linker aliases and their evidence;
- reference PE exports and imports;
- unresolved symbols classified as owned functions, excluded functions, game
  data, imports, known toolchain support, or unclassified external
  dependencies;
- an evidence-limited data manifest.

All JSON is stable, sorted, free of timestamps and absolute paths, and hashes
its material inputs. VC6's COFF `TimeDateStamp` is explicitly zeroed for
object hashing; clean rebuilds otherwise retain the same content hash. The
compiler-bundle fingerprint covers the material `Bin` and `Include` trees,
not unrelated SDK or library directories. A shared audit digest detects
mixed-generation JSON, and component hashes cover the object list and export
definition. The report never adds fake providers.

The shared semantic `name_map.json` and `data_map.json` inputs use a canonical
per-image JSON projection. The name map contains callable entry points only;
arrays, scalar globals, sentinels, and function-pointer variables belong in
the data map. An edit to Grim-only rows therefore invalidates the
Grim audit without needlessly rebuilding Crimsonland, while edits to shared
top-level data-map metadata still invalidate both images. Older audit records
without projection metadata retain their full-file hash behavior.

`objects.json` distinguishes `function_count` from physical `object_count`.
Each physical row has a `functions` array; ordinary rows contain one binding,
while an explicit cluster contains every independently validated member. The
link list contains each physical object exactly once.

The executable audit keeps any remaining closure debt explicit:
same-display-name definitions with incompatible decorated linkage are not
treated as resolutions, absent definitions remain visible, and repeated
non-COMDAT `.bss` owners remain hard duplicates. The modeled metadata
lifecycle clusters close the executable's current game-function debt without
weakening those rules.

Known compiler helpers are classified as toolchain references. CRT entry
points are stricter: `_sscanf`, for example, is classified as toolchain only
when its referencing object requests a recognized VC6 CRT default library.
The closure row records that library evidence; without it, the symbol remains
an unclassified external and blocks game-owned closure.

## Closure gates

The first native-link victory is all game-owned symbols resolving, not
whole-PE byte identity.

The report separates three gates:

1. `function_closure`: no unresolved in-scope game functions, no duplicate
   strong definitions, and every reference export has an unambiguous mapping.
2. `game_owned_closure`: function closure plus no unresolved mapped game data
   or unclassified external symbols.
3. `all_references_closed`: no unresolved COFF reference of any category.

Use `--require-game-closure` when the second gate is expected to pass. It exits
with status 1 while honest game-data debt remains; malformed inputs or build
failures exit with status 2.

CI verifies the checked-in artifacts for both images with:

```bash
just native-verify --require-game-closure --allow-absent-toolchain
```

This recomputes the shared audit digest, checks the companion hashes and every
available recorded input, and enforces both game-owned closure claims without
requiring a proprietary compiler bundle on the CI runner. The exception is
narrow: only absent ignored files below `tools/match/bin/` or
`tools/match/compilers/` are permitted. If those files are present, their
recorded hashes are still checked; all tracked sources, configs, catalogs,
definitions, reference binaries, and generated companions remain mandatory.

## Structural Grim link

Grim is the first image with a checked-in provider boundary. Once its
game-owned closure gate passes, run:

```bash
just native-link grim.dll
```

`tools/native/providers/grim.dll.json` must cover the unresolved-symbol set
exactly. It distinguishes 20 exports that the reference PE really imports
from `MSVCRT.dll`, `USER32.dll`, `WINMM.dll`, and `d3d8.dll`. The original
VC6 SP6 `MSVCRT.LIB` now supplies 15 of those imports plus the exact
`atonexit.obj` runtime adapter and `dllsupp.obj` toolchain absolutes: 18
closure symbols total. The original DirectX 8.1 `d3dx8.lib` supplies another
six closure symbols, including byte-proven aliases from the recovered
`d3dx_copy_texture_filtered` name to the archive's
`D3DXComputeNormalMap` and from `jpeg_std_error` to the archive's namespaced
IJG body. Deterministic VC6 builds from the pinned IJG 6a and zlib 1.1.3
sources supply eight more closure symbols. Five closure imports still use
generated import libraries, and 16 host-replaced symbols remain explicit
placeholders.

The D3DX archive also needs 24 decorated platform symbols while the linker
selects and prunes its members. These are modeled as `link-dependency`
providers, not counted as closure coverage. `/OPT:REF` retains 17 imports in
the output and discards seven unused edges, including `FindResourceW`; every
retained output import is required to exist in the pinned reference PE table.
Every provider group cites repository evidence.

All provider archives are ignored inputs pinned by size and SHA-256 to
`analysis/library_provenance.json`. Extract the proprietary historical
archives and rebuild the open-source codec archives at their configured paths
before linking:

```bash
mkdir -p tools/native/providers/build/vc6-sp6
cabextract -F vc98/lib/msvcrt.lib \
  -d tools/native/providers/build/vc6-sp6 \
  /path/to/VS6sp61.cab

mkdir -p tools/native/providers/build/directx-8.1
unzip -j /path/to/DX81SDK_FULL.exe \
  DXF/DXSDK/lib/d3dx8.lib \
  -d tools/native/providers/build/directx-8.1

uv run python scripts/build_native_codec_providers.py \
  --jpeg-tar /path/to/jpegsrc.v6a.tar.gz \
  --zlib-tar /path/to/zlib-1.1.3.tar.gz
```

The codec recipe verifies its pinned source and tool hashes, applies IJG's
documented one-byte Windows `boolean` ABI, normalizes archive and COFF
timestamps, and requires exact matches for 18 libjpeg functions plus zlib's
`uncompress` entry before publishing either archive.

The link command rebuilds the canonical audit, rejects archive drift,
synthesizes the five remaining closure imports and 24 D3DX link dependencies
with the recorded VC6 tools, emits deterministic weak COFF aliases where
compiler decoration differs from the reference export name, and creates an
explicitly labeled per-symbol COMDAT placeholder COFF object for the remaining
providers. It
then invokes the VC6 release linker with the recovered entry point, image
base, export definition, and dead-code elimination. It verifies all 20
configured closure exports plus the complete output import-table subset
against the reference image. It writes
`analysis/native/grim.dll/link/link.json`; bulk PE, map, library, response,
log, and provider outputs remain ignored. Generated archive, object, PE
header, and PE export-directory timestamps are normalized, so identical
inputs produce the same linked-image hash.

This is a structural linker milestone, not a runnable DLL or a byte-match
claim. `link.json.runnable` stays false while any placeholder COMDAT is
retained. The canonical Grim link proves that all 16 configured placeholders
survive `/OPT:REF`; its closure report also keeps those 16 references
unresolved, so
`all_references_closed` cannot pass merely because a generated stub made the
linker accept the image. Replacing each placeholder group with its actual
provider object is the path from a structural image to a runnable one.

## Structural executable link

The executable uses the same provider boundary, with two important
differences. It is linked as a Windows GUI PE at base `0x00400000`, and its
runtime is the statically linked VC6 SP6 `LIBCMT.LIB` rather than Grim's
`MSVCRT.DLL` seam:

```bash
just native-link crimsonland.exe
```

`tools/native/providers/crimsonland.exe.json` covers the current 97-symbol
non-game closure exactly. The pinned VC6 archive supplies 57 excluded CRT
functions plus `__fltused` and `sscanf`; the pinned DirectX 8.1 archive
supplies `D3DXVec2Normalize`; generated import libraries supply 34 exports
that are present in the reference PE; a deterministic recovered-source archive
supplies the exact registry helpers and the complete legacy DirectX version
island. No closure symbol remains a placeholder.

The recovered-source recipe compiles eight exact all-scope platform functions:
the DirectX wrapper, its DxDiag query, the 2,920-byte file-version fallback,
three version-resource leaves, and the two registry helpers. It rejects any
instruction or reference regression before publishing the normalized archive.
The DxDiag member also carries the two byte-proven GUID definitions from its
original translation unit.

The executable now enters through VC6's authentic `WinMainCRTStartup` member
from `wincrt0.obj`. A deterministic weak alias maps the CRT's `_WinMain@16`
reference to the recovered `_crimsonland_main@16`, so the link exercises the
GUI startup graph instead of selecting the console startup and fabricating a
`_main` shim.

Archive matching proves that the vector-normalization initializer and thunk
are D3DX8's `init_D3DXVec2Normalize` and `_D3DXVec2Normalize@8` in
`d3dxmath.obj`. Recovered callsites now use the original archive identity
directly, so this provider needs no compatibility alias.

The combined archive-backed graph declares 99 transitive symbols. Eighty-seven
map to reference-backed KERNEL32, ADVAPI32, OLE32, OLEAUT32, or VERSION imports,
and two more resolve to `__snprintf` and `_tolower` in the pinned VC6 archive.
The other ten archive imports
(`EnumSystemLocalesA`, `FatalAppExitA`, `GetCurrentThread`, `GetLocaleInfoA`,
`GetLocaleInfoW`, `GetUserDefaultLCID`, `IsValidCodePage`, `IsValidLocale`,
`SetConsoleCtrlHandler`, and `TlsFree`) are absent from the reference import
boundary. They remain explicitly configured as link-only placeholders, but
per-symbol COMDATs let `/OPT:REF` prove that all ten are discarded and do not
survive in the produced PE.

The canonical structural link retains all 87 reference-backed dependencies.
Its 121 output imports are all present in the reference table, including
DSOUND ordinal 11 and OLEAUT32 ordinals 8 and 9. All ten configured
link-only placeholders are discarded, so the CLI reports
`placeholders=0/10 runnable=True`. The resulting PE file is 856,064 bytes with
an 868,352-byte in-memory image, entry RVA `0x4f0de`, i386 machine type,
Windows GUI subsystem, base `0x00400000`, and normalized zero timestamp. The
checked record is
`analysis/native/crimsonland.exe/link/link.json`; the PE, map, response, log,
generated provider libraries, aliases, and placeholder object remain ignored.

## ABI boundary

Each image assertion unit is compiled by the same 32-bit VC6 toolchain before
the audit succeeds. The Grim unit checks the recovered C++ surface's pointer
and scalar widths, configuration-record and interface sizes, vtable extent and
selected slot offsets, default packing, factory signature, and representative
`__thiscall`/variadic member types. The Crimsonland unit checks the common
scalar model, evidence-backed gameplay/UI record sizes and offsets, console
object packing, and the recovered mod API's C++ member-pointer surface.

The recovered C++ interface is the callable authority. Analyzer-oriented C
headers preserve analysis layouts but are not a replacement SDK for native
`__thiscall` dispatch.

## Data boundary

`analysis/ghidra/maps/data_map.json` is a curated symbol map, not yet a
linkable data-definition manifest. The first report preserves every mapped
row and alias and joins its address to the exported reference sections, but it
leaves size, alignment, and initializer bytes unknown unless explicitly
proven. It does not infer extents from adjacent labels or infer zero
initializers from `.data`.

Tracked artifacts and their exact field contract are described in
`analysis/native/README.md`.
