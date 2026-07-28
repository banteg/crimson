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
from `MSVCRT.dll`, `USER32.dll`, `WINMM.dll`, and `d3d8.dll` from 33 static,
toolchain, or host-replaced symbols that still lack recovered provider
objects. Every group cites repository evidence, and reference-import entries
are checked against the pinned PE import table before linking.

The command rebuilds the canonical audit, synthesizes import libraries with
the recorded VC6 tools, emits an explicitly labeled placeholder COFF object
for the remaining providers, and invokes the VC6 linker with the recovered
entry point, image base, and export definition. It writes
`analysis/native/grim.dll/link/link.json`; bulk PE, map, library, response,
log, and provider outputs remain ignored. Archive, object, PE header, and PE
export-directory timestamps are normalized, so identical inputs produce the
same linked-image hash.

This is a structural linker milestone, not a runnable DLL or a byte-match
claim. `link.json.runnable` stays false while any placeholder symbol remains.
The canonical closure report also keeps those 33 references unresolved, so
`all_references_closed` cannot pass merely because a generated stub made the
linker accept the image. Replacing each placeholder group with its actual
provider object is the path from a structural image to a runnable one.

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
