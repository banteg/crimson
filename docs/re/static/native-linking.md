---
tags:
  - status-analysis
---

# Native linking

Function matching proves individual recovered translation units against
reference instruction streams. It does not prove that those objects close
over symbols, share a compatible ABI, or can reproduce a PE image. The native
linker track makes those remaining obligations explicit.

## Grim pilot

`grim.dll` is the first target. Its active port scope currently has one
canonical scratch for every owned function, and the audit keeps each function
in its own translation unit so pooling, inlining, constructor ordering, and
static symbol changes cannot disturb established evidence.

Generate the checked-in reports:

```bash
just native-audit grim.dll
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

## ABI boundary

The Grim assertion unit is compiled by the same 32-bit VC6 toolchain before
the audit succeeds. It checks the recovered C++ surface's pointer and scalar
widths, configuration-record and interface sizes, vtable extent and selected
slot offsets, default packing, factory signature, and representative
`__thiscall`/variadic member types.

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
