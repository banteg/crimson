# Recovered Crimsonland source

This directory holds recovered, project-owned source for every Crimsonland build
we study. It is organised by **build family**: a set of builds close enough to
share function bodies. Tooling, scratch notes and experiments stay under
`tools/match`; each scratch's `SOURCE` points into this tree.

For 1.9.93 it is complete: every one of the 858 game and engine functions in
`crimsonland.exe` and `grim.dll` compiles to the original machine code.

```
decomp/
  builds.json      every known build: package, image pins, compilers, family
  1.9/             family 1.9: builds 1.9.1, 1.9.8, 1.9.9, 1.9.92, 1.9.93 (canonical)
    crimsonland/   crimsonland.exe, one directory per inferred translation unit
    grim/          grim.dll, one directory per inferred subsystem
```

Each image tree has a `layout.json` that records how strong the evidence for
its grouping is; the native-link tests validate it.

## Builds

[builds.json](builds.json) pins each build's package and game images (size and
sha256), with the C++ object counts and C2 builds read from each image's Rich
header. `profiles` maps a C2 build to the matcher's compiler profile.

Each build also names a `tree`: the unpacked, wrapper-free install under
`game_bins/crimsonland/<build>/`, where every pinned image sits at
`<tree>/<name>`. The original packages stay under
`game_bins/crimsonland/historical/`; `uv run scripts/unpack_game_bins.py`
rebuilds the trees from them and checks every image against its pin. 1.9.93 is the GOG install itself, so its tree is
`game_bins/crimsonland/1.9.93-gog`.

| Build | Linked | Game exe | Game C++ objects | Family |
|---|---|---|---|---|
| 1.0.2 | 2002-05 | `crimson.exe` | 1 (C2 8966) | unassigned |
| 1.3.0 | 2002-07 | `crimson.exe` | 2 (C2 8966) | unassigned |
| 1.4.0 | 2002-09 | `crimson.exe` | 7 (C2 8966) | unassigned |
| 1.9.1 | 2003-06 | `crimsonland.exe` | 23 (C2 8966) | 1.9 |
| 1.9.8 | 2003-08 | `crimsonland.exe` | 24 (C2 9044) | 1.9 |
| 1.9.9 | 2008-10 | `crimsonland.RWG`, unwrapped | 36 (C2 9782, with runtime) | 1.9 |
| 1.9.92 | 2009-02 | `crimsonland.RWG`, unwrapped | 36 (C2 9782, with runtime) | 1.9 |
| 1.9.93 | 2011-02 | `crimsonland.exe` | 34 (C2 9782, with runtime) | 1.9 |

The game grew from one C++ object into two dozen source files, and it never
had a C object: every build before 1.9.9 takes its runtime from an older
compiler build, and none links a C object from the game's compiler. The
freeware builds share their compiler with 1.9.1 but little of its code (see
[other builds](#other-builds)), so they belong to no family yet. Their image-level `mapping_source` entries
bootstrap comparisons from 1.9.93 without claiming that the whole source tree
or its layouts describe freeware.

Two build quirks are recorded in `builds.json`:

- 1.9.8's `grim.dll` is an incremental build. Nine C++ objects were recompiled
  with the Processor Pack (C2 9044), so their functions identify the Grim source
  files that changed after 1.9.1.
- 1.9.9 ships the Reflexive Arcade wrapper as `crimsonland.exe`. The game image is
  `crimsonland.RWG`, whose `.text` is encrypted from just past the entry point to
  the section end. The pinned image is the output of
  [reflexive](https://github.com/banteg/reflexive)'s `extract --unwrap`. 1.9.92
  ships the same wrapper, and its pinned image is unwrapped the same way.

## Differences between builds of a family

Builds in one family share one source. A build differs only by:

- its compiler, from `builds.json`;
- which functions go in which file, in which order;
- real source changes, guarded by `CL_BUILD`.

`CL_BUILD` is `major*10000 + minor*100 + patch` (1.9.8 is 10908, 1.9.93 is
10993). A source that tests it includes `cl_build.h`, which defaults it to the
canonical build; the matcher defines it for every other build. Guards are
reconstruction scaffolding, not a claim about the original source; generated
per-build trees resolve them away. Rules:

- Guard only behavioural changes. A body that differs only in code generation
  under another compiler is a spelling constraint, not a source change.
- Guard whole statements or whole functions; guard a struct field once instead
  of every user.
- A guard counts only when every build it claims compiles exactly.

## Other builds

The curated analysis names only the canonical images. `uv run crimson match
build-map` derives maps for every other build with a family or explicit mapping source and writes them to
`analysis/decomp/<build>/<image>/`. Each function row records how it was placed,
strongest first:

- `exact`: the body is identical up to relinking;
- `interface`: every instruction agrees after pairing Grim virtual slots through
  the two DLLs' native vtables and mapped method identities;
- `recovered`: a reviewed native identity and extent pinned in `recovered.json`;
- `referenced`: an operand of an exact body points at it;
- `called`: the same call site of a mapped caller that changed but kept its
  call sequence;
- `ordered`: it sits between mapped neighbours in layout order, at a similar
  size.

`exact`, `interface`, and reviewed `recovered` rows have a pinned extent; the others run to the next
known function. A global is named when every reference to it from these bodies
agrees. Interface mapping is placement and reference evidence, not compiled
match credit; a candidate must still pass the build's own instruction, encoding
and reference checks. Function aliases and colocated object/member names retain
the same proven addresses.

The initial game-code survey (679 canonical functions) found overlap with 1.9.93 as follows:

| Build | Exact | Placed |
|---|---|---|
| 1.0.2 | 17 | 78 |
| 1.3.0 | 21 | 110 |
| 1.4.0 | 58 | 151 |
| 1.9.1 | 429 | 632 |
| 1.9.8 | 361 | 655 |
| 1.9.9 | 622 | 677 |
| 1.9.92 | 647 | 678 |

1.9.8 places more functions than 1.9.1, but the Processor Pack changes enough
code generation that fewer of its bodies are exact.

`--build` compiles a scratch with that build's compiler profile and
`/DCL_BUILD=<n>`, and compares it against that build's image:

```bash
uv run crimson match scratch tools/match/scratches/<name> --build 1.9.8
uv run crimson match probe tools/match/scratches/<name> --build 1.9.8 --source <file>
uv run crimson match build-scan 1.9.8
```

A reference to a global that the build's data map does not name stays
unresolved, so such a function reports `audit`, never `match`.

Builds marked `reported` in `builds.json` (1.9.93 and 1.9.8) are published to
decomp.dev, each from its own evidence; see
[analysis/decomp/README.md](../analysis/decomp/README.md#198).

## Freeware setup

1.0.2, 1.3.0 and 1.4.0 have committed function, global, import and image-metadata
maps for both `crimson.exe` and `grim.dll`. Their actual filenames and image
hashes remain the matching targets. A scratch naming the donor's
`crimsonland.exe` resolves to that build's `crimson.exe`; the comparison uses
its own maps, VC6 `msvc6.5` profile and `CL_BUILD` (10002, 10300 or 10400).

```sh
uv run crimson match builds
uv run crimson match build-map 1.0.2 1.3.0 1.4.0 --check
uv run crimson match build-scan 1.4.0 -j 8
uv run crimson match scratch tools/match/scratches/console_clear_log --build 1.4.0
uv run crimson match probe tools/match/scratches/console_clear_log --build 1.4.0 --source /tmp/candidate.cpp
```

These maps are a starting point for recovering changed bodies, not a complete
inventory of freeware functions. They are not marked `reported`: publishing a
percentage needs an independent native inventory, including functions with no
1.9 counterpart. Placement evidence alone never earns compiled match credit.
The shared source remains under `decomp/1.9`; add a freeware family and its own
layout only once native evidence supports its grouping.

## Scope

Third-party code keeps its upstream or archive provenance and is not presented
here: the VC6 runtime, D3DX, IJG libjpeg, libpng, zlib, Ogg Vorbis, FMOD and
the Reflexive Arcade wrapper.
