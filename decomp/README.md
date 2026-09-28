# Recovered Crimsonland source

This directory holds recovered, project-owned source for every Crimsonland build
we study. It is organised by **build family**: a set of builds close enough to
share function bodies. Tooling, scratch notes and experiments stay under
`tools/match`; each scratch's `SOURCE` points into this tree.

```
decomp/
  builds.json      every known build: package, image pins, compilers, family
  1.9/             family 1.9: builds 1.9.1, 1.9.8, 1.9.9, 1.9.93 (canonical)
    crimsonland/   crimsonland.exe, one directory per inferred translation unit
    grim/          grim.dll, one directory per inferred subsystem
```

Each image tree has a `layout.json` that records how strong the evidence for
its grouping is; the native-link tests validate it.

## Builds

[builds.json](builds.json) pins each build's package and game images (size and
sha256), with the C++ object counts and C2 builds read from each image's Rich
header. `profiles` maps a C2 build to the matcher's compiler profile.

| Build | Linked | Game exe | Game C++ objects | Family |
|---|---|---|---|---|
| 1.0.2 | 2002-05 | `crimson.exe` | 1 (C2 8966) | unassigned |
| 1.3.0 | 2002-07 | `crimson.exe` | 2 (C2 8966) | unassigned |
| 1.4.0 | 2002-09 | `crimson.exe` | 7 (C2 8966) | unassigned |
| 1.9.1 | 2003-06 | `crimsonland.exe` | 23 (C2 8966) | 1.9 |
| 1.9.8 | 2003-08 | `crimsonland.exe` | 24 (C2 9044) | 1.9 |
| 1.9.9 | 2008-10 | `crimsonland.RWG`, unwrapped | 36 (C2 9782, with runtime) | 1.9 |
| 1.9.93 | 2011-02 | `crimsonland.exe` | 34 (C2 9782, with runtime) | 1.9 |

The game grew from one C++ object into two dozen source files, and it never
had a C object: every build before 1.9.9 takes its runtime from an older
compiler build, and none links a C object from the game's compiler. The
freeware builds share their compiler with 1.9.1 but join a family only once
measured function overlap shows they share source.

Two build quirks are recorded in `builds.json`:

- 1.9.8's `grim.dll` is an incremental build. Nine C++ objects were recompiled
  with the Processor Pack (C2 9044), so their functions identify the Grim source
  files that changed after 1.9.1.
- 1.9.9 ships the Reflexive Arcade wrapper as `crimsonland.exe`. The game image is
  `crimsonland.RWG`, whose `.text` is encrypted from just past the entry point to
  the section end. The pinned image is the output of
  [reflexive](https://github.com/banteg/reflexive)'s `extract --unwrap`.

## Differences between builds of a family

Builds in one family share one source. A build differs only by:

- its compiler, from `builds.json`;
- which functions go in which file, in which order;
- real source changes, guarded by `CL_BUILD`.

`CL_BUILD` is `major*10000 + minor*100 + patch` (1.9.8 is 10908, 1.9.93 is
10993). Guards are reconstruction scaffolding, not a claim about the original
source; generated per-build trees resolve them away. Rules:

- Guard only behavioural changes. A body that differs only in code generation
  under another compiler is a spelling constraint, not a source change.
- Guard whole statements or whole functions; guard a struct field once instead
  of every user.
- A guard counts only when every build it claims compiles exactly.

## Scope

Third-party code keeps its upstream or archive provenance and is not presented
here: the VC6 runtime, D3DX, IJG libjpeg, libpng, zlib, Ogg Vorbis, FMOD and
the Reflexive Arcade wrapper.
