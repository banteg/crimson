# Matching Decompilation

This is the Crimsonland version of the Snail Mail matching-islands workflow:
write a small C/C++ scratch for one native function, compile it with the
original-era MSVC toolchain, then diff normalized x86 assembly against the
function bytes in `game_bins/crimsonland/1.9.93-gog/crimsonland.exe` or
`game_bins/crimsonland/1.9.93-gog/grim.dll`.

## Tracked Images

Track both shipped PE images in the same dashboard:

- `crimsonland.exe`: main game executable
- `grim.dll`: Grim2D engine DLL

Every scratch has an `IMAGE`; it defaults to `crimsonland.exe`. Set
`IMAGE=grim.dll` for Grim2D functions so the harness reads the matching
manifest, metadata, and binary image.

## Toolchain

Current PE evidence points to a VC6-family final link for both
`crimsonland.exe` and `grim.dll`:

- PE optional-header linker version is `6.0`.
- Rich headers include `Linker600` and dominant `Utc12_C` / `Utc12_CPP` object
  counts.
- `grim.dll` imports `MSVCRT.dll`, consistent with a VC6 `/MD` build.
- both images have 2011-02-01 PE timestamps, so this looks like an old-code
  toolchain used for a later packaged/relinked binary.

The Rich headers also contain some VC7-era import-library/static-object records,
so treat that as mixed-library ancestry rather than the primary compiler.

```sh
MSVC_VER=msvc6.5
CFLAGS="/O2 /G6 /W3 /GR-"
NOTE=branch-x87
```

The current ranking is `msvc6.5`, then `msvc6.5pp`, then `msvc6.6`, with
`msvc7.0` kept as a comparison profile. Both `msvc6.5` and `msvc6.5pp` produce
100% matches for the checked-in smoke scratches plus representative
x87/control-flow scratches in both images; the scratches do not distinguish
those two profiles yet. Keep per-scratch overrides in `scratch.conf` while we
calibrate broader coverage.

`tools/match/cl.sh` looks for the compiler in this order:

1. `CRIMSON_MSVC_ROOT` as either a direct compiler root or a parent directory
   containing `$MSVC_VER/`
2. `tools/match/compilers/$MSVC_VER/`
3. a sibling Snail Mail checkout at `../snail-mail/tools/match/compilers/$MSVC_VER/`

decomp.me's `msvcwin9x` release has usable `msvc6.5`, `msvc6.5pp`, and
`msvc7.0` archives. The current dashboard is generated with `msvc6.5`.

Run the compiler through `wibo`. Put `wibo` on `PATH`, set
`WIBO=/path/to/wibo`, or place it at `tools/match/bin/wibo`. On macOS/Apple
Silicon, the `wibo-macos` x86_64 release runs under Rosetta 2. Download the
platform release from the decompals/wibo releases page and make it executable,
for example:

```sh
mkdir -p tools/match/bin
curl -L -o tools/match/bin/wibo \
  https://github.com/decompals/wibo/releases/download/1.1.0/wibo-macos
chmod +x tools/match/bin/wibo
```

## Scratch Layout

Create `tools/match/scratches/<function>/` with:

- `scratch.cpp`: candidate implementation
- `scratch.conf`: shell variables consumed by `match.sh`

Minimum config:

```sh
FUNCTION=console_cmd_argc_get
```

DLL config:

```sh
IMAGE=grim.dll
FUNCTION=grim_get_time_ms
```

Useful optional fields:

```sh
IMAGE=crimsonland.exe
SOURCE=scratch.cpp
SYMBOL=probe
END=0x00401156
COMPILER=msvc6.5
CFLAGS="/O2 /G6 /W3 /GR-"
```

Run one scratch:

```sh
tools/match/match.sh tools/match/scratches/<function> --regions
```

Regenerate the dashboard:

```sh
uv run crimson match status --write tools/match/STATUS.md
```

Compare another compiler profile without editing scratches:

```sh
uv run crimson match status --compiler msvc6.5pp
uv run crimson match status --compiler msvc7.0
```

Target function extents come from `analysis/ida/raw/<image>/functions.json`.
The status dashboard reports matched functions out of every manifest function,
matched code bytes as a percentage of every manifest function extent, and then
groups scratch rows under each tracked image. Pass `END` when the manifest
extent includes unrelated code or misses a hand-curated boundary.

Use `NOTE=smoke` for tiny plumbing checks. Treat compiler/settings calibration
as provisional until it includes broader representative branches, calls, stack
arguments, and x87 code from both images. For link-sensitive code, check `/MD`
vs `/MT` first; `grim.dll`'s `MSVCRT.dll` import makes `/MD` the likely final
link mode.

## No Fakematching

A match is useful only when the source is a plausible reconstruction of the
original semantics. The harness rejects inline assembly and naked functions.
Do not use fake externs or dummy relocations to hide constants; relocation
normalization exists only for real native functions and globals.

Record residual mismatches in the scratch directory instead of forcing
byte-shaped source.
