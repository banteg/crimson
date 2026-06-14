# Matching Decompilation

This is the Crimsonland version of the Snail Mail matching-islands workflow:
write a small C/C++ scratch for one native function, compile it with the
original-era MSVC toolchain, then diff normalized x86 assembly against the
function bytes in `game_bins/crimsonland/1.9.93-gog/crimsonland.exe`.

## Toolchain

Current static docs identify both `crimsonland.exe` and `grim.dll` as Visual
Studio 2003 / VC++ 7.1 SP1 builds. decomp.me currently publishes a nearby
`msvc7.0` bundle in `OmniBlade/decomp.me`'s `msvcwin9x` release; this checkout
uses it as the initial calibration profile until we have a VC7.1 bundle or
evidence that another profile wins.

```sh
MSVC_VER=msvc7.0
CFLAGS="/O2 /G6 /W3 /GR-"
```

The flags are a working hypothesis, not a proven global match profile yet.
Keep per-scratch overrides in `scratch.conf` while we calibrate exact coverage.

`tools/match/cl.sh` looks for the compiler in this order:

1. `CRIMSON_MSVC_ROOT` as either a direct compiler root or a parent directory
   containing `$MSVC_VER/`
2. `tools/match/compilers/$MSVC_VER/`
3. a sibling Snail Mail checkout at `../snail-mail/tools/match/compilers/$MSVC_VER/`

Initialize the Wine prefix once with:

```sh
WINEPREFIX="$HOME/.wine-crimson" wineboot -i
```

## Scratch Layout

Create `tools/match/scratches/<function>/` with:

- `scratch.cpp`: candidate implementation
- `scratch.conf`: shell variables consumed by `match.sh`

Minimum config:

```sh
FUNCTION=console_cmd_argc_get
```

Useful optional fields:

```sh
IMAGE=crimsonland.exe
SOURCE=scratch.cpp
SYMBOL=probe
END=0x00401156
COMPILER=msvc7.0
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

Target function extents come from `analysis/ida/raw/<image>/functions.json`.
Pass `END` when the manifest extent includes unrelated code or misses a
hand-curated boundary.

## No Fakematching

A match is useful only when the source is a plausible reconstruction of the
original semantics. The harness rejects inline assembly and naked functions.
Do not use fake externs or dummy relocations to hide constants; relocation
normalization exists only for real native functions and globals.

Record residual mismatches in the scratch directory instead of forcing
byte-shaped source.
