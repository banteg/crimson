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
CFLAGS="/O2 /GB /W3 /GR-"
NOTE=branch-x87
```

The VC6 family and the blended `/GB` CPU schedule are supported by the current
corpus. Switching the whole scratch set from `/G6` to `/GB` preserves every
existing exact match and makes `player_start_reload`, `perk_select_random`, and
`weapon_pick_random_available` exact as well. The reload function is a medium
263-byte, 67-instruction calibration target with calls, stack arguments, x87
operations, branches, and 28 audited references. `/GB` also improves most
larger in-progress scratches.

The compiler backend can still vary by object. `bonus_label_for_entry` is exact
with `msvc6.5` and `msvc6.6`, but not `msvc6.5pp` or `msvc7.0`; it also rejects
`/O1`, `/Od`, and `/Oy-`, supporting speed optimization and frame-pointer
omission. `perk_select_random` instead requires the tested `msvc6.5pp` backend.
Keep evidence-backed compiler overrides in `scratch.conf` while treating
`msvc6.5 /O2 /GB` as the global starting profile.

`tools/match/cl.sh` looks for the compiler in this order:

1. `CRIMSON_MSVC_ROOT` as either a direct compiler root or a parent directory
   containing `$MSVC_VER/`
2. `tools/match/compilers/$MSVC_VER/`
3. a sibling Snail Mail checkout at `../snail-mail/tools/match/compilers/$MSVC_VER/`

decomp.me's `msvcwin9x` release has usable `msvc6.5`, `msvc6.5pp`, and
`msvc7.0` archives. The default dashboard profile is `msvc6.5 /O2 /GB`; some
scratches carry an evidence-backed compiler override.

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
CFLAGS="/O2 /GB /W3 /GR-"
REFERENCE_ALIASES='$E2:widget_idle_color_destroy,$E3:widget_hover_color_destroy'
```

`REFERENCE_ALIASES` is reserved for proven object-local compiler symbols whose
names are reused across translation units. Each comma-separated
`object-symbol:image-symbol` pair scopes that candidate symbol to one uniquely
named native address; normal masked-reference auditing still compares the
resolved address.

Run one scratch:

```sh
tools/match/match.sh tools/match/scratches/<function> --regions
```

Regenerate the dashboard:

```sh
uv run crimson match status --check -j 8 --write tools/match/STATUS.md
```

Each status row includes fuzzy-weighted bytes and its remaining fuzzy gap in
addition to exact-match state. Keep the canonical Markdown board complete, but
filter the terminal report when investigating a narrower slice:

```sh
uv run crimson match status --image crimsonland.exe --state wip \
  --min-bytes 64 --sort fuzzy-gap --limit 20
uv run crimson match status --summary-only
uv run crimson match status --image crimsonland.exe --json
```

Use address-keyed triage to rank both scratch-backed and still-uncovered native
functions. Triage resolves scratch `FUNCTION` values through the manifest and
joins by `(image, address)`, so a raw-address scratch or stale recovered name
cannot create a false missing-function report.

```sh
uv run crimson match triage --image crimsonland.exe \
  --state missing,wip --min-bytes 32 --sort fuzzy-gap --limit 30
uv run crimson match triage --image crimsonland.exe --summary-only
uv run crimson match triage --image crimsonland.exe --state missing --json
```

Probe a source-shape experiment without editing the tracked scratch. The
baseline and shadow build use the same selected compiler profile, and the
report shows deltas for fuzzy bytes, instruction count, prefix, and references.

```sh
uv run crimson match probe tools/match/scratches/player_update \
  --source /tmp/player_update_variant.cpp --label scalar-entry-copy
uv run crimson match probe tools/match/scratches/player_update \
  --stdin --json < /tmp/player_update_variant.cpp
```

Pass `--record` to append the complete result, source SHA-256, profile, label,
and timestamp to `experiments.jsonl` in the scratch directory. Recording is
explicit; ordinary probes leave both the scratch and repository untouched.

Sweep one scratch across installed compilers and one or more flag sets. Options
are repeatable and the result is ranked with exact, reference-clean matches
first:

```sh
uv run crimson match profiles tools/match/scratches/creature_spawn \
  --compiler msvc6.5 --compiler msvc6.5pp --compiler msvc6.6
uv run crimson match profiles tools/match/scratches/creature_spawn \
  --compiler msvc6.5 --cflags "/O2 /GB /W3 /GR-" \
  --cflags "/O2 /G6 /W3 /GR-" --json
```

Localized mismatch regions include normalized instruction spans, native and
candidate byte ranges, native VAs, local fuzzy-weighted bytes, scoped reference
counts, and cautious diagnostic hints:

```sh
tools/match/match.sh tools/match/scratches/player_update \
  --regions --region-context 3 --max-regions 8
uv run crimson match scratch tools/match/scratches/player_update \
  --json --max-regions 8
```

Hints such as `possible-control-flow-shape`,
`possible-x87-lifetime-or-ordering`, and
`possible-stack-frame-or-lifetime` are triage aids, not proof. Use native
decompilation, call/reference evidence, and plausible source shape before
changing a scratch.

The status pipeline caches unchanged results and evaluates stale scratches in
parallel. A cache entry is invalidated by the scratch source/config, compiler
arguments and binary, `cl.sh`, the transitive local-header graph, the target
image and symbol maps, or the matcher itself. This keeps repeat status runs
cheap without allowing stale objects or scores to survive an input change.
Compiler/CFLAGS profiles use separate digest-named build directories, and
objects plus cache metadata are published atomically, so concurrent profile
comparisons cannot overwrite the canonical build.

Compare another compiler profile without editing scratches:

```sh
uv run crimson match status --compiler msvc6.5pp
uv run crimson match status --compiler msvc7.0
uv run crimson match status --cflags "/O2 /G6 /W3 /GR-"
```

Target function extents come from `analysis/ida/raw/<image>/functions.json`.
The status dashboard reports matched functions out of every manifest function,
matched code bytes as a percentage of every manifest function extent, and then
groups scratch rows under each tracked image. Pass `END` when the manifest
extent includes unrelated code or misses a hand-curated boundary.

Use `NOTE=smoke` for tiny plumbing checks. Treat compiler backend calibration
as per-object evidence unless several representative functions establish a
shared profile. For link-sensitive code, check `/MD` vs `/MT` first;
`grim.dll`'s `MSVCRT.dll` import makes `/MD` the likely final link mode.

## No Fakematching

A match is useful only when the source is a plausible reconstruction of the
original semantics. The harness rejects inline assembly and naked functions.
Do not use fake externs or dummy relocations to hide constants; relocation
normalization exists only for real native functions and globals.

Record residual mismatches in the scratch directory instead of forcing
byte-shaped source.

## Exact Matches and Masked References

Instruction normalization replaces relocated and in-image addresses with
`ADDR`, but an `ADDR` token is not proof that the operands refer to the same
thing. The matcher retains the hidden reference on both sides and audits it
against function symbols, the per-image IDA import manifest,
`analysis/ghidra/maps/data_map.json`, exact resolved base-plus-addend addresses,
and compiler-generated constant contents.

A scratch is `match` only when its normalized instruction score is 100% and
all aligned masked references are proven equal. A 100% instruction score with
unresolved or different references is `audit`, so it is excluded from matched
function and byte totals. The `refs` column is `ok/unresolved/mismatch`.

The function manifest is overlaid by exact program/address entries from
`analysis/ghidra/maps/name_map.json`. This lets newly recovered function names
participate in scratch selection and reference auditing immediately, without
waiting for a full IDA artifact regeneration. Curated `aliases` on those
entries also connect decorated C++ constructor and destructor references to
their proven native addresses.

VC6 exception-chain references against the absolute `__except_list` symbol are
resolved to the linked `fs:[0]` operand. Compiler-local frame-handler labels are
accepted only when the matcher proves the full handler graph: thunk to
`__CxxFrameHandler`, FuncInfo fields, unwind-map entry, cleanup funclet stack
offset, and call to scalar `operator delete`.

Inspect exact-score reference debt with:

```sh
uv run crimson match audit --exact-only --status problem
uv run crimson match audit --exact-only --status all --json
```

Use `--all-scores` when investigating references inside partially matching
functions. `crimson match diff` and `crimson match scratch` exit nonzero for
either an instruction mismatch or masked-reference debt.
