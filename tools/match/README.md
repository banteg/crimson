# Matching Decompilation

This is the Crimsonland version of the Snail Mail matching-islands workflow:
write a small C/C++ scratch for one native function, compile it with the
original-era MSVC toolchain, then diff normalized x86 assembly against the
function bytes in `game_bins/crimsonland/1.9.93-gog/crimsonland.exe` or
`grim.dll`.

## Matching Scope

The default `port` scope is defined in `analysis/matching_scope.json`. It
contains game-owned `crimsonland.exe` logic before `0x00452ef0` and the
Grim2D engine implementation in `grim.dll` before `0x1000a8d0`. It excludes:

- D3DX, CRT, codec, import-thunk, and other bundled library code linked after
  the owned ranges in either image
- individually audited functions marked `third-party` when a library object is
  interleaved inside an owned range, or `platform-replaced` when the port's host
  backend replaces the whole function

Both images' Binary Ninja databases, IDA and Ghidra exports, maps,
annotations, and owned scratches are matching inputs. Pass `--scope all` only
for an explicit consultation outside the port scope. Dispositioned functions
and their existing scratches remain available there as analysis evidence, but
are omitted from default scores, validation, triage, and worker shards.
The IJG 6a decompressor entry cluster at `0x10009a50..0x1000a107` is the first
`third-party` island: it sits between Grim-owned exports and input code despite
coming from the confirmed `d3dx8.lib`.

The address-keyed scope deliberately takes precedence over IDA's `library`
flag, which can change between analysis versions and has produced false
positives inside game code.

Function dispositions are deliberately narrower than subsystem exclusions.
Grim rendering, batching, texture behavior, timing policy, higher-level input
semantics, configuration access, and shared game state remain in `port`.
For example, `grim_config_defaults_init` initializes game-owned player,
key-binding, audio, display, and gameplay defaults and therefore stays a
matching target even though the adjacent Win32 configuration dialogs are
`platform-replaced`. Add `third-party` only with concrete library provenance;
add `platform-replaced` only when call sites and state effects show that a host
engine backend can replace the whole function.

## Toolchain

Current PE evidence points to a VC6-family final link for
`crimsonland.exe`:

- PE optional-header linker version is `6.0`.
- its Rich header contains 137 product-10/build-9782 C records and 34
  product-11/build-9782 C++ records, consistent with the VC6 SP6 code
  generator.
- controlled Processor Pack compiles instead stamp C and C++ objects as
  product 48 and 49 with build 9044. A stock VC6 link preserves those distinct
  records, and neither occurs in `crimsonland.exe`.
- the image has a 2011-02-01 PE timestamp, so this looks like an old-code
  toolchain used for a later packaged/relinked binary.

The Rich headers also contain some VC7-era import-library/static-object records,
so treat that as mixed-library ancestry rather than the primary compiler.
`grim.dll` separately contains C/C++ records from builds 9782 and 8047, proving
an aggregate compiler mixture for that image. It does not establish which
individual Grim functions came from each build.

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

Do not infer object provenance from whichever compiler gives the best score for
one scratch. Alternate compilers change block placement and scheduling in ways
that can compensate for an imperfect source reconstruction. For example, the
earlier Processor Pack match for `perk_select_random` disappeared after spelling
its two rejection-path increments explicitly; the recovered shape is exact with
both `msvc6.5` and `msvc6.6`. A better `msvc6.5pp` score therefore identifies a
source-shape residual, not evidence of a hidden backend split. Keep alternate
profiles in `probe`, `mutate`, or `profiles` experiments rather than as the
canonical compiler for `crimsonland.exe` scratches.

Use `msvc6.5 /O2 /GB` as the global search profile and confirm provenance from
PE, COFF, archive, or other build metadata. `bonus_label_for_entry` is a useful
profile calibration point: it is exact with `msvc6.5` and `msvc6.6`, but not
`msvc6.5pp` or `msvc7.0`, and it rejects `/O1`, `/Od`, and `/Oy-`.

`tools/match/cl.sh` looks for the compiler in this order:

1. `CRIMSON_MSVC_ROOT` as either a direct compiler root or a parent directory
   containing `$MSVC_VER/`
2. `tools/match/compilers/$MSVC_VER/`
3. a sibling Snail Mail checkout at `../snail-mail/tools/match/compilers/$MSVC_VER/`

decomp.me's `msvcwin9x` release has usable `msvc6.5`, `msvc6.5pp`, and
`msvc7.0` archives. The default dashboard profile is `msvc6.5 /O2 /GB`;
alternate archives remain available for controlled shape experiments.

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

Useful optional fields:

```sh
IMAGE=crimsonland.exe
SOURCE=scratch.cpp
SYMBOL=probe
END=0x00401156
COMPILER=msvc6.5
CFLAGS="/O2 /GB /W3 /GR-"
REFERENCE_ALIASES='$E2:widget_idle_color_destroy,$E3:widget_hover_color_destroy'
RECOVERY=semantic-complete
RESIDUAL=compiler
```

`REFERENCE_ALIASES` is reserved for proven object-local compiler symbols whose
names are reused across translation units. Each comma-separated
`object-symbol:image-symbol` pair scopes that candidate symbol to one uniquely
named native address; normal masked-reference auditing still compares the
resolved address.

`RECOVERY` can be `incomplete` or `semantic-complete`. Use the latter when the
port behavior is understood even though byte identity is blocked.
`RESIDUAL` is a comma-separated set of `analysis`, `compiler`, and
`references`. Use `analysis` when the behavior is recovered but a plausible
source shape still needs to be found. These fields keep semantic recovery
separate from source-analysis, compiler, and reference debt; exact matches are
reported as `recovery=exact` automatically.

Run one scratch:

```sh
tools/match/match.sh tools/match/scratches/<function> --regions
```

Inspect one target through the matching state and all three analysis views:

```sh
uv run crimson match inspect player_update
uv run crimson match inspect tools/match/scratches/player_update --binja-live
```

Inspection resolves and evaluates only the selected target's scratch
directories; it does not compile the full corpus. It starts with exact Binary
Ninja commands and can save a bounded live evidence bundle under the ignored
`tools/match/.cache/evidence/` tree. It then reports the address-matched IDA
and Ghidra snapshots, the best scratch, recovery metadata, and a bounded first
mismatch region.

## Parallel Matching Batches

The coordinator evaluates the corpus once, ranks the requested targets by
remaining fuzzy gap, and creates deterministic disjoint claims:

```sh
batch_dir=/tmp/crimson-match-batch
uv run crimson match shard --workers 4 --state missing,wip \
  --min-bytes 32 --limit 24 --out "$batch_dir"
```

Sharding requires a clean repository so pre-existing edits cannot be mistaken
for worker output.

By default, sharding includes missing targets plus scratches whose recovery is
`incomplete` or `unspecified`. Scratches marked `semantic-complete` are omitted
even when they retain a large compiler/reference fuzzy gap. If that recovery
queue is empty, the command exits without writing an inert plan and points at
the separate residual-audit mode:

```sh
uv run crimson match shard --mode residual-audit --workers 4 \
  --min-bytes 32 --limit 24 --out "$batch_dir"
```

Residual-audit mode defaults to `--state wip,audit` and
`--recovery semantic-complete`. Explicit `--state` or `--recovery` values
override either mode's defaults.

`plan.json` pins the batch's starting commit. Each `worker-NN.json` assigns
targets and their only permitted `scratches/<directory>` paths. Existing
scratches retain their current directory; missing targets receive a stable
directory name. Claims are balanced by estimated fuzzy-gap bytes rather than
only target count.

Give every worker a separate worktree based on the pinned commit and its one
claim file:

```sh
git worktree add --detach ../crimson-worker-01 HEAD
cd ../crimson-worker-01
uv run crimson match inspect <claimed-function> --binja-live
uv run crimson match scratch tools/match/scratches/<claimed-directory> --regions
uv run crimson match worker-outcome "$batch_dir/worker-01.json" \
  tools/match/scratches/<claimed-directory> \
  --disposition falsified \
  --summary "Supported profiles preserve the same scheduling residual." \
  --hypothesis "toolchain:VC6 profile split" \
  --evidence "experiments.jsonl: recorded profile matrix"
uv run crimson match worker-check "$batch_dir/worker-01.json" \
  --require-outcome \
  --out "$batch_dir/worker-01-report.json"
```

Workers may edit only the scratch directories in their claim. They must not
regenerate `STATUS.md` or edit shared matcher headers, analysis maps, or
tooling. `worker-check` checks both commits and dirty files since the pinned
base, rejects every path outside the claim, evaluates only claimed scratches
that exist, and emits JSON without touching the dashboard. Add
`--require-handled` when every claimed target is expected to have a scratch
before handoff.

`worker-outcome` appends a batch-scoped record to the scratch's
`outcomes.jsonl`. Valid dispositions are `matched`, `improved`, `falsified`,
and `blocked`; hypotheses use the normalized `analysis`, `references`,
`source-shape`, `toolchain`, or `unknown` categories. The command verifies
`matched` and `improved` claims against the live scratch, while falsified and
blocked outcomes require evidence. `worker-check --require-outcome` rejects
missing, malformed, or stale-batch outcomes.

Keep final integration coordinator-owned. A worker can export an uncommitted
patch, including newly created scratches, with:

```sh
git add -N tools/match/scratches
git diff --binary -- tools/match/scratches > "$batch_dir/worker-01.patch"
```

The coordinator applies the worker patches, performs the only global corpus
evaluation, and creates the batch commit:

```sh
git apply "$batch_dir"/worker-*.patch
uv run crimson match checkpoint --claims "$batch_dir/plan.json"
git add tools/match/scratches tools/match/STATUS.md
git commit -m "feat(match): recover claimed gameplay functions"
```

Checkpoint rejects duplicate scratch targets, a stale or malformed plan,
scratch changes outside all claims, evaluation failures, and whitespace
errors. Because ownership is measured from the pinned base commit, the same
check also covers worker commits if a coordinator chooses to integrate them
directly.

Regenerate and validate the dashboard:

```sh
uv run crimson match checkpoint -j 8
```

The checkpoint rejects duplicate scratch targets and configs outside the port
scope, evaluates the corpus, rewrites `tools/match/STATUS.md`, runs
`git diff --check`, and reports the current scratch change count. Both staged
and unstaged diffs are checked. `just match-checkpoint` is the short form.
The dashboard also summarizes the checked-in native object, closure, and data
manifests. A linker row is marked current only while the three reports share
and reproduce one audit digest, their recorded source, selection, toolchain,
and reference inputs still hash to the live repository, and the generated
`objects.txt` and `exports.def` companions match their recorded hashes;
otherwise it is explicitly labeled stale, missing, or invalid.

Each status row includes fuzzy-weighted bytes and its remaining fuzzy gap in
addition to exact-match state. Keep the canonical Markdown board complete, but
filter the terminal report when investigating a narrower slice:

```sh
uv run crimson match status --image crimsonland.exe --state wip \
  --min-bytes 64 --sort fuzzy-gap --limit 20
uv run crimson match status --summary-only
uv run crimson match status --image crimsonland.exe --json
uv run crimson match status --recovery semantic-complete --residual compiler
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

All matcher `--json` modes keep the rendering stack lazy and write only the
JSON document to stdout, so their output can be piped directly to tools such as
`jq`.

Probe a source-shape experiment without editing the tracked scratch. The
baseline and shadow build use the same selected compiler profile, and the
report shows deltas for fuzzy bytes, instruction count, prefix, and references.
When fuzzy bytes improve while reference debt, resolved-reference coverage,
prefix, first mismatch, or instruction-count shape regresses, the report
labels the result with explicit tradeoff warnings.

```sh
uv run crimson match probe tools/match/scratches/player_update \
  --source /tmp/player_update_variant.cpp --label scalar-entry-copy
uv run crimson match probe tools/match/scratches/player_update \
  --stdin --json < /tmp/player_update_variant.cpp
```

Pass `--record` to append the complete result, source SHA-256, profile, label,
and timestamp to `experiments.jsonl` in the scratch directory. Recording is
explicit; ordinary probes leave both the scratch and repository untouched.

For repeated source-shape experiments, use the bounded mutation harness. A
JSON plan names exact, non-overlapping source spans and plausible replacements:

```json
{
  "schema": 1,
  "sites": [
    {
      "name": "sum-order",
      "find": "entry.x + offset.x",
      "replacements": [
        {"name": "commuted", "text": "offset.x + entry.x"},
        {"name": "parenthesized", "text": "(entry.x + offset.x)"}
      ]
    }
  ]
}
```

The default sweep changes one site at a time. Increase `--max-changes` to test
interactions; `--max-variants` keeps the Cartesian search bounded. Sites must
match exactly once unless they specify a one-based `"occurrence"`. Ambiguous
or overlapping sites fail before compilation. Specs use byte-exact source
spans and should be regenerated or reviewed after reformatting or refactoring
the scratch.

```sh
uv run crimson match mutate tools/match/scratches/player_update \
  --spec /tmp/player-update-mutations.json --jobs 8 --top 20
uv run crimson match mutate tools/match/scratches/player_update \
  --spec /tmp/player-update-mutations.json \
  --max-changes 2 --max-variants 128 --time-budget 120 \
  --stop-on-improvement --record --json
```

Every variant builds in an isolated temporary scratch and is ranked by the
canonical match score, exact/reference-clean state, prefix, and instruction
shape. Time budgets are soft: the current batch finishes, then no more variants
are scheduled. Reports show evaluated/planned/possible coverage at each
mutation depth and call out interaction combinations that were never
evaluated. Ranked candidates also show movement of the first native mismatch
byte offset.

Pass `--record` to append one `kind=mutation-sweep` entry containing the full
evaluated result set, spec SHA-256, coverage, scores, and improving winner to
the scratch's `experiments.jsonl`. `--top` limits display only, not the recorded
evidence. As with probe recording, do not run concurrent recording commands
against the same scratch.

Summarize the append-only experiment corpus before scheduling more sweeps:

```sh
uv run crimson match experiments --sort no-improvement --limit 20
uv run crimson match experiments --scratch player_update --json --check
```

The summary counts improving, byte-neutral, and degrading variants, repeated
source/profile evaluations, repeated specs, exact winners, metric tradeoffs,
and each scratch's trailing no-improvement streak. `stalled` means at least
three recorded mutation sweeps since the last improving sweep; it is a prompt
to change or falsify the current hypothesis, not a claim that the function is
unmatchable. `--check` rejects malformed or internally inconsistent JSONL.

The tracked scratch is never edited.
`--write-best /tmp/winner.cpp` writes a candidate only when it beats the
baseline; combine it with `--require-improvement` in scripted searches.

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

Target function extents come from `analysis/ida/raw/<image>/functions.json`,
then are filtered through `analysis/matching_scope.json`.
The status dashboard reports matched functions out of every manifest function,
matched code bytes as a percentage of every manifest function extent, and then
groups scratch rows under each in-scope image. Pass `END` when the manifest
extent includes unrelated code or misses a hand-curated boundary.

Use `NOTE=smoke` for tiny plumbing checks. Treat compiler-profile calibration as
search evidence, not per-object provenance. Establish toolchain ancestry from
PE/COFF records or identified archive members; for link-sensitive code, check
`/MD` vs `/MT` first.

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

Compiler-local sparse switches are audited by mapping each byte lookup entry
through its companion absolute jump table and comparing the resulting
destination partition. This accepts linker/compiler differences in private
table numbering only when every lookup value still reaches the same
function-local equivalence class.

Inspect exact-score reference debt with:

```sh
uv run crimson match audit --exact-only --status problem
uv run crimson match audit --exact-only --status all --json
```

Use `--all-scores` when investigating references inside partially matching
functions. `crimson match diff` and `crimson match scratch` exit nonzero for
either an instruction mismatch or masked-reference debt.
