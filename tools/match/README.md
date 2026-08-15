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
being a separately linked plain-C JAZ decoder copy. The confirmed `d3dx8.lib`
contains namespaced, byte-distinct entry bodies elsewhere in Grim.

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

Current PE evidence identifies a VC6-family final link for both images, with
compiler records inherited from several input providers:

- The PE optional-header linker version is `6.0`, and the Rich header records
  product 4 (`Linker600`) build 8447. Product 25 build 9210 is `Implib700`
  input metadata, not the final linker.
- Products 10 and 11 are the `Utc12_C` and `Utc12_CPP` object-producer IDs.
  They are one compiler-pipeline stamp per object, not separate C1/C1XX
  frontend records paired with a second C2 record. The executable contains
  137 product-10/build-9782 C records and 34 product-11/build-9782 C++
  records, consistent with VC6 SP6-generated objects.
- Products 28 and 29 are `Utc13_C` and `Utc13_CPP`. Build 9178 is the
  VC7-generation `c2.dll` 13.00.9178 shipped in the Windows XP DDK 5.1.2600,
  paired with the 13.00.9176 frontend and 7.00.9210 tool family. These records
  are not a hidden VC6 backend companion to the build-9782 objects.
- controlled Processor Pack compiles instead stamp C and C++ objects as
  product 48 and 49 with build 9044. A stock VC6 link preserves those distinct
  records, and neither occurs in `crimsonland.exe`.
- the image has a 2011-02-01 PE timestamp, so this looks like an old-code
  toolchain used for a later packaged or relinked binary. The timestamp alone
  does not prove that a relink occurred.

The Rich headers also contain import-library and static-object records, so do
not treat every C/C++ product record as game-code compiler provenance. In
particular, the pinned VC6 SP6 `msvcrt.lib` contains product 10/11 build-8047
members. A structural Grim relink through that archive reproduces the
reference's exact product-4/build-8047 count of 2 and
product-11/build-8047 count of 2. Grim's aggregate 8047 records therefore do
not prove that any engine translation unit used an 8047 frontend.

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
Some archives, including the local `msvc7.0` profile, do not carry a complete
Platform SDK. The repository's `third_party/headers/` fallbacks therefore
provide the Win32 declarations used by the corpus and preserve both C vtable
declarations and C++ COM inheritance. The focused matcher test compiles that
surface, including inherited Direct3D calls, with the sparse profile.

### XP DDK build-9178 attribution control

The exact DirectX 8.1 `d3dx8.lib` already pinned by this repository carries
134 product-29/build-9178 C++ members, one product-28/build-9178 C member, one
older product-28/build-8685 member, and one product-18/build-8444 assembly
member. Its code and relocations match the native D3DX ranges in both images.
The large `Utc13` population is therefore established provider ancestry; it
does not imply that Grim2D or game source was partially migrated to VC7.

The preserved Windows XP DDK 5.1.2600 media was verified locally. The outer
archive SHA-512 is
`9a71263f003382d8713dbd02b0185e201b2e460e975bc611cbe1f2d708bf3fb0903666d5f84577ec63c063398e7023d2da3f9b2b829f5ac0fdd297f2f97eaf13`;
the contained ISO SHA-512 is
`2ed5128aeda9b4708523d1f93b3e26d20a00b22531da7530c4eac22b61ec94440c54661b55e657097c9c0ce740c972c332b3958d2ede2e04305047f7494f5cac`.
Its own `X86DBINS.INF` maps the following phase files:

| file | version | MD5 |
| --- | ---: | --- |
| `cl.exe` | 13.00.9176 | `63d33681a8ea99f3d9a871cfdf5f0e02` |
| `c1.dll` | 13.00.9176 | `71a08ff8448e990e5dd65f16488e1935` |
| `c1xx.dll` | 13.00.9176 | `ee48a14b0757d5a39d587058d2bdd4ae` |
| `c2.dll` | 13.00.9178 | `d8388fb47144f176f1a4f808100b4da4` |
| `link.exe` | 7.00.9210 | `0f614a5fafdf36a155fe83989189e1e4` |
| `ml.exe` | 7.00.9210 | `78aac4b5784393fbb4a4b51d1a02d231` |

The ignored local profile is named `msvc7.0ddk`; the older `msvc7.0` profile
actually reports 13.10.3077 and is only a VC7.1 code-generation surrogate.
Only the compiler-phase binaries above are claimed exact. The profile reuses
the matcher's reconstruction-header surface, with a private `minwindef.h`
shadow that spells 64-bit integers as `__int64` for CL 13.00; it is not a claim
that the game's complete original DDK/SDK include environment was recovered.
Replaying the four source reconstructions that had isolated build-9178
scheduling debt makes all four exact under `msvc7.0ddk /O1 /G6`: the
Floyd-Steinberg mapper, component-color selector, and both quantizer pass
initializers reproduce 1,285 bytes and 453 instructions with all 19 references
resolved. Their canonical scratches remain bound to the original archive
members, which is stronger provenance than a recompile.

A complete compiler scan of the current 61 game-owned WIPs produced zero exact
or improved build-9178 profiles and zero evaluation errors. Do not sweep or
promote `msvc7.0ddk` for the port scope without new object-local evidence;
retain `msvc6.5 /O2 /GB` as the game-code search profile.

### Grim build-8047 attribution control

The published decomp.me VC6 inventory and every compiler bundle available in
the local Crimson/Snail Mail workspaces were fingerprinted from the version
strings embedded in `C1XX.DLL` and `C2.DLL`:

| profile | C++ frontend | optimizer |
| --- | ---: | ---: |
| `msvc6.0` | 8168 | 8168 |
| `msvc6.3` | 8472 | 8447 |
| `msvc6.4` | 8867 | 8799 |
| `msvc6.5` | 8964 | 8966 |
| `msvc6.5pp` | 8964 | 9044 |
| `msvc6.6` | 9782 | 9782 |

None contains an 8047 frontend or optimizer. An additional compile with the
authentic June 1998 Visual Studio 6 Enterprise RTM media
`VSE600ENU1.ISO` (SHA-256
`a670cfb0a5ba6c89c2aa32fd884f21fa348e72cad9d4378b63d08e9da1708f15`)
stamps a C++ object as `@comp.id=0x000b1fe8`, or build 8168, confirming
that 8047 is not the RTM frontend under a different profile name. The two
otherwise-uninstalled published archives checked here were `msvc6.3.tar.gz`
at SHA-256
`84f73e718b3671bfd5de3b7764622b07633b572ee826ca3b77602d224c128608`
and `msvc6.4.tar.gz` at SHA-256
`6d4ef930390ca7481ae5b63ea3bf00d62e0993cd95f1d6f42ba06bb30f993c57`.
Do not substitute 8168 or another nearby build and label the result 8047.

The pinned VC6 SP6 `msvcrt.lib` explains why 8047 appears without such a
compiler bundle. Its COFF members contain 3 product-4, 26 product-10, and
4 product-11 records with build 8047. The current structural Grim relink,
which resolves the DLL's CRT seam through that archive, carries 2 product-4,
1 product-10, and 2 product-11 build-8047 records. The product-4 and
product-11 counts exactly equal the reference image, while the partial
product-10 reproduction is sufficient to falsify the inference that the
aggregate C record count belongs to engine code.

Corpus-wide controls also reject a hidden SP6 backend split. Across the current
137-function Grim corpus, the available 8966 and 9782 optimizers produce
`0` wins, `0` losses, and `137` ties: both report 131 exact functions,
14,938 exact bytes, six WIPs, 20,800.513 fuzzy-weighted bytes, and total
reference debt 1. Across all 671 executable scratches the same comparison is
also byte-for-byte tied: 561 exact functions, 115,403 exact bytes, 110 WIPs,
282,305.057 fuzzy-weighted bytes, and reference debt 103.

Do not spend matching time searching for an 8047 game compiler unless new
object-local evidence separates an engine translation unit from the confirmed
import-library contribution. Rich-header aggregate counts alone are provider
ancestry, not a compiler-selection target.

### 2003 MOD SDK calibration oracle

The separately published `Crimsonland MOD SDK 1.0` release is useful as a
bounded source-style oracle. `analysis/mod_sdk_provenance.json` pins the
2003-08-14 archive, public API and type headers, example sources, Visual Studio
project recipes, and shipped example DLLs without vendoring the SDK. Validate a
directory or the original ZIP and replay its calibrated exports with:

```sh
uv run crimson match mod-sdk --sdk /path/to/cl_mod_sdk_v1 --check
uv run crimson match mod-sdk --sdk /path/to/cl_mod_sdk_v1.zip --check --json
uv run crimson match sdk-oracle --sdk /path/to/cl_mod_sdk_v1.zip --check
```

If the original package is no longer local, retrieve the pinned capture from
the Internet Archive URL recorded as `package.archive.archived_url` in the
manifest. An extracted `cl_mod_sdk_v1/` at the repository root is ignored by
Git and is the first default source checked by both commands.

The replay compiles each example `DllMain.cpp` with its release `/MT /W3 /GX
/O2` code-generation flags under `msvc6.5pp`, verifies the resulting COFF
producer record as product 49/build 9044, and requires normalized-instruction
identity for `CMOD_GetMod` and `CMOD_GetInfo` in both shipped DLLs. The release
recipe's `/YX` and `/FD` PCH/program-database flags are omitted because they do
not describe code generation; the resulting exported functions nevertheless
reproduce exactly. The DLL Rich records independently carry build 9044 and the
VC6 linker build 8447.

Use the pinned `ClMod.h`, `cltypes.h`, and `r_roks.cpp` for exact contemporary
API declarations and the developer's `vec2_t`, `mat3_t`, color, expression, and
local-lifetime idioms. This does **not** make the SDK source for game internals
or make build 9044 provenance for `crimsonland.exe`; the game's owned C/C++
records remain build 9782. Linux ports and the remake use different engines and
are not source-shape oracles for this target.

The separate `sdk-oracle` lane compiles the untouched `r_roks.cpp`, selects
only its externally defined `?r...` functions, and searches executable DLL
sections with relocation-masked object fingerprints. Unique linked caller
xrefs disambiguate identical record/play helper bodies. The pinned specimen
maps all 25 externally defined `r_roks.cpp` functions (14,548 bytes and 3,911
instructions) back to `cl_crimsonroks.dll` at normalized instruction identity;
CRT and compiler-generated helpers are excluded by construction. The separate
`DllMain.cpp` export calibration remains part of `mod-sdk`. These measurements
are calibration evidence only and never contribute to the 1.9.93 game matching
score or `STATUS.md`.

Treat SDK idioms as hypotheses, not target semantics. The first bounded
transfer to `projectile_spawn` tested the exact MOD helpers' last-entry pool
sentinel against the game's one-past bound. The SDK sentinel preserves the
headline normalized ratio but loses the audited pool-end reference, while the
one-past `for` spelling used by exact game allocators is byte-identical to the
current candidate. Keep the stronger target and exact-neighbor evidence when
the two lineages disagree.

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
AUTO_INLINE_OFF=select_ncolors,create_colorindex
REFERENCE_ALIASES='$E2:widget_idle_color_destroy,$E3:widget_hover_color_destroy'
RECOVERY=semantic-complete
RESIDUAL=compiler
```

Only the fields shown above plus `NOTE` are accepted; misspelled or malformed
assignments fail immediately instead of silently falling back to defaults.

An exact historical provider object can be used without recompiling source:

```sh
FUNCTION=provider_function
ARCHIVE=../../../native/providers/build/provider/provider.lib
ARCHIVE_MEMBER='objf\i386\provider.obj'
ARCHIVE_SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SYMBOL='?decorated_provider_symbol@@YGXXZ'
# Choose at most one explicit aggregate boundary:
ARCHIVE_EXTENT=section-tail
# ARCHIVE_END_SYMBOL='?next_entry@@YAXXZ'
# ARCHIVE_SIZE=9
```

Archive scratches are provenance-bound alternatives to source scratches:
`ARCHIVE_SHA256`, `ARCHIVE_MEMBER`, and `SYMBOL` are mandatory, `SOURCE` is
forbidden, and the extracted member still passes the ordinary instruction and
reference audit. This promotes an exact pinned-library match into checkpoints
without treating a whole archive or an ambiguous member hit as recovered code.
`ARCHIVE_EXTENT=section-tail` is optional and covers assembler objects whose
public entry symbol is followed by COFF-local function labels that Binary Ninja,
IDA, or Ghidra recover as one linked function. The archive scanner considers
this larger extent only for external entry symbols and records it explicitly in
generated configs; ordinary compiled functions continue to use the default
single-symbol extent. Pass `--object-extent section-tail` to the low-level
`match diff` or `match dump` commands when inspecting one of these objects
without a scratch config.
`ARCHIVE_END_SYMBOL` instead selects an explicit exclusive code-symbol
boundary in the same COFF section. It is useful when callable entry labels sit
inside one aggregate assembler routine; it cannot be combined with a
non-default `ARCHIVE_EXTENT`. The low-level equivalent is
`--object-end-symbol`.
`ARCHIVE_SIZE` supplies a positive byte size for a proven COFF code label whose
object does not encode a function extent. It is mutually exclusive with both
`ARCHIVE_END_SYMBOL` and a non-default `ARCHIVE_EXTENT`; the low-level
equivalent is `--object-size`.

Scan an established provider range and materialize only unambiguous matches:

```sh
uv run crimson match archive path/to/provider.lib \
  --start 0x00460000 --end 0x00468000 --missing-scratches \
  --expected-sha256 <sha256> --write-scratches \
  --write-reference-aliases \
  --scratch-note-prefix provider-release
```

Writing requires both the pinned digest and `--missing-scratches`, never
overwrites an existing directory, and defaults to archive-member-unique hits.
Pass `--write-symbol-unique` only when duplicate matching members expose the
same function symbol; the generated scratch still has to pass the normal
reference audit before it counts as exact. `--write-reference-aliases` adds
only zero-addend relocations that align with an already unique function, data,
or import name in the target catalog; unknown addresses and conflicting
inferences remain unresolved.

Use `--show-reference-bindings` to list still-unresolved object symbols that
consistently align with one image base address. The report normalizes COFF
addends before rejecting conflicting bases and includes occurrence, addend,
function, and archive-member evidence. It is read-only so a newly discovered
CRT global still has to be named in the data map before generated aliases can
consume it; automatic alias generation remains restricted to zero-addend
evidence.

`REFERENCE_ALIASES` is reserved for proven object-local compiler symbols whose
names are reused across translation units. Each comma-separated
`object-symbol:image-symbol` pair scopes that candidate symbol to one uniquely
named native address; normal masked-reference auditing still compares the
resolved address.

`AUTO_INLINE_OFF` is a comma-separated list of line-leading function names.
For source scratches, the compiler staging step wraps each named definition in
MSVC `auto_inline(off)` / `auto_inline(on)` pragmas without changing the
canonical source file. Use it only when native disassembly proves that a helper
survived as a call while neighboring helpers from the same translation unit
were inlined. Archive scratches cannot use this setting.

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
mismatch region. For non-exact scratches it also aligns conservative basic-
block anchors and reports reordered exact blocks, structurally compatible
similar blocks, unmatched blocks, and conflicting paired edges. This CFG view
is diagnostic only and never contributes to the exact-match score.

## Parallel Matching Batches

The coordinator evaluates the corpus once, ranks the requested targets by
remaining fuzzy gap, and creates deterministic disjoint claims:

```sh
batch_dir=/tmp/crimson-match-batch
uv run crimson match shard --workers 4 \
  --min-bytes 32 --limit 24 --out "$batch_dir"
```

Sharding requires a clean repository so pre-existing edits cannot be mistaken
for worker output.

By default, sharding first includes missing targets plus scratches whose
recovery is `incomplete` or `unspecified`. If that recovery queue is empty, it
automatically switches to semantic-complete residual work instead of emitting
an empty plan. Use an explicit mode to pin either queue:

```sh
uv run crimson match shard --mode recovery --workers 4 \
  --min-bytes 32 --limit 24 --out "$batch_dir"
uv run crimson match shard --mode residual-audit --workers 4 \
  --min-bytes 32 --limit 24 --out "$batch_dir"
```

Residual-audit mode defaults to `--state wip,audit` and
`--recovery semantic-complete`. Explicit `--state` or `--recovery` values
override either mode's defaults and disable the automatic fallback.

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

Before recording `falsified` or `blocked` for a source-shape or compiler
residual, complete the [local-minimum escape protocol](#escaping-local-match-minima)
and put its residual card in the scratch notes. A collapsed aggregate score or
several non-improving single-site sweeps are not sufficient evidence of a wall.

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

Checkpoint rejects duplicate scratch targets, contradictory recovery/residual
metadata, a stale or malformed plan, scratch changes outside all claims,
evaluation failures, current experiment evaluation errors, stale native audit
artifacts, and whitespace errors. Because ownership is measured from the
pinned base commit, the same check also covers worker commits if a coordinator
chooses to integrate them directly.

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
uv run crimson match status --summary-only --check --fresh -j 8
```

Use `--fresh` for a periodic independent audit. It bypasses both compiled-object
and matcher-result caches, rebuilds every selected scratch, and then applies the
normal exact-reference and metadata checks. Ordinary recovery work should keep
the cached path; the fresh run is intentionally much slower.

The generated board also ranks the non-exact residual frontier by fuzzy-gap
bytes. Its experiment evidence is tied to the current scratch epoch:
`current-stalled` requires at least three complete, error-free, non-improving
sweeps against the current inputs, while `historical-only` means the recorded
search belongs to an older source, configuration, dependency, or binary
baseline. Never treat a historical `stalled` flag as a reason to skip fresh
source analysis. Recovery and residual labels describe the current assessment;
they are not proof that every source shape or compiler lifetime has been tried.

Use address-keyed triage to rank both scratch-backed and still-uncovered native
functions. Triage resolves scratch `FUNCTION` values through the manifest and
joins by `(image, address)`, so a raw-address scratch or stale recovered name
cannot create a false missing-function report.

```sh
uv run crimson match triage --image crimsonland.exe \
  --state missing,wip --min-bytes 32 --sort fuzzy-gap --limit 30
uv run crimson match triage --state wip --sort unexplored --limit 30
uv run crimson match triage --image crimsonland.exe --summary-only
uv run crimson match triage --image crimsonland.exe --state missing --json
```

The `search` column is `experiment records/unique variants`; `streak` counts
consecutive non-improving mutation sweeps, and `flags` carries experiment-log
signals such as `stalled`, repeated variants, tradeoffs, or evaluation errors.
`--sort unexplored` puts the least-tested targets first, then favors the larger
remaining fuzzy gap, so residual work does not repeatedly reopen saturated
compiler-scheduling boundaries.

All matcher `--json` modes keep the rendering stack lazy and write only the
JSON document to stdout, so their output can be piped directly to tools such as
`jq`.

Probe a source-shape experiment without editing the tracked scratch. The
baseline and shadow build use the same selected compiler profile, and the
report shows deltas for fuzzy bytes, instruction count, prefix, and references.
When fuzzy bytes improve or remain tied while reference debt,
resolved-reference coverage, prefix, first mismatch, or instruction-count
shape regresses, the report labels the result with explicit tradeoff warnings.
This matters because relocation masking can leave the headline score unchanged
even when a candidate names the wrong native target.

```sh
uv run crimson match probe tools/match/scratches/player_update \
  --source /tmp/player_update_variant.cpp --label scalar-entry-copy
uv run crimson match probe tools/match/scratches/player_update \
  --stdin --json < /tmp/player_update_variant.cpp
```

Pass `--record` to append the complete result, source SHA-256, canonical
baseline epoch, profile, label, and timestamp to `experiments.jsonl` in the
scratch directory. The epoch hashes the source/build inputs, target evidence,
curated reference maps, and a versioned baseline scheme. Recording is explicit;
ordinary probes leave both the scratch and repository untouched.

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

When one replacement only compiles with another, encode that relationship on
the replacement instead of knowingly scheduling invalid variants. `requires`
and `conflicts` contain `site/replacement` keys; constrained combinations are
excluded from both the plan and its possible-variant count:

```json
{
  "name": "reuse-shared",
  "text": "return shared",
  "requires": ["owner/declare-shared"],
  "conflicts": ["qualifier/make-const"]
}
```

```sh
uv run crimson match mutate tools/match/scratches/player_update \
  --spec /tmp/player-update-mutations.json --jobs 8 --top 20
uv run crimson match mutate tools/match/scratches/player_update \
  --spec /tmp/player-update-mutations.json \
  --max-changes 2 --max-variants 128 --time-budget 120 \
  --stop-on-improvement --record --json
```

By default the plan mutates the configured scratch source. Pass `--source`
when the recovered implementation lives in a scratch-local header or under
`tools/match/include`; the selected file is shadowed ahead of the canonical
include roots while the configured translation unit remains unchanged:

```sh
uv run crimson match mutate tools/match/scratches/config_init_defaults \
  --spec tools/match/scratches/config_init_defaults/saved-name-loop-lifetime-mutations.json \
  --source tools/match/include/crimson_config_defaults_impl.h --record
```

Recorded sweeps include the absolute `mutation_source` so include-backed
experiments remain distinguishable from ordinary top-level-source sweeps.

Every variant builds in an isolated temporary scratch and is ranked by the
canonical match score, exact/reference-clean state, prefix, and instruction
shape. Time budgets are soft: the current batch finishes, then no more variants
are scheduled. Reports show evaluated/planned/possible coverage at each
mutation depth and call out interaction combinations that were never
evaluated. Ranked candidates also show movement of the first native mismatch
byte offset. This ordering selects a safe canonical winner; it is not a search
completeness proof. A globally degrading variant can still be the strongest
diagnostic result when it makes one native region exact or reveals a consistent
whole-function register or stack-slot recoloring.

Pass `--record` to append one `kind=mutation-sweep` entry containing the full
evaluated result set, spec SHA-256, coverage, scores, and improving winner to
the scratch's `experiments.jsonl`. `--top` limits display only, not the recorded
evidence. As with probe recording, do not run concurrent recording commands
against the same scratch.

Summarize the append-only experiment corpus before scheduling more sweeps:

```sh
uv run crimson match experiments --sort no-improvement --limit 20
uv run crimson match experiments --sort errors --limit 20
uv run crimson match experiments --scratch player_update --json --check
uv run crimson match experiments --check --strict --limit 1
```

The summary counts improving, byte-neutral, degrading, and evaluation-error
variants separately, along with repeated source/profile evaluations, repeated
specs, exact winners, metric tradeoffs, and each scratch's trailing
no-improvement streak. Current and historical records are reported separately;
legacy records without an epoch remain useful history but cannot mark the live
scratch as stalled. Sorting by `errors` surfaces plans whose intended complete
variants may need an authoring audit instead of treating a failed compile as
negative matching evidence. `stalled` means at least three consecutive,
complete, error-free, current-baseline mutation sweeps since the last improving
sweep. Truncated or errored sweeps are inconclusive and break that streak. It is
a prompt to change or falsify the current hypothesis, not a claim that the
function is unmatchable. `--check` rejects malformed or internally inconsistent
JSONL; `--strict` also rejects current-baseline evaluation errors.

After manually confirming that compile failures came from an invalid mutation
plan (for example, a replacement used a local that its plan never declared),
append a digest-bound audit rather than deleting or rewriting the sweep:

```sh
uv run crimson match experiment-audit tools/match/scratches/player_update \
  --record 12 --reason "replacement referenced an undeclared local"
```

The audited variants remain visible as errors and keep the sweep inconclusive,
but no longer fail `experiments --strict`. Never use this for compiler,
environment, or unexplained evaluation failures; repair and rerun those instead.

The same command accepts an errored probe record when the failure is traced to
an invalid probe-only source shape, such as an include path that cannot exist in
the shadow build. It appends a separate digest-bound `probe-error-audit`; the
failed probe remains visible, but no longer poisons strict validation after the
source error has been corrected and the intended probe rerun successfully.

The tracked scratch is never edited.
`--write-best /tmp/winner.cpp` writes a candidate only when it beats the
baseline without increasing reference debt, regressing the exact prefix or
first mismatch, or moving the instruction count farther from native. Higher or
byte-neutral fuzzy-scoring tradeoffs remain ranked and recorded with warnings
but are never selected as the retained winner. Combine `--write-best` with
`--require-improvement` in scripted searches.

### Escaping Local Match Minima

The exact-match score is the acceptance criterion, not the only search signal.
Do not treat `winner=null`, `best_improves=false`, a prefix regression, or a
large fuzzy-score drop as negative evidence until the assembly difference is
classified. VC register allocation can change across an entire function while
the mutated source makes the intended loop or block byte-exact.

Before describing a residual as a compiler wall, backend choice, saturated
search, or stalled target, record this compact residual card in the scratch's
`NOTES.md`:

```text
Residual signature
- target/candidate instructions and CFG/control shape:
- target/candidate stack-frame allocation:
- references ok/unresolved/mismatched:
- consistent register or stack-slot mappings:
- regions made exact by globally neutral or degrading variants:
- conclusions and the source/profile assumptions held fixed for each:
- untested lifetime, expression, and repeated-site interactions:
```

Then apply this escape protocol:

1. Inspect regions and assembly before pruning by score. If instruction counts
   and control shape agree, look for a consistent operand substitution such as
   two stack homes being exchanged across every aligned loop.
2. Keep native facts separate from source explanations. Write "shared counters
   separate these spills under the current row-value spelling," not "shared
   counters are required."
3. Preserve diagnostic regressions. A variant that makes the target region
   exact is a seed for the next experiment even when an allocator change makes
   earlier regions worse. The conservative `--write-best` refusal is not a
   reason to discard that source.
4. When native code repeats one pattern, create one mutation site per homologous
   source region. Propagate a promising lifetime or expression change across
   every site and test interactions, not only the region containing the first
   mismatch.
5. For at most five binary sites, exhaust the full non-empty power set (31
   variants) with `--max-changes` covering every site. Do not rely on
   single-site hill climbing: allocator thresholds often require several
   individually neutral or degrading changes before the stack coloring flips.
6. Split coupled hypotheses into independent axes. At minimum test outer-counter
   lifetime, inner-counter lifetime, cursor lifetime, and hoisted versus direct
   invariant expressions separately before crossing them.
7. After repeated non-improving sweeps, explicitly negate the two strongest
   conclusions inherited from earlier notes. A negative sweep closes only the
   tested source/profile Cartesian product; list the fixed and untested axes.

`grim_state_init` is the reference case. A native-looking final atlas cursor
fell to 64.71%, but retained the 425-instruction control shape; aligned assembly
showed that the outer and inner conversion spills had exchanged stack homes.
Keeping the outer `y` shared, making only the final inner column local, and
writing the row value directly from `y` made that tail byte-exact while the
whole-function score remained only 97.18%. Propagating the same lifetime and
expression shape across the five homologous atlas loops and evaluating all 31
combinations produced four exact variants. See
[`grim_state_init/NOTES.md`](scratches/grim_state_init/NOTES.md#exact-atlas-counter-lifetime-recovery).

This case demonstrates the required evidence boundary: a collapsed score can
hide a native control shape, a locally exact regression can identify the causal
source lifetime, and an apparent local residual can require a coherent
whole-function interaction sweep.

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

Scan every canonical WIP across the installed compiler corpus when a backend
split is a live hypothesis:

```sh
uv run crimson match compiler-scan --scope port --state wip \
  --compiler msvc6.0 --compiler msvc6.5 --compiler msvc6.5pp \
  --compiler msvc6.6 --check
```

The scan keeps each scratch's canonical flags, compiles selected profiles in
parallel, and prints only exact or improved leads by default; pass `--all` to
include ties. Its summary still counts every selected target and evaluation.
Set `DISPROVEN_COMPILERS=compiler-a,compiler-b` in `scratch.conf` when object or
image provenance rules those profiles out. Corpus scans skip those evaluations
by default; pass `--include-disproven` to revisit them as source-shape evidence.
An alternate compiler win is deliberately labeled search evidence rather than
provenance: confirm the image's PE/Rich records or object-local COFF/archive
evidence before changing a canonical `COMPILER` value.
Use `--json` when scanning experimental or cross-generation profiles such as
MSVC 7; failed evaluations are returned individually in `evaluation_errors`,
and `--check` deliberately fails if any requested profile cannot compile.

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
changing a scratch. `match inspect` also reports the target and candidate
prologue allocation once, with their signed delta. Treat that as a root-cause
clue: one frame-size difference can shift every later stack operand and must
not be counted as dozens of independent missing locals.

CFG edge consistency is evaluated only through unique exact block anchors.
Predecessor counts never turn otherwise duplicate instruction blocks into
unique anchors: that can cross-pair repeated loop latches merely because their
surrounding incoming edges differ. Unique exact pairs also have to be within 5%
normalized block-order distance and belong to a monotonic backbone before edge
validation trusts them; exact but distant or reordered pairs remain visible
without anchoring an unrelated successor. The text report therefore prints
`anchors=` separately from `exact=`; only the former contributes to the
anchored edge-conflict count.
Duplicate exact, displaced exact, and similar blocks are still shown, but their
edge results are reported separately as heuristic conflicts instead of
inflating the anchored edge-conflict count in switch-heavy or multi-pass
functions.

Generate the selected VC compiler's mixed source/machine listing when a
residual looks like source-line scheduling, stack-slot reuse, or an x87/local
lifetime boundary:

```sh
uv run crimson match listing tools/match/scratches/player_update
uv run crimson match listing tools/match/scratches/projectile_update \
  --output /tmp/projectile_update.cod --json
```

The command recompiles with `/FAsc` in an isolated directory and refuses to
publish the listing unless the extracted object function, including
relocations, equals the canonical build. The adjacent JSON records both object
hashes, the function hash, source-line spans, machine offsets, prologue
allocation, and the compiler listing's named/generated stack aliases. The
stack summary counts distinct and reused offsets so allocation pressure is
visible without pretending every alias is a distinct local. These spans and
symbols describe how the selected compiler scheduled the reconstructed source;
they do not recover original local names or prove native variable lifetimes.
Use them alongside the CFG anchors and live native stack/data-flow evidence.

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

Audit recovered identities whose current presentation still exposes analyzer
placeholders, semantic `j_*` names, or redundant address suffixes in canonical
names, scratch directories, curated function/data aliases, reference aliases,
or notes:

```sh
uv run crimson match naming-audit --summary-only
uv run crimson match naming-audit --suggested-only --image crimsonland.exe
uv run crimson match naming-audit --provider-member d3dxmath.obj --apply-suggestions
uv run crimson match naming-audit --provider-member d3dxmathsse.obj,d3dxmathsse2.obj --apply-suggestions
uv run crimson match naming-audit --provider-member d3dxmath.obj --prune-placeholder-aliases
uv run crimson match naming-audit --rewrite-placeholder-references
uv run crimson match naming-audit --repair-provider-comments
uv run crimson match naming-audit --json --check
uv run crimson match resolved-name-audit --check
uv run crimson match resolved-name-audit --rewrite
```

Suggestions are intentionally narrow. The command proposes a canonical name
when another exact scratch for the same hash-pinned archive and COFF symbol
already has one unique non-placeholder identity. The address-keyed
`tools/match/naming_hints.json` ledger may also supply a canonical name,
presentation comment, and concise evidence string for an exact recovery whose
identity comes from binary context rather than a provider symbol. Hint/provider
conflicts are rejected instead of silently choosing one. Recognized DirectX 8.1 D3DX
base and optimized helpers may also derive canonical `d3dx_init_*`,
`d3dx_c_*`, `d3dx_sse*_*`, or `d3dx_x86_*` names directly from their exact
decorated COFF symbols, including the `$$1` implementation suffix. Exact
`CD3DXCodec_<FORMAT>::Encode` symbols similarly derive `d3dx_pixel_encode_*`
identities. Pinned `CD3DXImage::Load*`, `CD3DXFile` methods, and
D3DX-namespaced IJG/libpng entry points derive the corresponding
`d3dx_image_*`, `d3dx_file_*`, `d3dx_jpeg_*`, and `d3dx_png_*` identities.
Exact IJG 6a source recoveries use `grim_jaz_jpeg_*` so their plain C symbols
do not collide with the separate D3DX-namespaced copy. Pinned VC6
`intrncvt.obj` and `sbheap.obj` symbols derive their `crt_*` helper identities,
while `cprintf.obj` locals receive a `crt_printf_*` context prefix. Weak raw
linkage names from hash-pinned VC6 runtime objects are normalized to readable
`crt_*` identities. Selected decorated symbols from the VC6 exception-runtime
objects receive explicit canonicals while retaining their full decorated
linkage aliases. This also reports
`provider-name-conflict` when an older semantic name is meaningful but weaker
than that exact identity, and `provider-directory-conflict` when only the
scratch directory still carries the superseded identity. Real
decorated/linkage symbols remain useful aliases;
generated names such as `FUN_*`, `sub_*`, and `unknown_libname_*` are naming
debt once a stronger identity is proven.
`--apply-suggestions` updates canonical map rows, exact scratch `FUNCTION`
assignments, scratch reference aliases, and matching-scope disposition names
together. While the former identities are still known, it rewrites unambiguous
semantic and analyzer-name references across maintained analysis, source,
documentation, scripts, and matching notes. Decorated linkage symbols remain
intact. It removes superseded analyzer aliases and gives a renamed scratch an
image prefix when the canonical directory is already occupied by the
cross-image provider peer.
`--prune-placeholder-aliases` removes only the generated aliases reported on
the selected function and data rows; decorated provider and linkage aliases
are retained. Curated-map aliases are audited even when no exact scratch owns
the row, so resolved `DAT_*`, `LAB_*`, and address-derived table labels cannot
hide outside the exact scratch corpus. Curated comments are checked for stale
`DAT_*`, `FUN_*`, `LAB_*`, `PTR_*`, `sub_*`, switch/case/table labels,
`unknown_libname_*`, and `nullsub_*` references too.
`--rewrite-placeholder-references` replaces an analyzer target only when its
encoded address or unique raw identity resolves to one non-placeholder name in
the curated map. It updates every scratch for that image which uses the audited
target while leaving decorated object/linkage symbols untouched.
`--repair-provider-comments` restores the exact source or linkage symbol when
an older bulk rename rewrote an auto-generated provider comment to the new
canonical identity.

`resolved-name-audit` is the repository-wide companion to the scratch/map
audit. It scans maintained analysis, Zig, documentation, source, scripts,
matching notes, and native data initializers for analyzer identities whose
address already has a stronger curated identity. This includes semantic raw
function names, not only address-derived labels. Raw analyzer exports, native
build artifacts, experiment logs, and genuinely unresolved address-named
fields are excluded, while vtable slots such as a stale `nullsub_*` are checked
against their explicit target address. `--rewrite` replaces unambiguous labels
with their curated identity; when that identity is already present on the line,
it keeps the useful address as a plain hexadecimal literal instead of repeating
the name. Ambiguous multi-name addresses remain reported for manual review. The
same check runs as a pre-commit gate whenever maintained maps, documentation,
source, scripts, or tools change.

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

Assembler-local constants are compared by exact operand-width bytes only when
the COFF symbol is static and lives in a non-writable `.rdata` section. This
proves archive objects that name private SIMD/MMX constant pools without
treating mutable data with coincidentally equal initial contents as equivalent.

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

Decorated C++ aliases are resolved by their complete symbol before falling
back to a short display name. This keeps same-named methods on different
classes, such as surface and volume `Lock` helpers, distinct during the
reference audit.

VC6 exception-chain references against the absolute `__except_list` symbol are
resolved to the linked `fs:[0]` operand. Compiler-local frame-handler labels are
accepted only when the matcher proves the full handler graph: thunk to
`__CxxFrameHandler`, the 28-byte VC6 FuncInfo fields, unwind-map entry, and
cleanup funclet. Recognized cleanup shapes either call scalar `operator delete`
or tail-jump to the same base destructor directly referenced by the protected
function. The unwind-map record may be linked before or after FuncInfo.

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
