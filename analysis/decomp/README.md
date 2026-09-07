# Public decompilation progress

[Crimsonland on decomp.dev](https://decomp.dev/banteg/crimson) tracks the
matching reconstruction of **Crimsonland 1.9.93**, including its **Grim2D**
engine. The original Crimsonland site calls it the "Grim 2D API"; see the
[preserved June 2002 page](https://web.archive.org/web/20020615144308/http://koti.mbnet.fi/temper/crimsonland/)
and the [historical inventory](../historical/koti-mbnet-crimsonland/manifest.json).
The GOG provenance and exact reference hashes remain documented in
[provenance.md](../../docs/contributor/project-tracking/provenance.md).

## Scope and metrics

There is one version (`1.9.93`) and one combined report. **Game & Engine** is
the preferred category and headline, available through
[`?category=game`](https://decomp.dev/banteg/crimson?category=game).
Setting it as the project-wide default requires a decomp.dev maintainer to set
`default_category` to `game`; the current project settings form does not expose
this field. It uses the ownership ranges recorded in
`analysis/matching_scope.json`, retaining original platform code omitted by the
internal `port` workflow and excluding explicit third-party dispositions.
The **All** view keeps
the full curated denominator; **Crimsonland EXE**, **Grim2D DLL**, and **Libraries**
filter the same units. Libraries has **D3DX8** and **MSVC6 runtime** subcategories,
using the image/address ranges in `analysis/library_provenance.json`. These
describe established ranges, not an exhaustive attribution of every codec or
runtime function. Explicit third-party dispositions outside those library ranges
appear under **Other identified libraries**. Embedded codecs within D3DX8 remain under D3DX8. Library units
also belong to their image category, so category totals must not be added
together. **Unclassified ownership** contains functions outside both established
ownership groups: Game & Engine + Libraries + Unclassified ownership equals All
code. Image categories are an independent dimension. The treemap filters units rather than drawing nested group rectangles.

The denominator is every function in the curated `--scope all`
inventory of `crimsonland.exe` and `grim.dll`, including embedded libraries,
compiler runtime, original Windows code, and functions without candidates.
Separate dependency DLLs are outside these two target images. The primary
measure is original function code bytes with recognized terminal padding
trimmed, not file size or candidate count. Curated function-boundary fixes may
change the denominator; they invalidate the saved evidence and must be reviewed.
The saved `code_inventory` reconciles each executable PE virtual section into
retained function ranges and explicitly unresolved gaps, rejecting overlaps and
functions outside executable sections. It does not infer padding or embedded data
from adjacency: those classification totals remain zero until independently
justified. Thus All measures curated code, not a completeness proof of native-code
identification. File-alignment bytes outside virtual extents are excluded.

- **Matched:** source-built functions with normalized instruction identity and
  clean positional reference evidence and complete compared-byte coverage. Available library source
  counts; prebuilt archive members and generated import thunks do not.
- **Fuzzy:** the same source-built candidates' match ratios weighted by original
  code bytes, over the full denominator. A 100% instruction score with reference
  debt is capped at 99.99% for display so the treemap does not paint it as exact.
- **Encoded body:** source-built normalized matches whose instruction encodings
  also match after audited relocation treatment. Exposed separately in
  `report.metrics.json`, with byte and function totals; it does not redefine the
  historical objdiff matched series. Local relative relocations are resolved,
  audited external relocation fields are masked, and recognized terminal padding
  is excluded. This proves neither final data placement nor whole-image identity.
- **Linked:** currently zero. The bespoke structural linker uses provider and
  alias machinery and does not establish recovery of the original translation
  units and code organization. Its receipts give no public linked credit.
- **Data:** source-built definitions verified against the original data bytes,
  reported separately from code. See the data accounting below. Native data-map
  records and generated linker data objects do not automatically earn credit.

Pinned archive matches are valuable dependency-identification evidence, but
decomp.dev labels its headline "decompiled". They remain in the denominator at
zero public progress. The internal full-scope matcher still reports those
matches. The internal `port` dashboard and `body_byte_exact` diagnostic are
unchanged.

Each report unit represents one function, not a recovered original translation
unit. Unit names use recovered names for readable decomp.dev treemap labels;
duplicates include image/address suffixes. Function keys and our evidence/delta
tooling retain stable `image/address` identities, with recovered function names
in `demangled_name` metadata. decomp.dev uses unit names for both display and
history identity, so unit renames can still appear as removal and addition there. Source links point to the actual candidate file.
This gives a useful function treemap without implying recovered file boundaries.

## Data accounting

The full-image denominator uses the PE virtual extents of `.rdata`, `.data`,
`.data1`, and `.bss` (where present). This includes zero-filled storage and
unattributed gaps, but excludes file-alignment padding, executable sections,
resources, and relocation sections. Mapped switch tables within `.text` are not
counted again as data. For the pinned binaries this is **517,738 bytes**.

`tools/native/data_candidates.json` selects ordinary C++ definitions under
`tools/match/data/`, using recovered types and declarations. Refresh builds them
with the pinned VC6 compiler. A verification harness checks each `sizeof` against
an independently recorded native extent. The reporter then compares the emitted
COFF common/BSS/data storage with the reference initializer, byte for byte.
Overlapping declarations count each original byte only once.

The current set has **188 definitions covering 304,765 unique bytes**. Alongside
zero-initialized state, it includes the original developer-hint strings, symbolic
hint pointers, the console empty-string pointer, and the typed effect atlas table.
Original text and single-byte encodings are preserved. Array extents and types
come from existing recovery evidence; no padding or byte arrays are introduced
to make a definition fit.

Pointer slots must emit `IMAGE_REL_I386_DIR32` relocations at the recorded offsets,
reference the exact recorded symbols, and have zero addends. A copied numeric
address is rejected even when its final bytes are identical. Grim's PE relocation
directory independently checks the slot layout. The EXE has its relocations
stripped, so its pointer layout relies on the explicit symbolic native definitions.
Literal recipes containing Grim relocations cannot earn credit until they have
symbolic target evidence. Other relocation kinds and nonzero addends remain
unsupported and fail verification.

The compiler rejects `quest_unlock_index` and `quest_unlock_index_full` (header
`int`, native extent 2), and `player_plaguebearer_active` (header `int`, native
extent 1). These exclusions are recorded in the manifest and inventory; their
function-matching declarations are unchanged.

[The data inventory](DATA.md) ranks remaining objects by uncredited bytes and
blocker and lists the largest unnamed regions. Its JSON companion partitions
all 517,738 bytes exactly once. Object opportunities can overlap and must not be
summed; span totals are authoritative. Report refresh regenerates both automatically,
and CI rejects stale inventory output. To regenerate the inventory separately:

```sh
uv run crimson match data-inventory
```

`tools/native/data_ownership.json` records explicit whole-object ownership and
its evidence, independently of whether the object has a compiled match. It
currently attributes 341,469 bytes to Game & Engine and 27,299 to libraries;
148,970 bytes remain unknown. No ownership is inferred from adjacency, code
ranges, or successful matching. All unknown bytes remain in All and EXE/DLL totals.

The existing **Game & Engine** filter stays code-only. **Game & Engine + attributed
data** shows that same code treemap plus the explicitly owned data subset,
including unmatched objects. **Libraries + attributed data** works the same way.
**Unattributed data** exposes the remaining bytes. These subsets do not claim a
complete Game & Engine or library data denominator. Data-only units have no
functions and create no code treemap tiles. Data never changes code/fuzzy
percentages, and no linked-data credit is claimed: source groupings do not recover
original translation units or final data placement.

## Refresh and publish

On a machine with the matching compilers, reference images and pinned archives:

```sh
uv run crimson match report --refresh -j 8
```

This evaluates the complete scratch corpus using the matcher's content-checked
cache, rejects failures, duplicate targets and partial function extents, and
updates `analysis/decomp/1.9.93.json`. Commit that evidence alongside changes to
matching sources, shared headers, maps, toolchain configuration or the reporter.
It records source/input hashes, compiler fingerprints, reference hashes,
per-function results, and compiled data evidence. Schema 3 retains reference
counts, positional audit results, matcher state, compared/excluded/unexplained
ranges, encoded-body results, and candidate-object SHA-256 hashes. Exported match
flags must agree with these fields. Compared extents come from the matcher's
contiguous normalized disassembly (including undecoded `db` suffixes), with its
recognized terminal-padding count removed. A discarded tail cannot receive code
credit. Object hashes are local compilation receipts, not independently rebuilt
objects in CI. Inputs must stay unchanged
throughout the evaluation.

`report.metrics.json` accompanies the objdiff report in a separate CI artifact.
It includes encoded-body credit, unmatched bytes, the largest uncredited functions,
and executable reconciliation. Target hashes, inventory/ownership identity and
scoring implementation/policy identity are recorded independently. To compare
against a previous saved evidence file:

```sh
uv run crimson match report --baseline /path/to/previous-evidence.json
```

The delta reports newly matched and regressed bytes, but labels target, inventory
or scoring changes as a measurement baseline change rather than source progress.
Older schema snapshots establish a new baseline. Renames alone do not change the
native key or inventory identity. Fuzzy similarity is neither semantic recovery
nor an estimate of remaining effort.

To verify saved evidence and generate `artifacts/decomp/report.json`:

```sh
uv run crimson match report
```

The `Decompilation progress` workflow runs on pushes to `master` and PRs. It
downloads and checks the two reference images, verifies the evidence against
repository inputs, the complete live function inventory, and reference data
extents, exports objdiff v2
JSON, validates it with the SHA-256-pinned objdiff CLI, and uploads only
`report.json` as `1.9.93_report`. The verification mode is **source-bound local compilation; CI checks freshness
and report consistency**. Parser acceptance checks format compatibility only.
CI does not recompile the corpus; it rejects
stale evidence rather than attaching old scores to a new source revision.
Ignored compiler/archive inputs may be absent in CI, but are checked against
their recorded identities when present locally. No original binaries or
compiler files are included in the uploaded report.

Registration is at [decomp.dev/manage/new](https://decomp.dev/manage/new) after
the first default-branch report upload. Use the full game name `Crimsonland` and
platform `Windows`. The GitHub app is optional; ordinary polling is sufficient.
See the [integration guide](https://decomp.wiki/tools/decomp-dev) and
[objdiff report schema](https://github.com/encounter/objdiff/blob/main/objdiff-core/protos/report.proto).
