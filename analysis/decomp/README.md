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
the full denominator; **Crimsonland EXE**, **Grim2D DLL**, and **Libraries**
filter the same units. Libraries has **D3DX8** and **MSVC6 runtime** subcategories,
using the image/address ranges in `analysis/library_provenance.json`. These
describe established ranges, not an exhaustive attribution of every codec or
runtime function. Explicit third-party dispositions outside those library ranges
appear under **Other identified libraries**. Embedded codecs within D3DX8 remain under D3DX8. Library units
also belong to their image category, so category totals must not be added
together. The treemap filters units rather than drawing nested group rectangles.

The denominator is every function in the curated `--scope all`
inventory of `crimsonland.exe` and `grim.dll`, including embedded libraries,
compiler runtime, original Windows code, and functions without candidates.
Separate dependency DLLs are outside these two target images. The primary
measure is original function code bytes with recognized terminal padding
trimmed, not file size or candidate count. Curated function-boundary fixes may
change the denominator; they invalidate the saved evidence and must be reviewed.

- **Matched:** source-built functions with normalized instruction identity and
  clean reference evidence (`state == "match"`). Available library source
  counts; prebuilt archive members and generated import thunks do not.
- **Fuzzy:** the same source-built candidates' match ratios weighted by original
  code bytes, over the full denominator. A 100% instruction score with reference
  debt is capped at 99.99% for display so the treemap does not paint it as exact.
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
unit. Names are disambiguated by address when necessary; image/address identity
is retained in the evidence. Source links point to the actual candidate file.
This gives a useful function treemap without implying recovered file boundaries.

## Data accounting

The full-image denominator uses the PE virtual extents of `.rdata`, `.data`,
`.data1`, and `.bss` (where present). This includes zero-filled storage and
unattributed gaps, but excludes file-alignment padding, executable sections,
resources, and relocation sections. Mapped switch tables within `.text` are not
counted again as data. For the pinned binaries this is **517,738 bytes**.

`tools/native/data_candidates.json` selects ordinary C++ definitions under
`tools/match/data/`, using types and declarations already present in the matching
headers. The refresh builds them with the pinned VC6 compiler. A generated
verification harness checks every `sizeof` against the independently recorded
native extent, and the report verifies the actual COFF common/BSS/data storage.
Only zero-initialized definitions are supported in this first pass. Their
reference bytes are checked through the existing native-definition loader.
No array bounds, padding, or byte initializers are invented to make a candidate
fit. Overlapping declarations count each original byte only once.

The initial candidate set has **157 definitions covering 267,177 unique bytes**.
Fully specified native data recipes cover more, but copied literal bytes,
pointer tables, incomplete declarations, and uncompiled types remain unmatched
until independently built data candidates exist. In particular, the initial
compiler probe rejected `quest_unlock_index` and `quest_unlock_index_full`
(header `int`, native extent 2), and `player_plaguebearer_active` (header `int`,
native extent 1). Those declarations are excluded from data credit; this report
does not change their existing function-matching sources.

Data units belong to their **EXE/DLL** category and **All**. They are not assigned
to **Game & Engine** or **Libraries**, because the existing ownership ranges
describe code and do not establish a complete data denominator for those
categories. The Game & Engine view therefore remains code-only. Data-only units
have no functions and do not add tiles to the code treemap. Data does not affect
the code/fuzzy percentages, and no linked-data credit is claimed: these source
groupings do not recover the original translation units or final data placement.

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
per-function results, and compiled data evidence. Inputs must stay unchanged
throughout the evaluation.

To verify saved evidence and generate `artifacts/decomp/report.json`:

```sh
uv run crimson match report
```

The `Decompilation progress` workflow runs on pushes to `master` and PRs. It
downloads and checks the two reference images, verifies the evidence against
repository inputs, the complete live function inventory, and reference data
extents, exports objdiff v2
JSON, validates it with the SHA-256-pinned objdiff CLI, and uploads only
`report.json` as `1.9.93_report`. CI does not recompile the corpus; it rejects
stale evidence rather than attaching old scores to a new source revision.
Ignored compiler/archive inputs may be absent in CI, but are checked against
their recorded identities when present locally. No original binaries or
compiler files are included in the uploaded report.

Registration is at [decomp.dev/manage/new](https://decomp.dev/manage/new) after
the first default-branch report upload. Use the full game name `Crimsonland` and
platform `Windows`. The GitHub app is optional; ordinary polling is sufficient.
See the [integration guide](https://decomp.wiki/tools/decomp-dev) and
[objdiff report schema](https://github.com/encounter/objdiff/blob/main/objdiff-core/protos/report.proto).
