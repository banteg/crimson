# Public decompilation progress

[Crimsonland on decomp.dev](https://decomp.dev/banteg/crimson) tracks the
matching reconstruction of **Crimsonland 1.9.93**, including its **Grim2D**
engine. The original Crimsonland site calls it the "Grim 2D API"; see the
[preserved June 2002 page](https://web.archive.org/web/20020615144308/http://koti.mbnet.fi/temper/crimsonland/)
and the [historical inventory](../historical/koti-mbnet-crimsonland/manifest.json).
The GOG provenance and exact reference hashes remain documented in
[provenance.md](../../docs/contributor/project-tracking/provenance.md).

1.9.93's **Game & Engine** category is complete: 858/858 functions and
360,094/360,094 code bytes are matched, every one also an encoded-body match.
Libraries, unclassified functions, data and linking are measured separately
below.

## Scope and metrics

Five versions are reported, each from its own saved evidence: `1.9.93`, the
canonical build described below, `1.9.8` (see [1.9.8](#198)), and freeware
`1.0.2`, `1.3.0`, `1.4.0` (see [Freeware](#freeware)). Builds
marked `reported` in [decomp/builds.json](../../decomp/builds.json) are
published. **Game & Engine** is the preferred category and headline, available through
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
- **Linked:** verified source components linked at original virtual addresses,
  with exact final bytes, section permissions and symbolic/base relocations.
  The first component is Grim's four slot-state accessors and their two backing
  arrays (64 code bytes and 1,024 data bytes). Zero-filled reservations earn no
  credit. The broader structural linker still earns no public linked credit.
  This establishes component placement, not whole-image or file-layout identity.
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

The [generated inventory](DATA.md) gives the current unique matched-byte totals.
Alongside zero-initialized state, the definitions include the original developer-hint strings, symbolic
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

Native dword accesses establish that `quest_unlock_index` and
`quest_unlock_index_full` are four-byte runtime counters; only serialization
narrows them to 16 bits. Their corrected definitions now compile and match.
`player_plaguebearer_active` is an interior byte of the already matched player
array. Its declaration note remains in the inventory without creating false
unresolved byte debt.

[The data inventory](DATA.md) ranks remaining objects by uncredited bytes and
blocker and lists the largest unnamed regions. It also retains mapped labels
without proven extents in `unbounded_objects`, without guessing their sizes or
ownership. Its JSON companion partitions
all 517,738 bytes exactly once. Object opportunities can overlap and must not be
summed; span totals are authoritative. Report refresh regenerates both automatically,
and CI rejects stale inventory output. To regenerate the inventory separately:

```sh
uv run crimson match data-inventory
```

`tools/native/data_ownership.json` records explicit whole-object ownership and
its evidence, independently of whether the object has a compiled match. It
records attributed and unknown byte totals in the generated inventory.
No ownership is inferred from adjacency, code
ranges, or successful matching. All unknown bytes remain in All and EXE/DLL totals.

The existing **Game & Engine** filter stays code-only. **Game & Engine + attributed
data** shows that same code treemap plus the explicitly owned data subset,
including unmatched objects. **Libraries + attributed data** works the same way.
**Unattributed data** exposes the remaining bytes. These subsets do not claim a
complete Game & Engine or library data denominator. Data-only units have no
functions and create no code treemap tiles. Data never changes code/fuzzy
percentages. Linked data requires a separate reference-layout receipt proving
source-built storage at its original address; a source grouping alone earns none.

## 1.9.8

1.9.8 is measured with the same credit rules, from the same sources, compiled as
1.9.8: the build's compiler profile (the Processor Pack, C2 9044) and
`/DCL_BUILD=10908`. Its `grim.dll` is an incremental build, so each of its
functions takes the better of the build's two profiles. Prebuilt library code
keeps its own toolchain.

Its denominator is the function inventory of its [build map](#other-builds):
every canonical function placed in 1.9.8, with the exact extent of an identical
body or, for a changed one, the extent up to the next known function. Code the
map does not place stays unresolved in the executable reconciliation, as
uncurated gaps do for 1.9.93. Each function takes its categories from its
canonical counterpart. Data is not measured for 1.9.8: omitted data measures mean
unavailable, not a measured 0% or 100%. The CLI and generated summary say
**not measured**. Its code percentages describe the mapped inventory, not every
function in the historical image. The executable reconciliation and summary
retain the unmapped bytes so expanding a sparse map cannot masquerade as source
progress.

A reference counts only when 1.9.8's own maps name its target, so an exact
instruction body whose globals the map does not name yet stays at `audit`.

The shared C++ interface now describes 1.9.8's actual Grim vtable. That build
has two legacy methods at offsets `0x04` and `0x08`, whose semantics remain
unrecovered, and lacks the four later state-slot accessors. These changes shift
different parts of the interface in opposite directions. Slot correspondence
comes from the pinned DLL vtables and their mapped functions. The mapper can
propagate names from native callers whose normalized bodies differ only at
those dispatch offsets; compiled candidates still require the usual complete
instruction and reference checks, with encoding identity measured separately.

Build maps retain decorated function aliases and co-located object/member
names, so source references can resolve without replacing the readable native
names. Function searches and exact placements use decoded code extents with
verified terminal padding excluded. Different alignment padding does not hide
a shared body or extend its comparison into the next function. Grim maps are
generated before EXE maps that consume their interface correspondence.

The 1.9.8 weapon and player layouts are now selected by `CL_BUILD=10908`:
120-byte weapon rows without the later pellet-count member, 0x354-byte player
records without the three later perk timers, and a 64-entry projectile pool.
The Fire Bullets add-on recursively spawns a fire projectile before the
original shot; the canonical build's replacement branch is excluded. The
complete projectile spawner and weapon initializer match their native encoded
bodies, as do the weapon accessor/default constructor and several pool/player
initializers. The large older player/update/render functions remain partial.
See [the comparison](../../docs/re/static/fire-bullets-1.9.8-vs-1.9.93.md).

Reviewed native identities and full extents live beside a build's generated
maps in `recovered.json`. `build-map` verifies their image/body hashes and the
pinned instructions naming data before merging them into the heuristic maps.
A `recovered` placement supplies identity only; complete instruction, reference
and encoded-byte checks still determine compiled match credit.

## Refresh and publish

On a machine with the matching compilers, reference images and pinned archives:

```sh
uv run crimson match report --refresh -j 8
```

This evaluates the complete scratch corpus using the matcher's content-checked
cache, rejects failures, duplicate targets and partial function extents, and
updates `analysis/decomp/<version>.json` for every reported version
(`--version 1.9.8` limits it to one). Commit that evidence alongside changes to
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

The `decomp-report` pre-push hook runs the same saved-evidence verification as
CI when matching or report inputs change. If it reports stale evidence, run
the refresh command above and commit the generated evidence before pushing.
This includes source controls and verifier scripts under `tools/match/evidence/`,
which are part of the recorded input inventory even when canonical scratches
stay unchanged. The hook verifies evidence; it does not regenerate it.

`report.metrics.json` accompanies the objdiff report in a separate CI artifact.
It includes encoded-body credit, unmatched bytes, the largest uncredited functions,
and executable reconciliation. `version` and `data_measured` identify the build
and distinguish absent data evidence from a zero matched-byte count.
`executable_coverage` totals retained code and unresolved executable bytes.
Each scope includes the exact objdiff measures beside its encoded-body totals.
`report.md` summarizes the five chart series, encoded-body credit and executable
coverage in the measurement artifact and GitHub Actions job summary.
Target hashes, inventory/ownership identity and
scoring implementation/policy identity are recorded independently. To compare
against a previous saved evidence file:

```sh
uv run crimson match report --baseline /path/to/previous-evidence.json
```

The delta reports newly matched and regressed bytes, but labels target, inventory
or scoring changes as a measurement baseline change rather than source progress.
For those changes, newly matched/regressed source-byte counts are unavailable
(`null`). The inventory identity includes historical-to-canonical ownership
mapping, data section extents and explicit data ownership, so changes to those
also establish a new baseline.
Compiler identity uses each profile's fingerprint; the scratch path used to
locate that compiler is not part of its identity.
Older schema snapshots establish a new baseline. Renames alone do not change the
native key or inventory identity. Fuzzy similarity is neither semantic recovery
nor an estimate of remaining effort.

To verify saved evidence and generate `artifacts/decomp/<version>/report.json`:

```sh
uv run crimson match report
```

The `Decompilation progress` workflow runs on pushes to `master` and PRs. Its
version matrix is generated from `reported` builds in `decomp/builds.json`, so
new reported versions receive both artifacts and a summary automatically. It
compares to saved evidence from the pre-push commit or PR base when available,
showing measurement changes in the summary instead of source-byte gains.
Manual workflow runs and newly reported versions may have no baseline. It
downloads each reported build's pinned images from the project asset host,
verifies each version's evidence against repository inputs,
its complete live function inventory, and (for 1.9.93) reference data extents,
exports objdiff v2 JSON, validates it with the SHA-256-pinned objdiff CLI, and
uploads each `report.json` as `<version>_report`; decomp.dev lists one version
per artifact. The verification mode is **source-bound local compilation; CI checks freshness
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

## Other builds

`<build>/<image>/` holds the maps that place canonical functions and globals in
another build, derived from its family canonical image or explicit donor by `uv run crimson match build-map`. They
feed `--build` comparisons and the reported builds' inventories; see
[decomp/README.md](../../decomp/README.md#other-builds).


## Freeware

Each freeware image has an independent `native.json` inventory. Its image and
basic-block byte hashes, donor-map digest, analyzer version, verified starts,
and reviewed ownership boundaries are pinned. Unmapped native functions remain
in the reports; names from donor maps are identities, not the denominator.

The executable sections are partitioned without overlapping byte owners.
Verified unchanged bodies define physical extents; independent native starts
bound other function prefixes. Shared/interior entry points remain in the raw
discovery inventory. Every byte outside a retained function is an explicitly
uncredited executable remainder. These include uncertain alignment/embedded
data and stay in both All and the applicable native ownership scope. Gap units
are not counted as functions. Compilation uses these retained extents and
rejects partial coverage before awarding source credit.

The inventory policy is `native-functions-and-full-executable-remainder-v1`;
it is deliberately conservative and differs from 1.9's curated-functions
policy. The All code denominator equals the full executable virtual byte count.
`Confirmed Game & Engine` covers the reviewed initial application and engine
clusters, while uncertain template/SDK helpers stay unclassified. A weak donor
placement never transfers canonical game/library ownership. Exact donor library
identities can classify later functions, without awarding archive credit.
Data and linked-executable recovery remain unmeasured for these builds.

CI fetches the six original images from the existing public asset bucket and
verifies their registry SHA-256 pins. Report artifacts follow the existing
`<version>_report` naming convention, so all versions belong to the same
decomp.dev project. The content-pin URL parameter avoids stale CDN responses
when a previously absent version is first published.
