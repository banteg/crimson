# `ui_menu_layout_init`

Native target: `crimsonland.exe` at `0x0044fcb0` (7,237 bytes).

Live Binary Ninja and the audited data map recover the complete menu-layout
constructor. It clears and populates the 41-entry UI element graph, swaps the
two footer entries for config variable 100, initializes every element, loads
the five menu text textures, wires the main/pause/options/controls/quest
callbacks, and constructs the perk-selection prompt before calculating every
layout.

The native `0x318`-byte element contains three contiguous `0xe8` render layers
at offsets `0x3c`, `0x124`, and `0x20c`. Making those layers explicit recovers
the responsive three-layer vertex transforms rather than treating the latter
two as padding. The main-menu atlas loop deliberately keeps its two config
branches and four temporary `Vec2` assignments per branch; native code has two
separate temporary families and remaps row six only in the non-wide layout.
The many element positions are likewise aggregate `Vec2` assignments, which
is supported by their native stack-temporary copy shape.

The narrow main-menu transform is one fused vertex loop: it scales and shifts
the sign while applying the 14-pixel vertical correction to the first menu
entry. This is distinct from the later per-element responsive transforms.
Focused native disassembly also confirms that the level-up prompt operates on
the prompt owner's second `0xe8` subtemplate layer at `+0x124`, loads
`ui\ui_textLevelUp.jaz`, and applies separate four-vertex prompt/text
transforms.

Current MSVC 6.5 `/O2 /GB` result: **93.92%**, with 370 exact prefix
instructions, 1,422 native instructions versus 1,408 candidate instructions,
and a clean **528/0/0** reference audit. The candidate has the native
`0x68`-byte frame. Remaining differences are dominated by VC6 scheduling and
temporary-slot allocation across the responsive transforms, aggregate
position/atlas assignments, and prompt transform. The recovered element graph,
callbacks, assets, coordinates, atlas rows, responsive branches, and final
layout pass are complete. No volatile qualifiers, fake dependencies, dead
expressions, padding, or inline assembly are used to coerce the match.

The shared `ui_element_t` now exposes the three position/hover pairs as
`vec2f_t` unions and the complete render payload as three typed
`ui_menu_item_subtemplate_block_t` layers. Its former four-byte hole at
`+0x30` is the menu `label_id`, and the previously missing direction byte
extends the canonical object to the evidenced `0x318` bytes. The layout
constructor therefore no longer carries a second private structure, casts the
global element table, or casts elements back to the canonical type at helper
boundaries. This type-only recovery is matcher-neutral at the score and audit
above.

The data map now gives the pointer graph its full `ui_element_t *[41]` extent
while retaining the 41 interior slot names and comments. Binary Ninja therefore
shows the constructor's clear as one 0xa4-byte table operation and its
population as indexed array stores rather than pointer arithmetic relative to
slot zero. This is a presentation-only type recovery and does not change the
matching result.

Binary Ninja still discarded that pointee type at seven repeated indexed
reloads in the two menu-text atlas branches, rendering the eight UV stores as
`void *` plus raw offsets `+0x138..+0x190`. The name-map importer now supports
narrow `local_types` annotations keyed by the defining instruction address.
Replaying the map types those seven reload variables as `ui_element_t *`, so
live HLIL names every write as `overlay_vertices[0..3].u/v`. The importer also
walks database-path ancestors when locating the repository, allowing a direct
`bn py exec --script scripts/binja_import_maps.py` replay from
`analysis/binary_ninja/crimsonland.exe.bndb`. This remains a presentation-only
recovery; the matcher stays at **55.80%**, 1,302/1,422 instructions, prefix 10,
and **305/0/48** references.

## Compiler-residual lifetime refinement

The former first mismatch was the candidate's `0x70` frame versus native
`0x68`. The level-up prompt offset is used only by its one
`ui_element_set_rect` call. Giving that address-taken vector an explicit narrow
scope lets VC6 reuse its slot at the native lifetime boundary: the frame
becomes `0x68`, the exact prefix grows from 1 to 10 instructions, the score
rises from 55.43% to 55.80%, and the rounded fuzzy gap falls from 3,225 to
3,199 bytes. The instruction and reference audits remain 1,302/1,422 and
`305/0/48`.

Reusing the general table pointer as the initialization cursor regressed to
55.21% with one fewer resolved reference; direct table indexing in the atlas
loop was byte-neutral. Both are rejected in favor of the simpler existing
cursor lifetimes. A 20-profile matrix covered MSVC 6.0, 6.5, 6.5pp, 6.6, and
7.0 with `/GB`, `/G5`, `/G6`, and `/Oy-`; extended VC6.5 probes also covered
`/Ob0`, `/Ob2`, `/Oi-`, `/Og-`, `/Os`, `/O1`, and `/GX`. Stock MSVC 6.5
`/O2 /GB` remains tied for best with 6.0, 6.6, and `/G5`, so no override is
supported.

The scratch is classified `semantic-complete` with a `compiler` residual.
A fresh `match inspect --binja-live` pass confirms the same six
native callees in Binary Ninja, IDA, and Ghidra, while the recovered source
contains the complete 41-element graph, both configuration branches, all
three render layers, every callback and texture, and the final layout pass.
The bounded mismatch regions now start after the exact 10-instruction prefix
and differ only in x87 lifetimes, aggregate-copy scheduling, temporary slots,
and reference alignment; they do not expose a missing native operation.

## Reference residual re-audit

A fresh corpus audit keeps the candidate at 55.80%, 1,302/1,422 instructions,
and `305/0/48` references. All 48 entries are
aligned mismatches; there are no unresolved references. Live Binary Ninja
reports each menu slot as the evidenced `0x318`-byte `ui_element_t`, and the
menu-item and panel templates at their existing mapped object boundaries.

The mismatches cross distinct element-construction blocks rather than showing a
shared bad offset. For example, native `0x00450c51` stores
`controls_menu_update` into slot 14's `on_update`, while the aligned candidate
instruction belongs to slot 11's `play_game_menu_update` assignment. Other
pairs similarly cross slot 31/32/23/10/30 objects or different responsive
constant operations. Changing the common UI layout would corrupt already
resolved accesses. The residual is therefore aggregate-copy and compiler
scheduling only, and `RESIDUAL=compiler` leaves the remaining mismatches
visible.

## Recorded mutation wave

The mutation harness turned the repeated responsive-loop residual into a
source-shape fix. `transform-reload-mutations.json` first showed that spelling
the shifts as direct pointer-to-pointer dereferences restores 100 instructions,
raising the match from 55.80% to 58.14% and improving the reference audit from
`305/0/48` to `311/0/41`. The narrowed
`transform-scale-pair-mutations.json` then found the actual lifetime shape:
one slot pointer is reused for the X/Y scale pair before being reassigned to
the next layer. That single mutation raised the match to 79.23%, added
1,525.90 fuzzy-weighted bytes, and moved the audit to `404/0/29`.

The same pair lifetime in the fused narrow-menu transform was independently
positive in `narrow-transform-scale-pair-mutations.json`, adding another
211.79 weighted bytes and 20 resolved references. This spelling follows live
native disassembly: each layer base is loaded once, X is scaled, and Y is
scaled through the retained adjacent pointer; the later shifts still reload
the element pointer individually.

Live Binary Ninja also exposed three actual recovery omissions rather than
compiler residuals. Native initializes slot 33 with the aggregate
`(screen_width - 350, 200)` before every responsive branch, and initializes
slots 8 and 9 at `(-190, 122)` and `(-60, 185)` before applying their
wide/narrow X adjustments. `right-panel-initial-position-mutations.json` and
`responsive-base-position-mutations.json` recover those redundant but native
stores. Together they add 15 candidate instructions, 101.93 weighted bytes,
and seven resolved references.

The final retained result is **83.56%**, 1,395/1,422 instructions, prefix 10,
audit **431/0/25**, and a 1,189.47-byte fuzzy gap before the final prompt-origin
pass. Native initializes that adjacent float pair through one aggregate
temporary in both width branches. `prompt-origin-aggregate-mutations.json`
confirmed the typed `Vec2` copy shape, adding eight instructions, 85.35
weighted bytes, and six resolved references while removing two mismatches.

The final result is therefore **84.74%**, 1,403/1,422 instructions, prefix 10,
audit **437/0/23**, and a 1,104.12-byte fuzzy gap. Relative to the pre-wave
55.80% baseline, the gap fell by 2,094.61 bytes. The opening-order sweep
covered all 34 single and pair variants without changing a byte. Five prompt
pointer variants and three force-inlined vector-helper variants were likewise
neutral or regressive, so no prompt-transform rewrite was retained. All
complete rankings are recorded in `experiments.jsonl`; the JSON specs capture
the pre-application source snapshots used for each sweep.

## Final responsive-Y lifetime

Live native disassembly computes the last responsive offset as three staged
x87 operations: multiply the converted screen width by `0.0015625`, multiply
that result by `150`, then subtract `150` before adding the element's current
Y. `final-responsive-y-mutations.json` evaluated the fused and staged source
shapes; all three staged spellings compiled identically and improved the same
intended closing region.

The retained temporary follows that native dataflow without an artificial
dependency. It raises the result to **84.78%**, 1,404/1,422 instructions,
prefix 10, audit **439/0/22**, and a 1,101.17-byte fuzzy gap.

## Late panel position shapes

A fresh reference audit localized the strongest remaining coherent residual to
the adjacent slot 36-39 construction block. Native disassembly writes slot
39's Y position at `0x00450df2`, its X position at `0x00450df8`, and its
`use_offset_render` flag at `0x00450dfd`. The recorded
`late-panel-position-shape-mutations.json` sweep evaluated all 112 planned
single and two-site combinations of scalar order, explicit derived casts, and
staged locals for slots 36-39. Only replacing slot 39's aggregate temporary
with direct scalar stores changed the ranking positively; the two scalar source
orders compiled identically. The retained Y-then-X spelling mirrors the native
store order. It removes four candidate instructions, adds 44.60 weighted bytes,
and moves the audit from `439/0/22` to `446/0/21`. Changes to slots 36-38 had
no independent benefit and were rejected.

The same native block also showed a source-shape omission for the controls
panel. Native first constructs slot 14 at the wide-layout base
`(-165, 200)`, then overwrites X with `-183` only when the screen width is at
most 640. The port's equivalent ternary omitted that observable base store.
`controls-panel-base-position-mutations.json` evaluated all six planned
aggregate, scalar, branch-direction, and cast shapes. The wide-base aggregate
and explicit-cast forms tied for best, so the clean aggregate was retained.
It adds four candidate instructions and another 6.62 weighted bytes while
removing two reference mismatches; the scalar forms were fuzzy-regressive and
the narrow-base branch was weaker.

Together these two native-evidenced changes raise the retained result from
**84.78%** to **85.49%**: 6,135.83 to 6,187.05 weighted bytes, a 1,101.17 to
1,049.95-byte gap, 1,404/1,422 instructions, prefix 10, and audit
**449/0/19**. The full rankings and negative variants are recorded in
`experiments.jsonl`.

## Slot 31 aggregate lifetime

Live native disassembly at `0x004506e0` through `0x00450774` materializes the
slot 31 position `(-45, 210)` before the `0xe8`-byte template copy, then
constructs the derived hover maximum `(hover_min.x + 280,
hover_min.y + 180)` as a second aggregate temporary. The six-variant
`slot-31-aggregate-lifetime-mutations.json` sweep covered the evidenced
before/after-copy lifetime choices and scalar alternatives. Three aggregate
spellings tied for best; the retained position-before-copy/hover-after-copy
form mirrors the observed native schedule.

That one source-shape correction adds four candidate instructions and
**195.83 fuzzy-weighted bytes**, moving the result from **85.49%** to
**88.20%**. The gap falls from 1,049.95 to **854.12 bytes**, and the reference
audit improves from `449/0/19` to **`474/0/11`**.

The neighboring pause-menu elements do not share this lifetime shape.
`pause-menu-position-lifetime-mutations.json` exhaustively evaluated all 60
planned one- and two-site variants for slots 23, 24, and 25. Every variant
regressed, with the least-bad result losing 47.30 weighted bytes. No source
change was retained; the complete negative sweep is recorded so those
interactions do not need to be revisited.

Native also interleaves the next element's position constants across the
slot-24/25/26 layer copies and timeline updates. The 15-variant
`pause-cross-element-lifetime-mutations.json` sweep reconstructed those split
lifetimes independently and together, but every spelling regressed; the best
lost 62.67 weighted bytes and five resolved references. Likewise, native's
narrow-width controls-panel path restores the unchanged Y component after
overwriting X. All four direct aggregate and staged-source reconstructions in
`controls-panel-narrow-vector-mutations.json` lost at least 128.68 weighted
bytes and did not improve the reference audit. Both complete negative sweeps
are recorded, and neither source shape is retained.

Finally, `atlas-row-store-order-mutations.json` challenged the slot 32 UV
construction against native `0x004507c5..0x0045086c`. Four scalar and
named-aggregate spellings covered the observed store order. All regress by at
least 61.37 weighted bytes; scalar stores also delete 16 constructor-shaped
instructions present in native. The existing four aggregate assignments remain
the best evidenced source shape.

## Native branch, prompt UV, and timeline ordering

Three fresh coherent regions produced native-supported source-order gains.
First, native implements the right-panel X adjustment at
`0x00450e36..0x00450e6f` as a descending branch tree: widths above 800 use
`right_panel_x - 65`, widths above 640 use `right_panel_x - 30`, and the
remaining path uses `right_panel_x + 10`. The five-variant
`right-panel-branch-shape-mutations.json` sweep found the nested native shape
and its equivalent descending-threshold spelling tied for best. The nested
shape was retained, adding **10.23 fuzzy-weighted bytes** and resolving two
reference mismatches.

Second, native stores the prompt U coordinates in slot order 0, 1, 3, 2 at
`0x00451701`, `0x0045170b`, `0x00451715`, and `0x0045171f`.
`prompt-uv-store-order-mutations.json` covered six plausible schedules; the
native order was the sole winner, adding **5.11 fuzzy-weighted bytes** and one
resolved reference. The six prompt setup schedule variants were byte- and
reference-neutral, so none was retained.

Finally, native loads slot 30's timeline end before its timeline start at
`0x00450b8c` and `0x00450b98`, then stores start and end at `0x00450bb9` and
`0x00450bcb`. Reordering the two independent source updates to end-then-start
is fuzzy-weighted neutral, but improves the reference audit by four resolved
references and removes four mismatches. The staged alternatives in
`slot-30-timeline-order-mutations.json` each lost 122.75 weighted bytes.

The retained result moves from **88.19788%** to **88.40989%**:
6,382.88 to **6,398.22 weighted bytes**, an 854.12 to **838.78-byte gap**,
1,408/1,422 instructions, prefix 10, and audit **`482/0/5`** versus
`474/0/11`. `right-panel-conversion-lifetime-mutations.json` recorded eight
conversion-lifetime variants; the only nominal weighted improvement
(0.60 bytes) worsened the reference audit and contradicted native's
stack-local branch dataflow, so it was rejected. All 24 main-menu position
lifetime variants regressed, with the best losing 25.57 weighted bytes. Every
ranking, including these negative results, is recorded in `experiments.jsonl`.

## Opening and prompt loop saturation

Two final bounded sweeps challenged the remaining earliest mismatch without
changing the retained source. `prompt-transform-pointer-bound-mutations.json`
covered six independent pointer-bound loop spellings for the prompt and
level-up transforms. All six compiled and regressed; the least-bad variant
lost 3.92 fuzzy-weighted bytes and one resolved reference. Its recorded spec
SHA-256 is
`3020c4c080e74b0b1fd631071e70c51e657869a2f2ec544ad1942911ffd47e95`.

`opening-table-zero-interaction-mutations.json` then crossed six table-zeroing
and local-ownership shapes with four first-config-call lifetime shapes. Of 34
planned variants, 29 compiled: nine were byte- and reference-neutral and 20
regressed. The five failures all used an invalid const pointer-table owner and
are retained as explicit negative evidence. Neither the standalone table
spellings nor any interaction with the interface/config result produced a
positive result. Its spec SHA-256 is
`8a1362a9a73aa18e65e14f59fe08824e99eae17b0d94f407e6bc2f999339b3be`.

The baseline remains **88.40989%**, 1,408/1,422 instructions, prefix 10, audit
**`482/0/5`**, and an **838.78-byte** fuzzy gap. Together with the prior
opening-order and prompt-schedule matrices, these results bound the opening
residual as compiler scheduling rather than a missing semantic recovery. The
experiment log SHA-256 after both records is
`63a1482b3607f1190440b76acca15a9baf8eab88b8aeea182ee85b37b03b792b`.

## Prompt layer ownership recovery

The remaining prompt-transform region exposed a real aggregate-ownership error.
Binary Ninja types `ui_perk_prompt_element` at `0x0048f20c` as the full
`ui_element_t` (`0x318` bytes), while the symbol formerly modeled as the
independent `ui_perk_prompt_levelup_element` is at `0x0048f330`: exactly
`0x124` bytes into that owner, the offset of its second vertex block. Native
likewise carries one cursor from `0x0048f334` through the loop at
`0x0045175a..0x004517cd`, reaching the prompt and level-up vertices through
fixed member offsets.

The source now names that storage as `ui_perk_prompt_element.layers[1]` for
load, rectangle setup, and transformation instead of preserving the interior
symbol as a second global owner. It also transfers the exact neighboring
`ui_menu_assets_init` house style by exposing each 28-byte vertex's position as
a vector member and applying the transform through ordinary vector compound
operators. That vector spelling is byte-neutral; the corrected aggregate
ownership is the measured gain and also removes the stale overlapping extern.

The retained result moves from **88.40989%** to **89.11661%**: 6,398.22 to
**6,449.37 fuzzy-weighted bytes**, an 838.78 to **787.63-byte gap**, with the
instruction counts and prefix unchanged at 1,408/1,422 and 10. The reference
audit improves from **`482/0/5`** to **`485/0/4`**. The remaining local delta is
the compiler's x87 materialization schedule: native stores and reloads between
the compound vector stages, while the candidate legally fuses the adjacent
arithmetic. Source SHA-256 is
`146bec6b4fe14e75412e5625f91ea4fdd7bbb43bfc1d0e714dbb566002743fad`.

## Remaining interior-member identities

A focused Binary Ninja containment pass found three more stale standalone
aliases inside already recovered UI owners. `ui_perk_prompt_on_activate` at
`0x0048f240` is `ui_perk_prompt_element.on_activate` (`+0x34`), while
`perk_prompt_origin_x/y` at `0x0048f224/0x0048f228` are the same element's
`pos` vector (`+0x18/+0x1c`). The source now publishes the callback and both
origin branches through those actual members. The final
`ui_menu_layout_init_latch` at `0x0048f164` is likewise
`ui_element_slot_40.direction_flag` (`+0x314`), so that byte-neutral alias is
removed too.

The prompt member identities raise the result from **89.11661%** to
**89.25795%**, adding **10.23 fuzzy-weighted bytes** (6,449.37 to 6,459.60)
and reducing the gap from 787.63 to **777.40 bytes**. Instructions and prefix
remain 1,408/1,422 and 10; the reference audit improves from **`485/0/4`** to
**`488/0/3`**. An adjacent-template array spelling and the exact-neighbor
slot-31 vector-add spelling were both rejected after losing weighted bytes;
neither changed the retained source. Source SHA-256 is
`bf1cf806240dfd538343e3bf2df182e760a3aed85b14425013e44287c0b42384`.

## Narrow preserve-Y and atlas-row boundary

The remaining controls-panel seam was replayed from the current epoch rather
than inherited from its historical score. All four narrow vector-lifetime
spellings regressed by at least 190 weighted bytes. Live native inspection
also confirmed the apparently redundant Y preservation, so deleting or
folding that store would contradict the target.

A second 12-way menu permuted the independent atlas-row aggregate writes at
the three unresolved reference sites. Every ordering regressed; the least-bad
variant lost 5.11 weighted bytes and worsened the reference audit. The three
reference mismatches are therefore scheduling/alignment effects, not evidence
for a different aggregate order. No source was retained. The current baseline
remains **89.25795%**, 1,408/1,422 instructions, prefix 10, and `488/0/3`
references.

## Authenticated `ui_t` owner (2026-08-14)

The recovered 2003 `ui_t` declaration fixes the ownership and member order of
the target block rooted at `ui_mouse_blocked` (`0x004871cc`). Its scalar prefix,
41 contiguous `0x318`-byte elements, 41-entry element-pointer table, perk
prompt element, and prompt timer all land exactly on the independently mapped
1.9.93 addresses. The exact `ui_element_globals_init` constructor remains
135/135 with `121/0/0` references when expressed through that aggregate,
providing a byte-level calibration point for the layout.

`original-ui-owner-mutations.json` records the effect on this consumer:
**+337.62 weighted bytes**, prefix **10 to 370**, instructions unchanged at
1,408/1,422, and references **488/0/3 to 528/0/0**, with no tradeoff. The
aggregate owner is retained. The first remaining mismatch is now the commuted
base/index encoding in the first responsive transform loop, followed by the
already documented temporary and aggregate schedules.

## Post-owner preserve-Y replay

The aggregate owner changed the baseline after the earlier controls-panel
probe, so the four ordinary spellings of native's narrow-screen Y reload were
replayed against the current epoch. The staged variants add one or two
instructions but lose 183.68--186.46 fuzzy-weighted bytes. Both aggregate
forms add five instructions and lose 195.78 bytes. Prefix and the clean
`528/0/0` reference audit are unchanged in every case.

Native's load/store pair is still visible, but no tested typed aggregate or
scalar lifetime recovers it without a much larger scheduling regression. The
canonical source therefore remains **93.92226%**, 1,408/1,422 instructions,
prefix 370, and `528/0/0` references.
