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
a standalone `0xe8` subtemplate block, loads
`ui\ui_textLevelUp.jaz`, and applies separate four-vertex prompt/text
transforms.

Current MSVC 6.5 `/O2 /GB` result: **55.80%**, with 10 exact prefix
instructions, 1,422 native instructions versus 1,302 candidate instructions,
and reference audit **305 resolved / 0 unresolved / 48 mismatched**. The
candidate now has the native `0x68`-byte frame; remaining differences are
dominated by VC6 scheduling and temporary-slot allocation across the
aggregate position/atlas assignments, plus repeated inlined responsive-loop
register choices. The recovered element graph, callbacks, assets, coordinates,
atlas rows, responsive branches, and final layout pass are complete. No
volatile qualifiers, fake dependencies, dead expressions, padding, or inline
assembly are used to coerce the match.

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

The scratch is classified `semantic-complete` with `compiler,references`
residuals. A fresh `match inspect --binja-live` pass confirms the same six
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
scheduling only, and `RESIDUAL=compiler` leaves the 48 mismatches visible.
