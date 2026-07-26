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

Current MSVC 6.5 `/O2 /GB` result: **55.43%**, with 1 exact prefix
instruction, 1,422 native instructions versus 1,302 candidate instructions,
and reference audit **305 resolved / 0 unresolved / 48 mismatched**. The
candidate has a `0x70`-byte frame versus native `0x68`; remaining differences
are dominated by VC6 scheduling and temporary-slot allocation across the
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
recovery; the matcher stays at **55.43%**, 1,302/1,422 instructions, prefix 1,
and **305/0/48** references.

The scratch is classified `semantic-complete` with `compiler,references`
residuals. A fresh `match inspect --binja-live` pass confirms the same six
native callees in Binary Ninja, IDA, and Ghidra, while the recovered source
contains the complete 41-element graph, both configuration branches, all
three render layers, every callback and texture, and the final layout pass.
The bounded mismatch regions start with the `0x70` versus `0x68` frame and
then differ only in x87 lifetimes, aggregate-copy scheduling, temporary slots,
and reference alignment; they do not expose a missing native operation.
