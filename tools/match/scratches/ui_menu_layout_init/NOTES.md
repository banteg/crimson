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
