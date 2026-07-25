# `ui_list_widget_update`

- Native function: `0x0043efc0` (`1420` bytes, `403` instructions)
- Compiler profile: MSVC 6.5
- Current result: `98.76%`, `403` candidate instructions, `50/0/0`
  relocation references.

## Callers

Live Binary Ninja callsites establish that this is the shared dropdown widget
used by:

- the highscore date, player-count, and game-mode filters;
- the profile name-slot selector;
- the play-game player-count selector;
- the controls move, aim, and player-profile selectors.

## Recovered state and behavior

The second argument is the existing `ui_list_widget_t` (`0x1c` bytes):

| Offset | Type | Meaning |
| --- | --- | --- |
| `+0x00` | `unsigned char` | enabled |
| `+0x04` | `int` | open |
| `+0x08` | `int` | selected item |
| `+0x0c` | `char **` | item labels |
| `+0x10` | `int` | item count |
| `+0x14` | `unsigned char` | pointer inside expanded widget |
| `+0x18` | `int` | keyboard/hover active item |

The recovered helper:

- measures every label and sizes the widget to the widest label plus 48 px;
- closes disabled widgets and registers pointer hover with the focus system;
- opens and navigates the list with the up/down keys while focused;
- draws the bordered header, optional divider, and on/off arrow texture;
- returns `-2` outside the header, `-1` over an enabled header, or the active
  row while open;
- draws the selected label and all expanded rows with native hover/focus alpha
  values;
- updates the active row from pointer hover and closes when both pointer and
  keyboard focus leave.

## Remaining mismatch

The candidate has the native `0x1c` frame and the same calls, constants,
branches, state accesses, instruction count, and references. Materializing the
disabled-widget width before clearing `open` is behaviorally equivalent and
recovers the native branch-local x87 spill. It improves the weighted gap from
128.77 to 17.62 bytes and the exact prefix from 32 to 119 instructions. Writing
the down-key clamp directly against `item_count` also recovers the native
register allocation without changing its bounds.

The residual is the equivalent clamp control-flow lowering (`item_count - 1`
before comparison versus decrement after comparison) plus row-vector
expression scheduling. No source padding or semantic distortion is used to
force those compiler details.
