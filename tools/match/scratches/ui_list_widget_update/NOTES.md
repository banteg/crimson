# `ui_list_widget_update`

- Native function: `0x0043efc0` (`1420` bytes, `403` instructions)
- Compiler profile: MSVC 6.5
- Current result: `99.26%`, `403` candidate instructions, `50/0/0`
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

Writing the down-key bound as the evidenced `active_index > item_count - 1`
comparison recovers the native pre-comparison decrement, branch condition,
and complete clamp region. The exact prefix consequently advances from 119
to 321 instructions and the weighted gap falls from 17.62 to 10.57 bytes.

The remaining residual is row-vector expression scheduling. Native begins
materializing the row Y expression before loading and storing the X component;
the current compiler schedules the same constructor's X load first. No source
padding or semantic distortion is used to force that compiler detail.

## Recovery classification audit

A fresh focused `--regions` run is unchanged before and after classification:
**99.26%**, 403/403 instructions, prefix 321, and `50/0/0` references. Its
single region at native `0x0043f427..0x0043f464` contains the same row
constructor, pointer hit test, and arguments; only the X/Y materialization and
push schedule differ. Width measurement, focus navigation, drawing, hover
selection, return values, and close policy are complete.

The full compiler/flag sweep found no exact profile flip, with stock VC6.5
`/O2 /GB` remaining best. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

`row-position-lifetime-mutations.json` evaluated five named-result,
constructor, and component-assignment forms in the only residual region. The
natural named forms are byte-neutral; component assignments regress despite
one moving the prefix by a single instruction. No source change was retained.

## Exact-tail audit (2026-07-27)

Live Binary Ninja and `--regions` again confine the delta to the row vector's
X/Y materialization and argument-push schedule. MSVC 6.0, 6.5, and 6.6 all
produce the baseline; Processor Pack falls to 84.57%, while VC7 falls to
67.59% with unresolved and mismatched references. No tested flag profile is
exact.

`row-constructor-shape-mutations.json` evaluates 19 initializer-list,
assignment-body, addend-order, named-X, and temporary-copy combinations.
Eight natural forms are byte-neutral. Y-first assignment falls to 97.27%;
temporary copies fall to 81.98% and lose a resolved reference. The recorded
`reversed-initializer-confirmation` probe is neutral. No source change was
retained; baseline and final remain **99.26%**, 403/403, prefix 321,
`50/0/0`.
