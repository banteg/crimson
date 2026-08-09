# `ui_list_widget_update`

- Native function: `0x0043efc0` (`1420` bytes, `403` instructions)
- Compiler profile: MSVC 6.5
- Current result: exact, `403/403` instructions and `50/0/0` relocation
  references.

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

## Row-position recovery

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

The final residual was row-vector expression scheduling. Native begins
materializing the row Y expression before loading and storing the X component.
The original direct `(x, y)` constructor scheduled X first. Expressing the row
position in the ordinary menu house style as `*xy + list_vec2_t(0.0f, y_offset)`
recovers the native split X/Y schedule exactly. No source padding, dummy
dependency, volatility, or register-forcing construct is used.

## Recovery classification audit

A focused matcher run now reports **100.00%**, 403/403 instructions, prefix
403, and `50/0/0` references. Width measurement, focus navigation, drawing,
hover selection, return values, close policy, and row-vector materialization
all match.

The full compiler/flag sweep found no exact profile flip, with stock VC6.5
`/O2 /GB` remaining best. Classification: `RECOVERY=semantic-complete`.

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

## Row callsite value-shape boundary (2026-07-29)

The remaining native sequence starts the row-position Y expression before
storing X, then prepares the hit-test arguments while the candidate completes
the same constructor in X-first order. A final schema-1 sweep therefore tests
four ordinary ways to expose the constructed value at that callsite:
copy initialization, a direct temporary address, a const-reference-bound
temporary, and a canonical POD aggregate.

All 4/4 variants compiled. The first three are byte-identical to the baseline;
the POD aggregate loses 21.1414 fuzzy-weighted bytes while preserving the
instruction count, prefix, and `50/0/0` reference audit. No variant is
retained. The complete plan has SHA-256
`eae85b93be1ead939078cac7b91453a0204796092b18465a170de8db12e0d73d`,
and the four-record experiment log now has SHA-256
`164a93f668b8150e4c3e29514635be0246e8c1ab7d39227d124b8849ab02a52d`.
This closed the natural constructor/value-category search tried at that
checkpoint without padding, volatility, or a forced dependency. The source
then remained **99.26%**, 403/403 instructions, prefix 321, and `50/0/0`
references.

## Exact vector-offset closure (2026-08-09)

Exact sibling menus construct derived points with vector addition. Adding the
same ordinary `operator+` to the local vector and spelling each row point as
the base position plus `(0, row_offset)` reproduces native's interleaving of
the Y conversion, X load/store, and hit-test argument pushes. The rejected
copy-then-publish and copy-then-add forms fell to 80.94% and 80.69%,
respectively; they were restored. The retained vector-offset form is exact:
**100.00%**, **403/403 instructions**, prefix **403**, and references
`50/0/0`.
