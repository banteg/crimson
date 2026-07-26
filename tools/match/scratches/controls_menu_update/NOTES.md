# `controls_menu_update`

Native target: `crimsonland.exe` at `0x00448cd0` (21,289 bytes).

Live Binary Ninja disassembly and the Ghidra export recover the complete
controls-screen callback. It constructs the two buttons, three dropdowns,
direction-arrow checkbox, and 15 rebind rows; builds the configure-for,
aiming, and movement label arrays; renders both panels; and updates the three
dropdowns without losing their mutually exclusive open-state policy.

The callback copies two configured players' 13 input bindings into the live
`player_state_t::input` blocks every frame. Native code advances the config
cursor by `0x40` bytes and the player cursor by `0x360` bytes, while swapping
the stored X/Y axis order into the runtime field order. The right panel then
selects action rows from the active aim and movement schemes: keyboard torso
aim, dual-axis aim, relative/static/digital movement, point-and-click
movement, fire, and Player 1's level-up/reload bindings.

The persisted side of that copy is now a recovered
`player_input_config_t` record rather than a 64-dword array plus negative
indices. Its 13 named bindings, Y/X analog-axis storage order, and three-dword
tail account for the native 0x40-byte row stride; the destination remains the
distinct X/Y-ordered `player_input_t`.

The native loop initially materializes `config_p1_move_forward + 0x30`, the
`axis_move_x` field of the first persisted row, before incrementing the cursor
and reading the preceding row through negative displacements. Binary Ninja
therefore records the instruction-defined value at `0x004492a1` honestly as
an `int *` named `binding_axis_move_x_cursor`, rather than mis-typing that
interior cursor as the owning `crimson_cfg_t *`.

The point-and-click movement gate now uses the shared `cvar_float_t::value`
field. The matching map and live Binary Ninja database carry the same cvar
pointer type, replacing the former provisional byte-pointer-plus-`0x0c`
access. Native instructions `0x00448f94..0x00448fb1` compare the value with
zero before materializing the default count of three, then overwrite it with
four only for the nonzero case. Expressing that decision as an explicit
zero/else branch restores the complete native gate while preserving the
original behavior for signed zero and NaN.

Live Binary Ninja also shows that widget construction uses a 15-entry
countdown/pointer walk, followed by a separate pointer reset walk. Keeping
those cursors distinct from the 13-row key-label index restores the native
local lifetimes. The configured-binding lookup now advances its own index
alongside the row index instead of recomputing their sum, and the right-panel
base is constructed before the two-player runtime copy as in the native
schedule. The active rebinding row displays the native `"???"` placeholder.

Key rebinding waits for all input to be released, accepts keyboard, mouse,
joystick, and raw-input codes, and uses a separate analog-axis capture path
for the four axis rows. That path records absolute peaks for Grim IDs
`0x13f`, `0x140`, `0x141`, `0x153`, `0x154`, and `0x155`, then commits the
first peak above `0.5`. Escape cancels either capture path and releases the UI
input lock.

The native function inlines the complete `input_key_name` policy four times:
once inside the 13-row player-binding loop, once for the generic configured
binding at row 13, once for Level Up, and once for Reload. Live Binary Ninja
places the extra body after the loop at `0x0044a2c2`, assigns its label at
`0x0044b02d`, and only then enters the Level Up body at `0x0044b045`. The
scratch shares that policy through
`tools/match/include/input_key_name_impl.h`; defining
`CONTROLS_INLINE_KEY_NAME` gives VC6 the same force-inlined source body while
the standalone scratch continues to compile it as `input_key_name`.

The remaining tail now follows the native dataflow rather than helper-level
equivalences: rebind capture writes the selected regular, Level Up, or Reload
configuration field directly; the analog peak scan walks seven contiguous
float slots with a pointer, mapping the first six and routing the cleared
seventh slot through the native switch default; dropdown selection returns the
selected index; and list enable flags are reset and then cleared in native
open-list order. The two capture prompts share one base Y value, as in the
native branch join.

The panel geometry now uses the same inline vector-addition shape recovered in
the neighboring menu callbacks. The left base adds the widget position and
vertex vectors and applies `(300, 40)` before folding in the render offset.
Live disassembly at `0x00449238` shows the corresponding right base adding
`(50, 40)`, preserving a copy, applying `render_offset_x - 64`, and then
adding 32 to Y and 64 to X. This replaces the formerly fused right expression,
whose extra `+16` and `+4 - 38` did not represent the native coordinates.
Later, the post-heading position is staged as `y + 26` and `x - 8` before
rebuilding the key labels, followed by the native `x - 14` at `0x0044cb51`.
The inlined heading advances Y by 18 before X by 8, and its tint local is
populated in native R/B/G order before the alpha write.

The rebinding tail now follows the native branch layout more closely. Regular
player bindings are handled before the Level Up/Reload fields, the configured
binding cursor advances as its value is read, and clicking a row toggles the
capture slot directly instead of materializing an equivalent `was_idle`
boolean. The direct toggle also restores the native long-lived zero register,
which extends the exact prefix through all five widget constructors and the
selection-refresh block. The three dropdown updates pass their temporary
offsets by const reference, avoiding the redundant by-value copies that do not
exist in the native inlined call sites.

`point-click-gate-mutations.json` records the bounded schema-1 search used to
check that source recovery. The spec SHA-256 is
`0e14fa1f7f74e845215210c332a5cbc2acc6c966947a0a3399b7db286ada9afa`;
the recorded `experiments.jsonl` SHA-256 is
`cc6b2ebd715d425e6bb152558704ac2e3db7c41ad2ee58ee94249a5e2a56c114`.
All seven one-site alternatives were evaluated:

| Rank | Alternative | Source SHA-256 | Fuzzy delta | Match delta | Prefix | References |
| ---: | --- | --- | ---: | ---: | ---: | --- |
| 1 | `staged-cvar-value` | `2ec43537422e079041688be68814eda7c31e1f1de3e5e3fe4df1a903b6c119cc` | +7.875335 | +0.036993 pp | 162 | 1,530 / 4 / 9 |
| 2 | `explicit-zero-else` | `bf7923db70d879f0c87c660d7e0a27480595fa5916ab758b8787f9db10308cc2` | +7.875335 | +0.036993 pp | 162 | 1,530 / 4 / 9 |
| 3 | `staged-cvar-pointer` | `5479720b2e24fbba79088797b42d8b524b4c41004e87b1b093cf5f8b3eb7474a` | 0 | 0 pp | 148 | 1,529 / 4 / 9 |
| 4 | `implicit-float-condition` | `2d71d698a4bfa0fa4fb4366ee18e4312f8ad2e23d4a33220ed3f62fb709dcc9d` | 0 | 0 pp | 148 | 1,529 / 4 / 9 |
| 5 | `conditional-expression` | `06e494bb5febc5d5b2ece323e332b347c04a6edcaf0a4b5b614e8f80fdd17119` | -3.937668 | -0.018496 pp | 151 | 1,528 / 4 / 9 |
| 6 | `staged-nonzero-condition` | `635eaae7a12940a952d5b16c98ffcc23a6c9c32ead97355e9d38179fb131f3b6` | -7.536459 | -0.035401 pp | 151 | 1,529 / 4 / 9 |
| 7 | `reverse-default` | `826549805b411804b644799215a3549449599c676aa1052ab2d5c5eac0f3d12f` | -7.875335 | -0.036993 pp | 148 | 1,528 / 4 / 9 |

The first two alternatives compile identically, moving the first mismatch
from byte `0x2c4` to `0x30c`. The explicit branch was retained because it
captures the native decision without introducing a source-only local; the
canonical source SHA-256 is therefore the rank-2 hash above. All alternatives
replace the same source span, so they are mutually exclusive and no
positive-single interaction exists to sweep.

Current MSVC 6.5 `/O2 /GB /W3 /GR-` result: **76.63%**, with a fuzzy gap of
4,975.24 bytes, 162 exact prefix instructions, 5,421 native instructions
versus 5,392 candidate instructions, and reference audit **1,530 resolved /
4 unresolved / 9 mismatched**. This improves the prior **76.59%** result
(4,983.12-byte gap, 148 exact prefix instructions, 5,392 candidate
instructions, and 1,529 / 4 / 9 references) while retaining the native
`0x74`-byte frame. The remaining gap is dominated by allocation and early
UI/x87 lowering around the four enormous equivalent inlined key-label bodies.
All observed widgets, labels, scheme branches, runtime binding copies, row
updates, capture rules, and dropdown writes are present; no fake dependency,
padding, volatile coercion, or inline assembly is used.
