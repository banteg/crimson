# `play_game_menu_update`

Native target: `crimsonland.exe` at `0x0044ed80` (777 normalized
instructions).

Live Binary Ninja recovers the complete Play Game mode-select callback. The
natural reconstruction is a high-confidence WIP at 87.44%, with 776 candidate
instructions, a 120-instruction exact prefix, the native `0x2c` stack frame,
and reference audit `275/0/28` (no unresolved references). It uses Microsoft
Visual C++ 6.5 with `/O2 /GB /W3 /GR-` and passes the fakematch validator.

The residual is code generation rather than missing behavior: VC6 schedules
the opening vector temporaries differently and lays out the roomy/tight menu
branches in the opposite order. The candidate is one instruction shorter.
The VC6.5 processor-pack compiler (79.51%) and VC7.0 (61.25%) are both worse,
which supports retaining the repository's standard VC6.5 profile. No volatile
state, dead expressions, register hints, or other match-only shaping is used.

## Recovered source shape

- Six function-local static controls build under the native guard bits:
  Quests, Rush, Survival, Typ-o-Shooter, a residual Hardcore checkbox, and
  Tutorial. A seventh static holds the player-count list. The Hardcore control
  is labelled but otherwise unused by this callback, matching the executable.
- The callback anchors to menu element 11, draws the Play Game title quad, and
  optionally renders the native F1 `times played:` overlay. Quest plays sum the
  40 counters at indices 11 through 50; the cheap tutorial-placement test only
  uses counter 11 plus Rush and Survival totals.
- The roomy layout is selected while fewer than 40 quests are unlocked or more
  than one player is active, with 32-pixel rows. The single-player completed
  layout uses 28-pixel rows and conditionally exposes Typ-o-Shooter. Tutorial
  moves from the first row to the last after any relevant mode has been played.
  Live HLIL exposes this as the direct structured condition
  `quest_unlock_index < 40 || config_player_count > 1`; the scratch now keeps
  that `if`/`else` shape instead of reconstruction-only labels and gotos. This
  cleanup is byte-neutral at the score and audits reported above.
- Four local player labels are present, but the native list deliberately exposes
  only the one- and two-player entries. Changing it reloads the high-score table;
  opening it disables the three always-visible mode buttons.
- Five hover timers drive the exact tooltip offsets and alpha scale. Activated
  buttons reproduce native state routing: Quests opens quest selection, while
  Rush, Survival, Typ-o-Shooter, and Tutorial configure their mode, transition,
  sign focus, music fades, and pending gameplay state. Escape delegates to the
  contextual Back action.

The strict aliases cover every static object, the shared initialization guard,
and all seven `atexit` destructor thunks. Each destructor thunk is separately
verified as the native one-byte `ret` function.

## Reference residual re-audit

A fresh corpus audit keeps the candidate at 87.44%, 776/777 instructions, and
`275/0/28` references before and after classification. All 28 entries are
aligned mismatches; there are no unresolved references. Live Binary Ninja at
`0x0044f15f` confirms the native roomy-layout arm loads
`quest_play_counts[11]` (`0x00485644`), `mode_play_survival`, and
`mode_play_rush` in that order. The candidate contains the same three proven
objects, but its different opening x87 schedule shifts which generic
`mov reg, [ADDR]` instructions SequenceMatcher pairs. The remaining entries
likewise pair different constant-pool operations or the two scheduled
player-count-list field writes.

No data-map or object-layout correction is supported: every candidate symbol
resolves to its already audited native address. The residual is therefore
compiler scheduling only, and `RESIDUAL=compiler` records that conclusion
without changing the honest mismatch count.

## Player-list input-gate sweep (2026-07-27)

Live Binary Ninja and the current object agree on the complete local input
sequence at native `0x0044f620..0x0044f671` and candidate-relative
`0x89d..0x8ee`: reject list results at or below `-2`, query primary input
first, query Enter only when primary input is false, toggle the list, and then
apply nonnegative selections before reloading highscores. Fresh regions show
only shifted jump destinations here from the earlier layout divergence.

The recorded one-site sweep in
`player-list-input-gate-mutations.json` tested five equivalent C++ condition
and nesting shapes while preserving that call order. Constant-first threshold,
explicit boolean-comparison, and nested-valid-selection forms tied the
baseline exactly. Spelling the threshold as `selected >= -1` regressed the
match by 0.128783 percentage points and 4.169994 weighted bytes; introducing a
named input temporary regressed it by 0.257566 points and 8.339987 weighted
bytes. Every variant retained 776 candidate instructions and `275/0/28`
references. There were no positive singles, so no interaction was eligible.
The complete sweep is recorded in `experiments.jsonl`; no source variant was
applied.

## Opening-position copy sweep (2026-07-27)

After the Options and secret-credits passes reached stopping points, a bounded
pass selected the largest Play Game mismatch region at
`0x0044efce..0x0044f055`. Live Binary Ninja forms both UI-element coordinate
sums, labels Tutorial, adds `(330, 50)`, copies the base position, and applies
the render-offset X adjustment. Those operations and their dependencies are
already present in the source; the mismatch is temporary placement and x87
scheduling.

The recorded schema-1 `opening-position-copy-lifetimes` sweep tested all 5/5
planned copy, default-assignment, component, and pair-constructor forms. Its
spec SHA-256 is
`9d636c6f4b5ece30b8f9c5bc80715d45fd0ee5a2554a87e5ebff5ec0cab73b70`.
Default construction followed by assignment for only `base_position` is
byte-neutral. Default-assignment for `position` or both objects loses
`6.74313904227256` weighted bytes, six extra instructions, four prefix
instructions, and three resolved references. Component-copy and
pair-constructor forms each lose `63.761328269032674` weighted bytes and four
candidate instructions. With no positive single, the source remains unchanged
at `2831.4256278171283/3238` weighted bytes (`87.44365743721829%`), gap
`406.5743721828717`, 776/777 instructions, prefix 120, and `275/0/28`
references. Its SHA-256 is
`0074e502ced913f132686122ec0e158ed032f17c79c69ea1c483e27bc5d6c1ff`.

## Opening and player-list source-shape tranche

A second bounded pass recorded 73 variants across seven schema-1 mutation
sweeps and one standalone probe. It retained three semantic source-order
improvements:

- applying the render-offset X adjustment before copying `base_position`
  gained `10.169733007614013` weighted bytes and one exact reference;
- spelling the `(330, 50)` update as `position = position + ...` gained a
  further `44.49338515596537` weighted bytes and one exact reference; and
- publishing the player-list `items` pointer before `selected_index` and
  `item_count` gained another `16.658520900321037` weighted bytes, converted
  three references to exact, and removed two aligned mismatches.

Together these changes move the scratch from
`2831.4256278171283/3238` (`87.44365743721829%`) to
`2902.7472668810287/3238` (`89.64630225080386%`), shrinking the weighted
gap by `71.3216390639004` bytes. The candidate is now 778/777 instructions,
keeps the 120-instruction exact prefix, and reports `280/0/26` references.
The retained source SHA-256 is
`7c8efd940719789c60cce6a015e6a6776aa1f37a1b8af26351a57404c88e0dc7`.

The recorded spec SHA-256 values are:

- `adjusted-x-copyback-mutations.json`:
  `ca3fbe4d9daf681bd7b74446792caf32bc135c6bd1868abf7d7217c7093b2c93`;
- `opening-vector-owner-mutations.json`:
  `4b5dc9651bfb8ce75f568bd40d9f61dc9b07635173470a065d8c4cf7c775cb7e`;
- `layout-predicate-mutations.json`:
  `c2a190c96aebd4adf0b1545fbcd8e92d4cd6be3135b75ff9bba597048dc570a9`;
- `explicit-layout-routing-mutations.json`:
  `27eef41285964a510ce0c446ce3b285be2ad377bf3642a1fcfa0afd3d227daa7`;
- `vector-special-member-mutations.json`:
  `210187baeb39526d2ebc6839a6c831f2575d06e80217d53d741f2caefc27347a`;
- `player-list-publication-mutations.json`:
  `d5130b30c99e11185737063f87d15f602cf2e30bce635d210d313e2d0090baaa`;
  and
- `menu-offset-application-mutations.json`:
  `a1098b631d71637a255eed62dc74f921db1c3f4f53b4e6fda43e92645e93d05f`.

Live target disassembly places the roomy layout block before the tight block,
opposite the candidate's physical order. Direct structured control flow, the
complete explicit-goto reconstruction, and physically inverted source arms
all compile byte-identically; the latter probe has source SHA-256
`fadbc02f4246278c79c260f62affce813744da0ff2f7e69645e74f53c706be7e`.
Using bitwise OR for the layout predicate gained `11.069148756134382`
weighted bytes and improved the reference alignment, but added three more
instructions while the candidate was already one instruction long, so it was
not retained. Vector special-member spellings and menu-offset aliases were
neutral or regressive. This bounds the remaining opening/layout residual to
compiler block ordering, stack-slot ownership, and register allocation rather
than a missing semantic operation.

## Tooltip alpha f32 recovery

The reference audit exposed five genuine constant mismatches that were hidden
among the layout-alignment pairs. Native uses f32 bits `0x3a6bedfb`
(`0.0009000000427477062`) for every tooltip fade; the former `0.0009f`
literal compiled to the adjacent lower value `0x3a6bedfa`. The exact
`0.000900000043f` round-trip is also used by the recovered high-score tooltip
path and is retained at all five sites.

`hover-alpha-literal-spellings.json` confirms that both the exact decimal and
the natural constant-folded expression `0.09f * 0.01f` produce the native
value, while the shorter scientific spellings remain on the lower f32.
`hover-alpha-exact-f32-interactions.json` evaluates all 31 site combinations;
each corrected site resolves one reference independently and the five-site
winner improves the audit from `280/0/26` to **`285/0/21`** with unchanged
89.65% instruction score, 778/777 instruction counts, and 120-instruction
prefix. The remaining 21 mismatches are the documented block-scheduling
alignment pairs rather than literal-value debt.

## Named layout-predicate ownership (2026-08-09)

A fresh masked-reference audit confirms that the former 21-reference debt was
entirely aligned mismatch debt, not unresolved naming. Thirteen entries paired
the same proven `quest_play_counts[11]`, `mode_play_survival`,
`mode_play_rush`, and `mode_play_typo` loads across opposite layout arms; the
other eight paired the known 26.0f, 28.0f, and 32.0f constant-pool loads.
Binary Ninja confirms the data identities and native layout-arm load schedule;
the matcher records the exact constant bytes.

Giving the compound roomy-layout decision an ordinary named `bool` preserves
the exact predicate and branch semantics while recovering the native physical
arm order. This raises the match from 89.6463% to **95.4341%**, adds
187.408360 fuzzy-weighted bytes, shrinks the gap from 335.252733 to
147.844373 bytes, and improves the audit from `285/0/21` to **`306/0/12`**.
The 778/777 instruction counts and 120-instruction prefix are unchanged.

The remaining 12 mismatches are four repetitions of one source-expression
ordering choice: native loads quest, Survival, and Rush counts in that order,
while VC6 loads Survival, Rush, and quest for the current summed expression.
They remain explained source/compiler scheduling debt; no alias or data-map
change is warranted. Retained source SHA-256:
`89caefd22e46e1e8666b7d8bf904ba4a8148d31cc889e7c7b5211e26c7c4b418`.

## Play-count operand ownership (2026-08-09)

The four remaining audit groups share one VC6 whole-function scheduling
decision. The first roomy-layout test previously spelled the nonnegative
counter sum as quest + Survival + Rush, for which VC6 emitted Survival, Rush,
quest loads at all four repeated tests. Rotating that first source expression
to Rush + quest + Survival preserves the counter-domain result and makes VC6
emit the native quest, Survival, Rush load order at every site. This removes
all 12 aligned mismatches without aliases, data-map changes, or match-only
shaping.

The instruction score stays **95.4341%**, with the same 778/777 instruction
counts, 120-instruction prefix, and 147.844373-byte weighted gap. The reference
audit improves from `306/0/12` to **`318/0/0`**. Retained source SHA-256:
`8928bdca3bc79424a2ceb3dda4b710a1045da46c0c31361af0a1e96aaeb038de`.

## Typ-o-Shooter branch ownership (2026-08-09)

The next weighted region exposed a genuine branch-scope discrepancy rather
than compiler scheduling. Native calls `game_is_full_version` at `0x0044f4a0`;
the false edge goes directly to the unconditional 28-pixel row advance at
`0x0044f503`. On the true edge, a non-single-player count skips only the
Typ-o-Shooter button call by branching to `0x0044f4c4`. The optional play-count
text remains owned by the full-version branch, independently of whether the
button is exposed.

The former combined full-version/single-player condition incorrectly owned
the count text and row advance as well as the button. Recovering the native
nested scope removes the candidate's extra `mov` of `show_play_counts`, aligns
all downstream branch destinations, and restores the exact instruction count.
The retained result improves from **95.434084%** to **98.970399%**, gains
114.505892 fuzzy-weighted bytes, and shrinks the weighted gap from 147.844373
to 33.338481 bytes. It now has 777/777 instructions, a 120-instruction prefix,
and reference audit **`319/0/0`**. Retained source SHA-256:
`a7fa7e2cde6d4322c43739211cd86c26331d90c271fcf38b39c146d80daac635`.

## Tutorial row ownership (2026-08-09)

The two remaining repeated control-flow regions exposed the same semantic
scope error in the roomy and tight layouts. Native `0x0044f17b..0x0044f1a8`
tests whether the Tutorial-placement count is positive and, on the
nonpositive edge, conditionally calls the Tutorial button only for one player
but advances the row unconditionally. Native `0x0044f341..0x0044f36e` uses
the same nested ownership with the 28-pixel tight-layout advance.

The former combined `count <= 0 && player_count == 1` conditions incorrectly
made each row advance single-player-only. Restoring the native nested scopes
removes both regions, keeps the exact 777/777 instruction count, and improves
the match from **98.970399%** to **99.742600%**. The weighted gap falls from
33.338481 to 8.333333 bytes, references improve from `319/0/0` to
**`321/0/0`**, and the 120-instruction prefix is unchanged. The sole remaining
region is the already-bounded opening-position stack-slot allocation at
`0x0044efce..0x0044f009`. Retained source SHA-256:
`1e2d19e67439a8b4cf20aa0fb16268408154cc57ba7603201f4065d9af2ecf8f`.
