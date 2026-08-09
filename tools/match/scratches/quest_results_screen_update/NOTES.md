# `quest_results_screen_update`

High-value recovery for the 4,857-byte quest-completion callback at
`0x00410d20`. The function owns the staged time-breakdown animation,
high-score name entry, weapon/perk unlock presentation, and every route out of
the completed quest.

## Recovered source shape

- clears the reflex-boost and quest-retry state and starts the Crimson Quest
  music only on the native entry conditions;
- renders the gameplay world and menu elements before lazily constructing the
  name-submit button and text-input state;
- derives the working panel position by copying the base UI-element position,
  then applies the native render offset and 40-pixel inset;
- restores the direct high-score-return jump into the completed-results phase;
- computes the completed quest index, unlock ids, integer-truncated player-one
  health bonus, optional player-two bonus, perk penalty, and final time;
- reproduces the four-step animated Base Time, Life Bonus, Unpicked Perk Bonus,
  and Final Time reveal, including its timers, clink sound, skip inputs, alpha
  clamp, and 168-pixel separator;
- loads and ranks the quest high score, handles validated name entry and save,
  renders weapon/perk unlock notices, and lazily owns all four action buttons;
  and
- implements Play Next / Show End Note, Play Again, High scores, and Main Menu
  transitions with the native audio and return-state bookkeeping.

## Static-object evidence

The native constructor blocks use bits 1, 2, 4, 8, 16, and 32 of
`quest_results_screen_flags` for the name-submit button, name-input state, Play
Next, Play Again, High scores, and Main Menu objects. PE disassembly proves the
registered callbacks, in the same order, at `0x00412070` through `0x00412020`.
The VC6 relocation table maps the generated `$E2` through `$E7` thunks to those
six objects. Their named destructor scratches are exact one-instruction
matches; the function-local objects, guard, and thunks are connected only by
those scoped `REFERENCE_ALIASES`.

## Matching evidence and honest residual

The verified VC6 build is 1,168 normalized instructions against 1,168 native,
scores 95.29109589041096%, and audits 460 references as resolved, zero as
unresolved, and zero as mismatched. The native and candidate both use a
24-byte frame and preserve the working coordinates in `edi`/`ebp`. The
remaining delta is small register/lifetime and instruction-scheduling residue;
bounded lifetime tests leave it visible rather than forcing storage overlap.

The score-ranking branch at `0x0041168d` is invalid-first: records ranked 100
or worse clear the name-input state, advance directly to the completed-results
phase, and return. Qualifying records then fall through into the name-entry
setup. Expressing that early exit instead of an inverted condition with an
`else` restores the native basic-block order, aligns five additional
references, and raises the score from 85.59% without changing the frame or
instruction count.

## Health-reveal scheduling experiment

Live Binary Ninja disassembly localizes one repeated-reference mismatch to the
case-1 health-bonus reveal at `0x0041110d` through `0x00411136`. Native loads,
adds, and stores `quest_results_reveal_health_bonus_ms` before loading
`sfx_ui_clink_01`, then stores the 150 ms step timer immediately before the
call. The current candidate hoists the SFX load ahead of the counter add/store
after the wider frame changes register allocation.

`health-reveal-schedule-mutations.json` exhausts five valid single-site
variants across the counter expression and clink-id lifetime. Explicit
assignment, named and split accumulators, and pre-/post-timer clink snapshots
were all byte-neutral at the original baseline. The complete two-site
interaction matrix was rerun after the opening/lifetime improvements and all
11 variants remain byte-neutral at 87.1839%, 1,165 instructions, and
`438/0/2` references. This records the localized scheduling delta as compiler
residual without aliases, forced dependencies, volatile barriers, or storage
overlap.

The panel geometry now uses the recovered chained vector expression over the
UI element position, first vertex, and `(180, 40)` offset. The post-record
spacing remains visibly split into its native 78- and 6-pixel additions, and
the button alpha stores follow the native high-scores/play-next schedule.
Together these source-shape recoveries move the build to 1,165/1,168
instructions, 87.1839%, and a `438/0/2` reference audit without hiding either
remaining mismatch.

The quest-results name editor is now imported as its 32-byte character array,
and the compiler-generated zero-based scan variable at `0x0041184d` is
persisted as the integer `first_non_space`. The live decompiler therefore
renders the validation loop through
`quest_results_name_input_buffer[first_non_space]` rather than an untyped
absolute base plus a `void *` offset. Matching remains unchanged.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live Binary Ninja output covers the four-step reveal,
high-score qualification and name validation, unlock notices, and every exit
route; IDA and Ghidra corroborate the same 21-callee surface. The candidate is
within three instructions of native at 1,165/1,168 with `442/0/2`
references. Both mismatches align the repeated `sfx_ui_clink_01` load against
the adjacent, already-recovered health/perk reveal accumulators after the
stack-allocation divergence. They remain visible and unaliased, but are not
independent reference debt. A temporary overlay that reused the panel position
to chase the native `0x18` frame was rejected: it fell from 86.50% to 72.68%,
lost 27 aligned references, and introduced five additional reference
mismatches.

## Opening-vector and record-lifetime recovery (2026-07-27)

Live Binary Ninja renders the opening geometry as the UI element position plus
its first vertex and the `(180, 40)` panel offset before copying the working
cursor. The exact `quest_failed_screen_update` sibling uses the same chained
vector idiom. `opening-vector-expression-mutations.json` evaluated all 24
bounded type/expression combinations. The symmetric vector operator plus the
chained panel expression retained here adds 20.818688 weighted bytes and one
aligned reference without changing instruction count or reference debt.

`shared-temporary-vector-mutations.json` then evaluated all 63 declaration and
reuse combinations for the line, name-entry button, and two record positions.
Moving only the name-entry `record_xy` declaration to the native-length outer
lifetime adds another 12.491213 weighted bytes. Reusing other positions cannot
improve that result and is not retained.

The exact-sibling-inspired whole-body scope matrix
(`working-vector-scope-mutations.json`, 14 variants) is neutral at best; the
single-iteration `do` forms substantially regress alignment. The
Binary-Ninja-grounded base/perk reveal ordering matrix
(`reveal-case-order-mutations.json`, 29 variants) is entirely byte-neutral.
Those negative results bound the remaining source-shape search without
register forcing or artificial storage overlap.

At the end of that tranche the retained source was **87.1839%**,
1,165/1,168 instructions, a
1-instruction exact prefix, and `438/0/2` references. It gains 33.309901
weighted bytes over the prior baseline. Spec SHA-256 values are
`5abcd4c986d71457dd9b5997399e0687c5e07abd5405423fae34daeed9cce59e`
(opening), `3466fb782f7779cde29aa3672949cd5ad56ae583c75a50d9f070042796c83b16`
(shared temporary),
`dcda755367dd51f88ca29a5c864d46af6adbe09aa8c501480b8374a30688ff5d`
(scope), and
`a9dc6deca9310b323f80ceae0127ece9505aa5de987bf80907d334e5e2cbe595`
(reveal ordering). The retained source SHA-256 is
`bce9bb81ae0a484367fdf7d5f18daf560ba06145c5dac64dc8c9110ec20d2179`.

## Unlock-index expression recovery (2026-07-29)

Live Binary Ninja disassembly at `0x00411afd` through `0x00411b48` shows the
weapon notice setting up the Grim vtable before recomputing
`quest_stage_minor + quest_stage_major * 10 - 11` inside the
`weapon_table_entry` argument. The prior named `quest_index` caused VC6 to
compute that index before loading the interface and split the otherwise
native instruction schedule.

`unlock-index-expression-mutations.json` exhausts all 15 single-site and
two-site combinations across the weapon and perk notices. Inlining only the
weapon lookup adds 58.292327 weighted bytes and four aligned references with
no instruction or reference-debt regression. Both arithmetic spellings
compile identically; the retained minor-plus-major form follows the live
decompiler. The perk variants are byte-neutral because VC6 already folds that
named pair into the native nested lookup.

The exact sibling's local name-buffer idiom and five equivalent constructor
address spellings were separately bounded by all six variants in
`name-buffer-constructor-mutations.json`; every variant is byte-identical.
That falsifies the constructor expression as the cause of the early
name-buffer register lifetime without introducing a barrier or artificial
alias.

The current source is **88.3841%**, remains 1,165/1,168 instructions with a
1-instruction exact prefix, and audits `442/0/2` references. Spec SHA-256
values are
`1509f8110222447c18fd0236ccfea447d3d0ef4d47b18be51344ec89b1c7c01a`
(unlock index) and
`a2380c499a18611c2b037b0f33c187f26b0c0c4cbf5734ae1c2be26ae744b4e6`
(name-buffer constructor). The retained source SHA-256 is
`ba6e8fe7c57c408c554c11f1a2ef417d6f60f05d0ef83491b8951f36681da102`.

## Name-save copy-shape boundary (2026-07-29)

Live Binary Ninja disassembly at `0x00411893` through `0x004118e2` scans the
name buffer for its terminating byte, snapshots `name_input.cursor`, stores
`player_name_length`, and performs the inline word/tail copy into the active
high-score record. The current `strcpy` already produces that inline copy but
keeps one more instruction than each explicit sized-copy spelling tested.

`name-save-copy-shape-mutations.json` exhausts five source forms covering
`strlen + 1`, a separately incremented length, integer and `size_t` lengths, a
named source pointer, and a direct sized `memcpy`. All five compile
identically: they add 1.840829 weighted bytes and align two more references,
but reduce the candidate from 1,165 to 1,164 instructions against the native
1,168. The experiment therefore records
`instruction-count-further-from-target` for every variant and retains none.
This bounds the apparent reference gain as a copy-lifetime tradeoff rather
than honest whole-function progress.

The spec SHA-256 is
`068c661ee87806d4bd1bbf592d83b9d2cb270bb932623534fe910d75004a9386`.
The experiment-log SHA-256 after recording the complete five-variant sweep is
`8cce7fd918f4a13bc047737de98ee36fda32ec508b03076ef8f41d8554f2c388`.
The retained source and its 88.3841%, 1,165/1,168, `442/0/2` audit are
unchanged.

## Working-position ownership recovery (2026-07-30)

Live Binary Ninja stack recovery proves that native reserves three reusable
8-byte vector slots (`sub esp, 0x18`), preserves the post-banner working
position in `edi`/`ebp`, and rematerializes that position at
`show_results`. The former reconstruction reserved four slots, kept the
position on the stack, and instead carried the integer one and name-buffer
address in those registers.

`register-lifetime-mutations.json` first recovers the native frame without
storage overlays: the phase-1 submit-button position is dead before the
high-score record position, so reusing that vector extends the exact prefix
from 1 to 66 instructions in the final allocation context. All six
zero-final-time correction spellings compile identically, ruling out the
distant literal-one assignment as the allocation cause.

`working-base-lifetime-mutations.json` then evaluates all 19 bounded
base-position and results-label interactions. Snapshotting the post-banner
working position and restoring it at `show_results` raises similarity from
88.5555% to 94.3945%, adds 283.600957 weighted bytes, aligns 15 more
references, and clears both remaining reference mismatches. The retained
`results_base_xy` spelling is byte-identical to reusing `panel_xy` and states
the recovered ownership directly.

That allocation adds four instructions against a native three-instruction
restore, which changes the previously rejected name-save copy tradeoff.
Rerunning `name-save-copy-shape-mutations.json` makes all five sized-copy
forms clean improvements: the retained `strlen + 1` byte count and `memcpy`
remove one instruction, align three more references, and produce an exact
1,168/1,168 instruction count.

That tranche reached **94.5205%**, a 66-instruction exact prefix, and all
`460/0/0` normalized references. A final 39-variant
`opening-register-allocation-mutations.json` sweep covers vector operand
order, declaration order, copy ownership, and render-offset spelling; every
non-regressing form is byte-identical, bounding the opening stack-slot
permutation as compiler residual. Spec SHA-256 values are
`0e5247007fd4d5338a4cc4bde1e06c76c86a02d9067515a1b719083d3c482aa8`
(register lifetime),
`347d75d7b5d4ce96f48f0ca3064354688e07c4944e862c8e2a8e7912e55aa637`
(working base), and
`d2c9da8146d943b42af8b61bf4dceb20dab01642e682c1ca9f5da9a56c600f4e`
(opening allocation). The retained source SHA-256 is
`35a237034c83b23af7742e02b4ca70cbdcd5f42c240f2da9524b051283b46daf`.

## Opening-panel scope boundary (2026-07-30)

The exact sibling uses a short-lived opening panel position, so
`opening-panel-scope-mutations.json` tests whether making that lifetime
explicit changes this function's remaining opening stack permutation. Four
complete panel/record scope arrangements are byte-identical at 94.5205%,
1,168/1,168 instructions, a 66-instruction prefix, and `460/0/0` references.
A direct working-position expression instead regresses to 80.5663%, loses five
instructions and ten resolved references, introduces two reference mismatches,
and collapses the prefix to one instruction.

The retained source is unchanged. Spec SHA-256 is
`301ba09da2acdf8424fc01f83016a41bd41adb58d0c0db4df840d9cb08d54d35`;
the complete 14-sweep, 253-variant ledger has zero errors and SHA-256
`433ef5f879052545b4b126b66987f422046982154f8cc0c6ff13ef58d1e48444`.
Together with the 39-variant opening allocation sweep, this closes ordinary
lexical scope as the missing constraint.

## Name-coordinate scope correction (2026-08-09)

The name-entry phase used one source-level `button_xy` across the entire name
validation block, then republished it for the high-score record render. The
native lifetimes are separate: the submit-button coordinates die at
`ui_button_update`, and the later render coordinates reuse that same stack
pair. Giving each use its own short block expresses that ownership directly
and lets VC6 recover the native allocation without an overlay.

The score moves from 94.52054794520548% to 95.11986301369864%, a gain of
29.10873287671258 weighted bytes. Instructions remain exactly 1,168/1,168,
references remain `460/0/0`, and the exact prefix grows from 66 to 112
instructions.

Live Binary Ninja callsites at `0x00411e4a`, `0x00411e67`, `0x00411e84`, and
`0x00411ea1` show that the four result-action buttons intentionally share the
working coordinate. Native leaves each two-argument call on the stack, adjusts
the same absolute Y slot, and performs one `add esp, 0x20` after the fourth
call. Separate one-shot coordinate scopes would therefore contradict that
native ownership pattern and are not introduced.

## Results-base publication order (2026-08-09)

After excluding the name-coordinate lifetime and the low-score branch cursor,
the next independent render residual begins at the `show_results` entry,
`0x00411973..0x004119b9`. Native first updates or clamps
`quest_results_anim_timer`, begins the integer-to-float alpha conversion, and
loads the Grim interface. It then republishes both saved `results_base_xy`
components into the working coordinate immediately before the alpha multiply.
The previous source restored that independent aggregate before the timer
branch.

Moving only `xy = results_base_xy` below the timer update recovers that native
publication boundary. Similarity rises from `4619.971746575343/4857`
(`95.11986301369864%`) to `4628.288527397261/4857`
(`95.29109589041096%`), a gain of `8.316780821917572` weighted bytes.
Instructions remain exactly `1168/1168`, prefix remains 112, and references
remain fully aligned at `460/0/0`. No coordinate storage, branch condition, or
render behavior changes.

## Results-record aggregate publication (2026-08-09)

The next independent residual is the `show_results` record renderer at
`0x00411a26..0x00411a73`. Native copies the working X coordinate through x87
into the temporary record aggregate before forming its Y coordinate, then
publishes the Y field while setting up `ui_text_input_render`. Separate field
assignments let VC6 defer the X bit-copy until after the call arguments were
pushed.

Constructing `record_xy` from both components recovers the native aggregate
publication and removes that residual. Similarity rises from
`4628.288527397261/4857` (`95.29109589041096%`) to
`4665.71404109589/4857` (`96.06164383561644%`), a gain of
`37.4255136986294` weighted bytes. Instructions remain exactly `1168/1168`,
the prefix remains 112, and references improve from `460/0/0` to `461/0/0`.

`results-record-aggregate-mutations.json` covers the direct constructor, an
equivalent vector addition, and copy-then-Y-offset forms. The first two are
byte-identical winners; the copy form regresses by `3.959186` weighted bytes,
adds two instructions, and loses one aligned reference. The retained direct
constructor is the simpler source form. The spec SHA-256 is
`fb67b6ceb56c3658d2a53d795ab92b64f4d0cae29096c29688f5a6680fd8c40a`;
the retained source SHA-256 is
`8b5bf0204e6dbcfbdf97e8cd46b61416ff7d3e3ff3ab814af98136fa27cefb24`.

## Results-separator aggregate publication (2026-08-09)

The next independent render residual is the phase-`-1` separator at
`0x0041151a..0x0041155d`. Native begins the X calculation, captures the Grim
interface, and publishes the two-field line aggregate around the renderer's
argument setup. Separate field assignments gave VC6 a later stack home for
the aggregate and deferred its stores.

Constructing `line_xy` directly from `xy.x - 4.0f` and `xy.y + 1.0f`
recovers most of that publication schedule. Similarity rises from
`96.06164383561644%` to `96.4041095890411%`. Instructions remain exactly
`1168/1168`, the prefix remains 112, and references improve from `461/0/0`
to `462/0/0`. The retained source SHA-256 is
`d718d6c08401adca272e2063a899480d30405f210ddb6988d54ce2a0019492f2`.
