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

The verified VC6 build is 1,165 normalized instructions against 1,168 native,
scores 86.50%, and audits 437 references as resolved, zero as unresolved, and
2 as mismatched within nonmatching instruction regions. The remaining broad
delta is register/stack allocation: native uses a 24-byte frame and caches the
working coordinates in `edi`/`ebp`, while the natural reconstruction uses a
32-byte frame for separately named panel, button, and record positions and
hoists the constant-one and name-buffer values. Reusing or artificially
overlapping those positions made the source less faithful and reduced the
instruction match, so the residual is recorded rather than forced.

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
all compile to the same 1,165-instruction candidate: 4,201/4,857 fuzzy bytes,
86.4981%, a 1/1,168 exact prefix, and `437/0/2` references. Since no single
improved the baseline, no interaction was run and `scratch.cpp` remains
unchanged. This records the localized scheduling delta as compiler residual
without aliases, forced dependencies, volatile barriers, or storage overlap.

The panel geometry now uses the recovered UI element and vertex position
aggregates in native operand order. The post-record spacing remains visibly
split into its native 78- and 6-pixel additions, and the button alpha stores
follow the native high-scores/play-next schedule. Together these source-shape
recoveries move the build to 1,165/1,168 instructions, 86.4981%, and a
437/0/2 reference audit without hiding either remaining mismatch.

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
within three instructions of native at 1,165/1,168 with `437/0/2`
references. Both mismatches align the repeated `sfx_ui_clink_01` load against
the adjacent, already-recovered health/perk reveal accumulators after the
stack-allocation divergence. They remain visible and unaliased, but are not
independent reference debt. A temporary overlay that reused the panel position
to chase the native `0x18` frame was rejected: it fell from 86.50% to 72.68%,
lost 27 aligned references, and introduced five additional reference
mismatches.
