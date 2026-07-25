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

The verified VC6 build is 1,164 normalized instructions against 1,168 native,
scores 86.45%, and audits 429 references as resolved, zero as unresolved, and
9 as mismatched within nonmatching instruction regions. The remaining broad
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

The panel geometry now uses the recovered UI element and vertex position
aggregates. This type-only cleanup preserves the 1,164/1,168 instruction
build, 86.45% score, and 429/0/9 reference audit.

The quest-results name editor is now imported as its 32-byte character array,
and the compiler-generated zero-based scan variable at `0x0041184d` is
persisted as the integer `first_non_space`. The live decompiler therefore
renders the validation loop through
`quest_results_name_input_buffer[first_non_space]` rather than an untyped
absolute base plus a `void *` offset. Matching remains unchanged.
