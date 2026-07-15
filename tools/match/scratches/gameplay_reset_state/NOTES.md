# `gameplay_reset_state`

Native target: `crimsonland.exe` at `0x00412dc0` (1,639 bytes).

Live Binary Ninja evidence recovers the complete gameplay-session reset. It
clears the 16 bonus HUD records, resets Survival, Tutorial, quest, perk, bonus,
high-score, player, projectile, sprite-effect, secondary-projectile, creature,
spawn-slot, and FX-queue state, rebuilds weapon/perk/effect availability, and
finishes by generating a new random terrain. The six creature type records are
populated with their native texture names, four death sounds, two attack
sounds, animation rates, frame bases, corpse frames, and animation flags.

The two stack dwords are explained by ordinary C++ vector temporaries. Assigning
`vec2(width * 0.5, height * 0.5)` to the camera offset produces the native x87
stores and integer copies. Assigning `vec2(-1, -1)` to each player's move target
reuses the same temporary storage. Treating those values as independent float
scalars eliminates the native frame and is materially worse. The two-float
`player_aux_timer` clear naturally lowers as an eight-byte `memset`, producing
the native zero register and both stores.

Binary Ninja also establishes that `creature_t::target_player` is one byte:
the reset writes only `dl`/`bl`, and the field is read as a player index. The
shared recovered type now records that byte plus three bytes of padding without
changing the 0x98-byte creature stride. Three previously raw globals are named
conservatively: the initialized creature-type count, a write-only auxiliary
Survival handout flag, and a write-only float in the gameplay timer block. Each
write-only name is explicitly limited to its sole Binary Ninja xref.

The current honest VC6.5 result is 90.58%: 307 target instructions versus 309
candidate instructions, with references `206/0/1`. The remaining mismatch is
not missing behavior. VC6 rebases the first typed HUD walk for its record-end
comparison, adding one `lea` and saving `edi` four instructions early; it also
chooses `creature_t::state_flag` rather than `target_player` as the creature
walk's induction base. The other differences are independent sound-table and
camera-flag scheduling. The typed record walks and natural sequential sound
bank assignments are retained instead of hiding those residuals with volatile
state, dummy dependencies, hard-coded addresses, or artificial register
constraints.
