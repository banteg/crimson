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

The recovered local-index `for` loops are important source evidence. VC6
strength-reduces the 16-entry HUD loop to a pointer based at `slide_x`, so its
end comparison needs no rebase. The 384-entry creature loop keeps the integer
index in `edi` and a pointer based at `target_player` in `esi`, exactly matching
the native negative field offsets and post-increment `anim_phase` store. The
native sound-table scheduling is recovered by placing the lizard and second
spider's second death sound after their animation constants.

The current honest VC6.5 result is 99.02%: 307/307 instructions and references
`213/0/0`. Only two independent scheduling swaps remain. Native places the two
one-byte perk/bonus flags before the 256-byte weapon-usage `memset`, and places
the second `-1.0f` vector-temporary store between the two dwords of the
eight-byte player auxiliary clear. All six natural orderings of the camera,
flags, and clear operations, plus reusable-temporary and scalar-clear variants,
were checked; they either retain these swaps or diverge more broadly. The
plausible source is retained instead of adding volatile state, dummy
dependencies, hard-coded addresses, or artificial register constraints.
