# `perks_update_effects`

Native target: `crimsonland.exe` at `0x00406b40` (1437 bytes).

Exact match: 100.00%, 352/352 instructions, and 136/0/0 reference audit.

Binary Ninja and the MSVC candidate establish the complete runtime behavior:

- Regeneration gates on an odd CRT draw, then repeats the player-zero heal
  once per configured player. Greater Regeneration is not consulted in this
  native path.
- Lean Mean Exp Machine ticks every 0.25 seconds and awards ten experience per
  stored perk count. Death Clock and the three player bonus timers update once
  per configured player.
- Doctor, Pyrokinetic, and Evil Eyes share a radius-12 creature query.
  Pyrokinetic resets the target collision timer to 0.5 seconds, constructs five
  zero-vector particle arguments with intensities 0.8 through 0.2, and appends
  one random terrain effect. The query and all three perk tests read player
  zero directly, with no player-health gate. Python and Zig preserve that
  source in bug-compatible mode; corrected mode deliberately supports each
  living player's aim.
- Jinxed preserves a negative timer remainder when reseeding, damages player
  zero on the one-in-ten accident roll, skips creature killing while Freeze is
  active, and samples at most ten creatures with `rand() % 0x17f`. A successful
  kill awards the truncated base reward exactly once and plays the panned
  trooper pain sound.

The temporary two-float C++ value passed by reference to `fx_spawn_particle`
recovers the five repeated stack constructions exactly. The two bounded
player/creature loops recover the native global-index updates, including the
383-slot Jinxed modulus which excludes the last creature slot.

The Regeneration source is an ordinary local-index `for` loop over
`config_player_count`, even though its index is unused in the body. VC6
strength-reduces that loop to the native `dec ecx` countdown, keeps player
zero's health on the x87 stack, reuses the configured count for the later
per-player loop, and places the false-path reload in the exact native cold
block. Encoding the optimized countdown directly was semantically equivalent
but produced the wrong block order; restoring the plausible pre-optimization
source shape resolves the complete function without artificial control flow.

The Lean Mean timer store at `0x00406bc6` and the shield, Fire Bullets, and
speed-bonus stores at `0x00406c95`, `0x00406cc2`, and `0x00406cef` preserve
PC=24 subtraction results. Both ports now state those boundaries explicitly.
Python previously retained host-double remainders: at 36 Hz it awarded the
quarter-second Lean Mean XP tick on frame 9 and expired all three combat
bonuses, while native retains `1.1175871e-8` through that frame and crosses the
boundary on frame 10.

Regeneration's stored health add at `0x00406b96..0x00406bb4` and Death Clock's
multiply-then-subtract at `0x00406c4e..0x00406c5c` use the same PC=24 frame
arithmetic. Both ports now expose those operations directly. Python's former
host-double Death Clock drain left `+0.000001` HP after 900 updates at 30 Hz;
native is already at `-0.0008849055` on that frame and clamps the dead player
to zero on the following update.

Pyrokinetic's target-timer store at `0x00406db9`, Jinxed's proc-timer store at
`0x00406f85`, and the Jinxed reseed chain at `0x00406ffb..0x00407011` also
retain PC=24 results. At 36 Hz, both native timers remain at `1.1175871e-8`
through frame 9 and proc on frame 10. Python previously crossed on frame 9,
consuming Jinxed RNG or emitting the Pyrokinetic particle burst one update
early. The two ports now also make Jinxed's stored five-health damage and
`frame_dt * 20` creature lifecycle subtraction explicit.

The recovered effect boundaries now carry position aggregates end to end:
Pyrokinetic's aim is a `vec2f_t`, the Jinxed creature cursor is a
`const vec2f_t *`, and the panned sound takes that same typed position. These
changes preserve the exact 352/352 instruction match and all 136 references.
The radius query now receives `player_state_t::aim` directly, eliminating its
last interior-field cast without changing codegen.
