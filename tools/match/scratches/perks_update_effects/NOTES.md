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
