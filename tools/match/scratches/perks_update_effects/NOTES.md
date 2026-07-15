# `perks_update_effects`

Native target: `crimsonland.exe` at `0x00406b40` (1437 bytes).

Work in progress: 90.06% normalized match, 9/352-instruction exact prefix,
352/352 candidate instructions, and 135/0/0 reference audit.

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
  one random terrain effect.
- Jinxed preserves a negative timer remainder when reseeding, damages player
  zero on the one-in-ten accident roll, skips creature killing while Freeze is
  active, and samples at most ten creatures with `rand() % 0x17f`. A successful
  kill awards the truncated base reward exactly once and plays the panned
  trooper pain sound.

The temporary two-float C++ value passed by reference to `fx_spawn_particle`
recovers the five repeated stack constructions exactly. The two bounded
player/creature loops recover the native global-index updates, including the
383-slot Jinxed modulus which excludes the last creature slot.

The honest residual is VC6 basic-block placement: native leaves the
Regeneration false-path player-count reload out of line between Death Clock's
subtract and zero-health blocks, while the equivalent structured candidate
places it immediately after the heal block. This changes short versus near
branch encodings and therefore later branch labels, but not the instruction
count or audited references. VC6.5pp, VC7.0, `/G6`, and persistent-local
variants diverged in floating-point tests, scheduling, or register allocation
and were rejected rather than retained as matching aids.
