# `typo_gameplay_update_and_render`

Native target: `crimsonland.exe` at `0x004457c0` (2,082 bytes, 508
instructions).

Live Binary Ninja evidence and the exact matched gameplay coordinator recover
the complete Typ-o-Shooter frame loop. MSVC 6.5 `/O2 /GB` produces the same
508 instructions at:

```txt
match=98.43% prefix=33/508 target_insns=508 candidate_insns=508 refs=194/0/0
```

## Recovered source shape

- A function-local static two-float aim vector starts 128 units to the right of
  player zero. Its native one-bit guard and empty exit-time destructor account
  for `typo_runtime_init_flag`, `typo_target_world_x/y`, and `nullsub_71`.
- Enter submits any nonempty buffer, increments the attempt count, resolves the
  first active creature with that name, and requests one aimed shot. The
  unmatched command `reload` requests a reload instead.
- Input polling consumes at most one character per frame. Backspace always
  plays one of the two type-click sounds. Ordinary characters append only
  while the length is below 17, but a full buffer is still terminated and
  still plays the click sound; the first broad source draft incorrectly
  skipped that full-buffer sound path.
- The mode applies perk effects, the native 0.3 time scale, creature and
  projectile simulation, and the bespoke `player_fire_weapon` loop. It then
  forces Shotgun weapon id 3 and ammo 30 for player zero. This evidence also
  corrected an enum-migration regression that had selected Sawed-off Shotgun
  id 4 in both ports.
- Spawn cooldown decreases by `player_count * frame_dt_ms`, then adds
  `3500 - elapsed_ms / 800` until nonnegative, with a minimum increment of 100.
  Every event emits a type-4 creature at the right edge and a type-2 creature
  at the left edge, both following the same cosine y path and receiving random
  Typ-o names.
- Spawn tint uses the evidenced clamped channels
  `(elapsed + 1) * 8.33333343e-6 + 0.3`,
  `(elapsed + 1) * 10000 + 0.3`, and
  `sin((elapsed + 1) * 0.000100000005) + 0.3`. The unusual green multiplier is
  native, not a transcription correction.
- Bonuses are cleared, score/time/weapon-use state is updated, death queues the
  ordinary game-over state and music transition, and the shared perk prompt,
  HUD, world, labels, and UI elements are rendered.
- The custom typing panel uses the HUD panel texture at
  `(-1, screen_height - 144)` with size `182 x 53`, prompt format `">%s"`, and
  an underscore cursor at `text_width + 14` whose alpha alternates between 1.0
  and 0.4.

The three reference aliases identify the compiler-generated local-static guard,
object, and destructor with their proven native storage/callbacks. They do not
relax the instruction or operand audit.

## Remaining mismatch

Only eight normalized instructions differ. Native assigns the long-lived UI
position and the second spawn vector to the opposite two ordinary local-object
slots from the straightforward C++ candidate; all operations, branches,
constants, calls, references, frame size, and instruction count otherwise
agree. A layout-only aggregate could force those offsets, but there is no
source evidence for such an aggregate, so the natural vector objects are
retained.
