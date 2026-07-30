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

- A function-local static `typo_vec2_t` aim vector starts 128 units to the right
  of player zero. Its mangled symbol proves the aggregate type; applying it to
  the live database merges the former scalar `typo_target_world_x/y` objects
  into named `.x/.y` fields. Its native one-bit guard and empty exit-time
  destructor account for `typo_runtime_init_flag`, `typo_target_world`, and
  `nullsub_71`.
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

## Port parity

The two spawn-side `typo_target_name_assign_random` calls precede the write to
`highscore_active_record.score_xp`. Python and Zig therefore now feed name-tier
selection from the explicitly staged prior-frame score, then update that score
from player 0 after the mode spawn loop. Previously both ports passed the live
player experience and advanced Typ-o name difficulty one frame too early.

## Remaining mismatch

Only eight normalized instructions differ. Native assigns the long-lived UI
position and the second spawn vector to the opposite two ordinary local-object
slots from the straightforward C++ candidate; all operations, branches,
constants, calls, references, frame size, and instruction count otherwise
agree. A layout-only aggregate could force those offsets, but there is no
source evidence for such an aggregate, so the natural vector objects are
retained.

The static Typ-o target now initializes from
`player_state_t::position.x/y`. The aggregate field view is byte-neutral at
98.43%, 508/508 instructions, a 33-instruction prefix, and 194/0/0
references.

## Recovery classification audit

The live Binary Ninja body and exact gameplay coordinator account for the
complete input, shooting, spawn, simulation, scoring, death, HUD, panel, and
caret behavior. Candidate and native each have 508 instructions with
`194/0/0` references. `--regions` confines all remaining differences to the
two ordinary vector-local slot assignments and their x87 loads/stores, so
recovery is `semantic-complete` with a `compiler` residual.

## Recorded local-lifetime evidence

`local-vector-lifetime-mutations.json` evaluates seven declaration-order,
aggregate-type, and reuse combinations for the left spawn vector. All six
complete variants are byte-neutral at 98.43%; the isolated reuse mutation is
intentionally incomplete and fails compilation. This rules out a reusable
function-scope vector as the source of the local-slot swap. The plan SHA-256 is
`0167262718b8194dd92d4db2d3eacfb7defa9ba1b05ca49370329dcdfb642404`.

`panel-y-scalar-lifetime-mutations.json` evaluates eleven scalar declaration
and use combinations for the UI panel position. The three complete pairings
all regress to 88.98%, lose the exact prefix, and change the reference audit;
the partial combinations fail compilation. The aggregate panel vector is
therefore retained as the evidenced source shape. The plan SHA-256 is
`8ec1d0778c5189c0bd31c664721cb04e7244f55aaf416ce1bf1a5ba610ccb79a`.

`spawn-vector-slot-interactions.json` then evaluates all 54 bounded one- and
two-site combinations across the two spawn-position aggregates and the panel
aggregate. It covers typed versus plain vectors, component assignment versus
construction, left-before-right and right-before-left declarations, one
reused spawn vector, panel declaration order, and the cross-product of each
spawn shape with each panel shape. All variants compile: 44 are byte-neutral
at 98.43% with the same 508 instructions and `194/0/0` references, while the
10 reused-vector combinations regress. No source form moves either residual
slot toward native. The complete plan SHA-256 is
`6e464b772ca736ac0fead378fdaf83eba8d5aa601232555b5f6e9f1ac8070ecb`.

Across three complete sweeps, 72 unique variants produce no improvement and a
three-sweep no-improvement streak. The experiment ledger therefore marks this
target `stalled`: the remaining two-slot permutation is bounded as a VC6
allocation residual unless a different recovered type or translation-unit
constraint supplies new evidence.
