# `bonus_render`

Native target: `crimsonland.exe` at `0x004295f0` (4,088-byte manifest
extent, 1,088 instructions in the current Binary Ninja analysis).

Live Binary Ninja and the retained IDA artifact show that this callback owns
more than pickup sprites: it renders ordinary and weapon bonus icons, performs
the Telekinetic aim-hover label and delayed pickup path, renders three particle
styles plus exploding secondary projectiles and sprite effects, then delegates
the remaining effect pool to `effects_render`.

The icon evidence also revealed that the shell and inner icon have distinct
fade envelopes and that the icon size pulse is `pow(sin(phase), 2.0)`, not a
fourth power. The modern renderer parity fix is tracked separately from this
matching scratch.

The complete VC6 scratch currently matches 87.55% (1,088 target instructions,
1,089 candidate instructions, 14-instruction exact prefix). Reference auditing
reports 218 aligned references, no unresolved references, and 10 mismatches.
The remaining reference mismatches are instruction-alignment or strength-
reduced field-anchor differences such as `particle_style_id` versus the same
record's `intensity` field; no reference aliases are used.

The strongest source-shape evidence was VC6's treatment of index-based pool
loops. Writing the particle, secondary-projectile, and sprite-effect walks as
ordinary bounded index loops strength-reduces them to the native 0x38, 0x2c,
and 0x2c field-pointer strides. Removing cached secondary-projectile phase and
scale temporaries likewise recovers the native repeated field loads. The glow
pass uses the exact native 0.065 alpha constant and signed `% 2` parity test.

The Telekinetic walk retains its native aim-field induction pointer but now
types it as `vec2f_t`. An `offsetof(player_state_t, aim_x)` container recovery
provides the named player `health` field instead of the former `aim[-11]`
alias, while aim and bonus positions use named vector components. A shadow
probe verified byte-for-byte identical candidate output and unchanged
reference agreement.

The nearby-bonus search now uses a natural `nearby_bonus_found` flag instead of
a reconstruction-only `goto`. VC6 optimizes the flag away and emits
byte-for-byte identical code: search exhaustion resets the current hover timer,
the found path owns label rendering, and both paths share the Telekinetic
threshold test. The induction pointer now starts directly at
`player_state_table[0].aim`, and the outer guard retains the existing player
index; both type-safe expressions are likewise matcher-neutral.

The three particle render passes now use the canonical `particle_t` directly
instead of a scratch-local 0x38-byte record with two padding regions. Static
analysis shows that particle styles reinterpret the four floats at
`+0x14..+0x20` as either scale/age or RGBA, the float at `+0x24` as
intensity/progress, and `+0x2c` as spin/rotation. Those overlays now live in
the shared type and are authoritative in the Binary Ninja importer. The
canonical particle refactor was byte-neutral before the later source-shape
improvements below; both particle constructors remain exact at 67/67.

Narrowing the icon-phase and Telekinetic locals to their actual source
lifetimes recovers the native register schedule without changing any loop
bound or branch. In particular, the player index is initialized immediately
before the player walk, and the nearby-bonus cursor remains scoped to the
Telekinetic search. This raises the whole-function result from 85.64% to
87.55% and improves the reference audit from `212/0/12` to `218/0/10`.
