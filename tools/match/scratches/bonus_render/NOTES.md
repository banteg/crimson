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

The complete VC6 scratch currently matches 85.64% (1,088 target instructions,
1,091 candidate instructions, 14-instruction exact prefix). Reference auditing
reports 212 aligned references, no unresolved references, and 12 mismatches.
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
