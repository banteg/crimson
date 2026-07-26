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

The complete VC6 scratch currently matches 88.10% (1,088 target instructions,
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

## Recorded weapon-icon lifetime sweep

A fresh live Binary Ninja bundle from target
`3023:2:9499448411019345244` has SHA-256
`28887c3512886a9acc5b25211d47257f9bd9f509439af5edd19a21b24aa23893`.
In the weapon-icon pass, native `0x00429c15..0x00429c68` computes the icon
fade, duplicates it into `color.a`, and then overwrites the same stack local
with the pulsed icon scale. In particular, the stores and later multiply at
`0x00429c24`, `0x00429c64`, and `0x00429c68` all address the same pre-call
local. The prior scratch instead kept separate `fade` and `icon_scale` locals,
which produced the paired candidate `[esp+0x20]` versus native
`[esp+0x1c]` regions despite identical rendering behavior.

`weapon-icon-lifetime-mutations.json` is a schema-1, one-site plan covering
three ordinary in-place spellings: compound multiplication and explicit
left- and right-sided products. Its SHA-256 is
`f139ff0df95dce97ac03eeaff8ec2c4485624a69e374c77e64f4026fb1e8c7f4`.
All 3/3 possible single-site variants were evaluated and recorded with no
truncation:

| rank | variant | source SHA-256 | match | fuzzy gap |
| ---: | --- | --- | ---: | ---: |
| 1 | `in-place-scale-right` | `f55ed7b1f7c4a4c169297228ec24a2e0112a07b4e9fb334ee1923faee5c949a4` | 88.1029% | 486.354 |
| 2 | `in-place-scale-left` | `e29ea43c31ac3b13e6dc703f83b48f0e6ebbe1080a629082f2e63d7ca5610a29` | 88.1029% | 486.354 |
| 3 | `in-place-compound` | `c3806ca3d568dbe34451d5141d6a8a023317c69ba7fdd0b8e991b6a502ea597b` | 88.1029% | 486.354 |

All three variants are byte-identical. The retained right-sided product is
the ranked winner and directly describes the native factor-times-existing-
scale x87 schedule. Relative to the baseline source SHA-256
`9df2e14359f1673815a0d1cdacd3a034cf74bbf57a3d9531e0d638e66233293b`,
it raises the ratio from 87.5517% to 88.1029%, adds 22.534 fuzzy-weighted
bytes, and reduces the gap from 508.887 to 486.354 bytes. The 1,089/1,088
candidate/native instruction counts, prefix 14, first mismatch offsets 60/60,
and `218/0/10` reference audit are unchanged. The formerly visible
`0x00429c24` and `0x00429c64` stack-slot regions disappear from a fresh
focused region report. Because the three positive variants are alternatives
at one mutually exclusive site, no cross-site interaction exists to test.
The complete sweep is recorded in `experiments.jsonl`, whose SHA-256 is
`17d2b41e6c6f230957cd91bb4b38910d44f3446379ec393d62651e194044b24e`.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live Binary Ninja output confirms the ordinary and weapon
bonus passes, Telekinetic hover/apply path, all three particle passes, exploding
secondary-projectile and sprite-effect passes, and the final `effects_render`
call through `0x004295f0..0x0042a5e8`. IDA and Ghidra independently retain the
same signature and six named helper calls. The first localized regions differ
only in branch displacement, zero materialization (`EBX` versus literal zero),
and x87 scheduling. All their scoped references resolve; the ten whole-function
audit mismatches remain visible as alignment or strength-reduced field-anchor
effects rather than being aliased away. Each candidate cursor is an evidenced
interior of the same player, particle, secondary-projectile, camera, or sprite
record used by native, so none is independent source-reference debt.
