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

The complete VC6 scratch currently matches 89.10% (1,088 target instructions,
1,087 candidate instructions, 14-instruction exact prefix). Reference auditing
reports 221 aligned references, no unresolved references, and 8 mismatches.
The remaining reference mismatches are instruction-alignment or strength-
reduced field-anchor differences such as `particle_style_id` versus the same
record's `intensity` field; no reference aliases are used.

The strongest source-shape evidence was VC6's treatment of index-based pool
loops. Writing the particle, secondary-projectile, and sprite-effect walks as
ordinary bounded index loops strength-reduces them to the native 0x38, 0x2c,
and 0x2c field-pointer strides. Removing cached secondary-projectile phase and
scale temporaries likewise recovers the native repeated field loads. The glow
pass uses the exact native 0.065 alpha constant and signed `% 2` parity test.

The Telekinetic walk now uses an ordinary aggregate `player_state_t` cursor.
VC6 strength-reduces it to the native aim-field induction register: native EBP
addresses `aim_x`, with `health` at EBP-0x2c and `aim_y` at EBP+4, while each
source increment advances one 0x360-byte player record. This removes the prior
`offsetof` container recovery without inventing a field alias and improves
both the byte score and reference agreement.

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

## Recorded beam lifetime sweep

Live native disassembly at `0x0042a250..0x0042a2ac` shows the Bubblegun beam
pass consuming the sine phase twice: it stores the unscaled half-width, reuses
the remaining x87 phase as the half-height, and only then scales both values.
The previous source named a separate `half_height` immediately, which let VC6
duplicate and reorder the phase. Reusing `phase_size` for the scaled
half-height describes the same arithmetic while recovering the native x87
lifetime.

`beam-x87-lifetime-mutations.json` is a schema-1, one-site plan with four
semantic spellings. Its SHA-256 is
`c24f8184b10de32a70f4df342712753aa4798b697fa55818819d29962231ac6c`.
All 4/4 variants were evaluated and recorded without truncation. Three were
byte-neutral; `reuse-phase-as-height` was the sole improvement and was
retained. It raises the whole-function match from 88.1029% to 88.5622%, adds
18.778 fuzzy-weighted bytes, and reduces the fuzzy gap from 486.354 to
467.576 bytes. Instruction counts and prefix remain 1,089/1,088 and 14, while
reference agreement improves from `218/0/10` to `220/0/9`. The retained source
SHA-256 is
`0815cae05ff7539e64c66f8731bf92f1e36cc486e46ab45ce5e1402963d21de0`.

Four additional complete matrices record useful boundaries:

- the 2/2 Telekinetic exit-shape sweep was byte-neutral;
- moving the player-index lifetime across the weapon pass was negative
  (`86.6850%`, `213/0/12`);
- the 7/7 explicit particle interior-cursor matrix was negative despite
  reducing some reference mismatches;
- all viable variants in the 23/23 weapon-zero lifetime matrix were
  byte-neutral.

An earlier scaffolding sweep is retained in `experiments.jsonl` because it
establishes that the direct `player_aim_x` symbol spelling is byte-neutral.
Its shared-threshold alternative contained a spec-label typo and is not
semantic evidence; the corrected 2/2 exit-shape sweep above supersedes it.

## Telekinetic ownership and aggregate-cursor wave

Live native disassembly at `0x00429d87..0x00429f32` fixes the player walk's
ownership. Search exhaustion resets the current hover timer and joins the
threshold test; a found bonus first renders its label and then joins the same
test. A successful threshold test calls `bonus_apply`, publishes state and
time, resets that player's timer, and exits the player walk directly.

`telekinetic-loop-ownership-mutations.json` (SHA-256
`b635fe4646afae577d74260708b66377db9c1cdb376abdac4a5801a48eedccd5`)
evaluated all 5/5 planned variants. Moving the apply and publication stores
inside the threshold condition was the sole winner. It raises the match from
88.5622% to 88.6437%, adds 3.329 fuzzy-weighted bytes, and removes two
candidate instructions while preserving the `220/0/9` reference audit.
Keeping the label-render block inside the search was neutral or worse.

A direct aggregate-player probe then replaced the aim pointer plus container
recovery with `player_state_t *player`. It raises the match from 88.6437% to
89.1034%, adds another 18.795 fuzzy-weighted bytes, and improves the reference
audit from `220/0/9` to `221/0/8` without changing the 1,087 candidate
instructions. The retained source SHA-256 is
`8b6caab0e2f17480cd8e6de223e484bae9f05c3e4ec595cc1e4aaf1220b8954c`.
Cumulatively, the two retained changes add 22.125 weighted bytes over the
post-beam baseline and reduce the fuzzy gap from 467.576 to 445.451 bytes.

Three complete follow-up sweeps bound the remaining nearby residual:

- `telekinetic-search-sentinel-mutations.json` (SHA-256
  `d14394683898b048e80c8635abc9becbfbe60ef2601c15c478a135037214b4ab`)
  evaluated all 3/3 flag, pointer, and index sentinels; none improved.
- `telekinetic-shared-threshold-mutations.json` (SHA-256
  `b8f4bd284e4ce74bd8e5d3199836429a6a867a2208a9efe155620ce5cf2a966f`)
  evaluated all 3/3 typed and signed shared-threshold spellings. Every variant
  compiled byte-identically to the retained natural found-flag form.
- `particle-loop-aggregate-mutations.json` (SHA-256
  `16d3345c9397adc343867ddc1ae91719a7bf1e5f86951f2ed3cdaa32d5a01a1b`)
  evaluated all 6/6 ordinary aggregate-pointer loop forms. Every variant lost
  byte score; the least-negative sprite and beam forms each lost 5.431
  weighted bytes and added one instruction despite removing one reference
  mismatch. The existing index loops therefore remain the honest source.

The complete 12-line experiment log has SHA-256
`2d2ecd79a6d5c09174439a891a5a50f8530eec8664e4a9f111ef203b60183625`.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live Binary Ninja output confirms the ordinary and weapon
bonus passes, Telekinetic hover/apply path, all three particle passes, exploding
secondary-projectile and sprite-effect passes, and the final `effects_render`
call through `0x004295f0..0x0042a5e8`. IDA and Ghidra independently retain the
same signature and six named helper calls. The first localized regions differ
only in branch displacement, zero materialization (`EBX` versus literal zero),
and x87 scheduling. All their scoped references resolve; the eight whole-function
audit mismatches remain visible as alignment or strength-reduced field-anchor
effects rather than being aliased away. Each candidate cursor is an evidenced
interior of the same player, particle, secondary-projectile, camera, or sprite
record used by native, so none is independent source-reference debt.
