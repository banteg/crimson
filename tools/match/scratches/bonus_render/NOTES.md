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

The complete VC6 scratch currently matches 89.93% (1,088 target instructions,
1,087 candidate instructions, 14-instruction exact prefix). Reference auditing
reports 223 aligned references, no unresolved references, and 6 mismatches.
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

At that checkpoint, the complete 12-line experiment log had SHA-256
`2d2ecd79a6d5c09174439a891a5a50f8530eec8664e4a9f111ef203b60183625`.

## Sprite-effect publication ownership

Native `0x0042a53e..0x0042a5b8` keeps the final smoke-effect loop's induction
register anchored at `sprite_effect_t::scale`: `active` is read at `-0x28`,
`rotation` at `-0x14`, and the color and position fields at their corresponding
negative displacements. The prior loop-local `sprite_effect_t *effect` alias
made VC6 anchor the same 0x2c-byte walk at `rotation`, leaving the body
instruction-identical except for every member displacement.

Publishing the fields directly from `sprite_effect_pool[effect_index]` is the
natural global-array spelling used elsewhere in the gameplay source and lets
VC6 recover the native `scale`-owned induction without an interior pointer or
container recovery. Merely narrowing the aggregate alias to the active branch
was byte-neutral. Removing it raises the whole-function match from 89.1034% to
89.9310%, adds 33.832 fuzzy-weighted bytes, and improves the reference audit
from `221/0/8` to `223/0/6`, with instruction counts and prefix unchanged. The
entire smoke-effect loop body now matches instruction-for-instruction; its only
reported differences are branch-label displacement inherited from earlier
regions. The retained source SHA-256 is
`6e96d59dd82e6d6beb05d87453cf2b6d50d55151d93872ed918165f63f9e8d5f`.

The scratch is classified `semantic-complete` with compiler and aligned-
reference residuals.
Fresh live Binary Ninja output confirms the ordinary and weapon
bonus passes, Telekinetic hover/apply path, all three particle passes, exploding
secondary-projectile and sprite-effect passes, and the final `effects_render`
call through `0x004295f0..0x0042a5e8`. IDA and Ghidra independently retain the
same signature and six named helper calls. The first localized regions differ
only in branch displacement, zero materialization (`EBX` versus literal zero),
and x87 scheduling. All their scoped references resolve; the six whole-function
audit mismatches remain visible as alignment or strength-reduced field-anchor
effects rather than being aliased away. Each candidate cursor is an evidenced
interior of the same player, particle, secondary-projectile, camera, or sprite
record used by native, so none is independent source-reference debt.

## Current Telekinetic control replay

The earlier `telekinetic-search-sentinel-mutations.json` plan predates the
retained aggregate-player cursor and no longer matches the current source: its
search pattern is anchored on the old `player_aim` spelling. It is historical
evidence only, not a current-baseline exclusion.

Three fresh plans therefore replay the nearby control shapes against the
89.9310% source:

- `current-telekinetic-found-arm-mutations.json` (SHA-256
  `f2b66075c3a6d876e366efeee503b9479542c0b76e060f73a06378b0795f3954`)
  evaluates all 4/4 truth-test and empty-arm spellings;
- `current-telekinetic-apply-guard-mutations.json` (SHA-256
  `2c7a71f9b85993304de85eeebc814d6305a409a6ade6e51a4cc236a1e2b504c0`)
  evaluates all 6/6 nested, inverted, equivalent-threshold, and named-condition
  spellings;
- `current-telekinetic-control-interactions.json` (SHA-256
  `129bef5cdb0d092de7f1fc96135bed0da0a77cffa9b29927049df44cb3c7c706`)
  evaluates all 8/8 selected one- and two-site structural interactions.

All 18 evaluations (14 unique variants) are byte-identical to the current
baseline, including every two-site combination. A manual replay of the old
full player-index lifetime
move is current-applicable but negative: moving initialization ahead of the
weapon pass drops the result to 88.51%, adds one candidate instruction, and
changes the reference audit from `223/0/6` to `218/0/8`. It is not retained.
The restored scratch remains 89.93%, 1,087/1,088 instructions, prefix 14, and
`223/0/6`. The complete 15-line experiment log now has SHA-256
`8b88b520f5cf72783b1a82e974af7e638fe28e8519e757661132ecba4fc92cb6`.

## Current weapon-zero and particle-owner replay (2026-08-12)

Native `0x00429baa..0x00429d8d` materializes zero in `EBX` before the weapon
pass, reuses it for the texture stage, loop index initialization, and rotation,
then compares the player count against the same value before incrementing
`EBX` as the Telekinetic player index. The historical zero-lifetime matrix
predated the retained Telekinetic and sprite-loop changes, so all 23 variants
were replayed against the current 89.93% source. All 16 compile-valid one- to
four-site combinations remain byte-identical; the seven dependent variants
without the required declaration fail as expected. Explicitly coupling the
later player index to unrelated weapon-pass zero arguments would be a synthetic
dependency and is not a retainable source shape.

The six ordinary aggregate-pointer forms for the glow, sprite, and beam
particle walks were also replayed against the current source. Every form
regresses. The closest sprite and beam cursors each lose 5.43 weighted bytes
while reducing the aligned-reference mismatch count from six to five; the
other forms lose 7.91--118.33 bytes. This confirms that the current indexed
loops remain the strongest natural reconstruction. Across 29 current
evaluations there is no source improvement, so the 1,087/1,088 instruction,
`223/0/6` baseline is retained unchanged.

## Direct particle-pool ownership recovery (2026-08-14)

A fresh live comparison revisited the three particle passes after the retained
sprite-effect owner correction. Native keeps independent interior-field
induction anchors for the glow, sprite, and beam walks. The source still hid
all three behind a shared `particle` pointer and branch-local aggregate aliases;
VC6 consequently selected different record bases even though each loop body
was otherwise equivalent.

Publishing each field directly from `particle_pool[index]` is the same natural
global-array spelling already retained for `sprite_effect_pool`. It improves
all three passes independently and additively without changing instruction
count or control flow:

- glow ownership adds **18.795402** weighted bytes and changes references from
  `223/0/6` to `225/0/4`;
- sprite ownership adds another **41.349885** weighted bytes and changes
  references to `227/0/2`;
- beam ownership adds another **26.313563** weighted bytes and closes the
  reference audit at `229/0/0`.

Together the corrections raise the match from **89.931034%**
(`3676.380690/4088`, gap `411.619310`) to **92.045977%**
(`3762.839540/4088`, gap `325.160460`). Candidate and native remain
1,087/1,088 instructions with prefix 14. Removing the now-unused shared alias
is byte-neutral.

`particle-direct-index-ablation-mutations.json` (SHA-256
`fb0a17c6c36e429397b1cd049d4e2c596dd6abf39136bea9e80b286abcf2b33d`)
records all 7/7 one-, two-, and three-pass ablations. Each branch-local pointer
loses exactly its measured contribution and two references; the three-site
ablation returns exactly to the former 89.931034%, `223/0/6` baseline. This
rules out a whole-function alignment accident.

The remaining beam x87 region was replayed against the recovered owner shape.
`current-beam-x87-lifetime-mutations.json` (SHA-256
`ae04dc0d7328a2900e7c12afc06ef806b581ce78217affbb5471d0046e6423ce`)
tests six separate-height, unscaled-width, compound, named-scale, and pointer
lifetimes. Three are byte-neutral; two lose 26.313563 weighted bytes and one
adds three instructions while losing 16.444683. None reproduces native's
unscaled-width spill/reload schedule, so the canonical scalar form remains.

The retained source SHA-256 is
`9795760dd93f87c8e9389371e5599033fe8a398fa952f05ae14b9cde1958ac54`.
With all aligned references now resolved, the scratch remains
`semantic-complete` with only a compiler residual.
