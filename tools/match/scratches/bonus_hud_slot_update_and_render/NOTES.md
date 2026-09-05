# `bonus_hud_slot_update_and_render`

Native target: `crimsonland.exe` at `0x0041a8b0` (1566 bytes).

Live Binary Ninja evidence recovers a three-argument function: a pointer to the
current HUD Y cursor, a slot index, and the caller's transition alpha. The
callsite at `0x0041c7a9` pushes the transition alpha, slot index, and Y pointer
before the call. The previous two-argument analysis signature omitted the alpha
read from the third stack argument; `analysis/ghidra/maps/name_map.json` now
records the corrected prototype.

The function advances a 0x20-byte bonus slot's slide X from its primary and
optional alternate timer, clamps it at -2, retires it below -184 only when no
later slot remains active, draws the normal or compact indicator panel and icon,
then renders one or two timer bars. Normal indicators also draw the slot label;
compact indicators intentionally omit it.

The recovered source compiles to 79.80% with the calibrated
`msvc6.5 /O2 /GB` profile: 407 candidate instructions against 405 native,
an exact 0x18-byte local frame, and 72/0/0 audited references. Explicit
component construction for the compact primary, normal secondary, and normal
single bars improves the native store and address schedule without adding
artificial dependencies.

The remaining delta is compiler-shaped. Native VC6 shrink-wraps the `edi` save
until the render path after the off-screen retirement return, while the
available compiler saves it in the prologue. Repeated color/vector temporary
stores are also scheduled differently around the progress-bar calls. VC6.6 is
identical; `msvc6.5pp`, MSVC 7.0, `/G6`, and an explicit shared-tail rewrite all
regress, so no compiler override or ordering-only construct is retained.

## Recorded compact primary-bar lifetime sweep

A fresh live Binary Ninja bundle from target
`3023:2:9499448411019345244` has SHA-256
`47c10d50e38efe30522504753fa10e1d918d786fcceb0b862c68c106bebff568`.
The first compact-mode primary progress bar at
`0x0041abb2..0x0041ac15` provides a bounded view of the remaining temporary
schedule. Native starts the X calculation at `0x0041abb2`, loads the timer
pointer at `0x0041abbb`, stores position X at `0x0041abca`, and keeps the Y
calculation live while preparing the call slots. It then materializes the
color components beginning at `0x0041abdc`, stores position Y at
`0x0041ac00`, computes the ratio, and calls `ui_draw_progress_bar` at
`0x0041ac15`. The scratch preserves those values and the same call but
schedules the independent color stores earlier.

`compact-primary-bar-lifetime-mutations.json` is a schema-1, one-site plan
covering seven ordinary C++ spellings: reversed position/color declarations,
named X and timer lifetimes separately and together, precomputed position
scalars, position-plus-timer staging, and copy initialization. Its SHA-256 is
`53405059fe1d0be54db41cd25559b0063a129cfc496ea39576d4ee188c037228`.
All 7/7 possible single-site variants were evaluated and recorded without
truncation:

| rank | variant | source SHA-256 | weighted delta |
| ---: | --- | --- | ---: |
| 1 | `position-scalars-before-color` | `7bf155f05db5a7c53c62318cc006c756b8ad7193b2b3d8d38b1baf63e1eb420a` | 0 |
| 2 | `position-before-color` | `72f99b18360c541540dffe9ccc87e312d990dc54ee179aee8c72cf7ae067125d` | 0 |
| 3 | `position-and-timer-before-color` | `28f30174abe43b5eeaca8ed9d50b8311ba26b3a090e81f8127973a77595b848f` | 0 |
| 4 | `named-x-before-color` | `3f17149fedfbad0c5788718fe4ba72578187d4bbb83a69fc5d00a3a87bee125e` | 0 |
| 5 | `named-x-and-timer-before-color` | `3b5db0d5bdae57ca5e61f4a9de81aac1b22d11947232bb8940128e9518045dc6` | 0 |
| 6 | `named-timer-before-color` | `af20c969bd060bd93e95789d72ded1efab75182efb03b9dcc910debc55fb0897` | 0 |
| 7 | `copy-initializers` | `d0f512ebb65fc698b86a99cf7b22913247079a642518531e7028ea9cc4aea78c` | 0 |

VC6 canonicalizes every variant to the baseline object: 77.8325%, a
347.143-byte fuzzy gap, 407/405 candidate/native instructions, prefix 5, and
`69/0/0` references. The unchanged semantic source has SHA-256
`f858c47e12c5f7782f67fc606d0c0fe7ea0ec064ce778a79bf83d3af06ed37d1`.
No single mutation improved, so no interaction was eligible and no source
variant was retained. The complete record is in `experiments.jsonl`, whose
SHA-256 is
`577cc28944ad80f942daa1c7d44e1ed0270ade2abc5c68d43648ab421d48efe8`.
This local canonicalization strengthens the compiler-scheduling
classification without adding artificial dependencies.

## Recorded remaining-bar construction sweeps

The other five progress-bar construction regions were then tested against the
live native schedules with ordinary typed and raw-array spellings. Four
schema-1 plans cover the initial raw-array probe, a typed default-constructor
control, all remaining one-site typed variants, and the complete interaction
matrix for the independently improving sites:

| plan | SHA-256 | evaluated / possible | best weighted delta |
| --- | --- | ---: | ---: |
| `secondary-bar-construction-mutations.json` | `443b6b87e17710e44040f13946386db156c4b75180fdf6630b4e2249e61fdb95` | 10 / 10 | +7.7143 |
| `normal-secondary-typed-construction-mutations.json` | `ef816fdfdfc92c573a79ac6658f3bbba2ec2c582c5c22b085ccaabce7ef364c7` | 7 / 7 | +7.7143 |
| `remaining-bar-construction-mutations.json` | `99746d53fc91a5a87f19a943a49dc9b80c264beea14dab708248d9f95133cd91` | 15 / 15 | +15.4286 |
| `improving-bar-interactions.json` | `54f225bf77f1caf121b5f95352465f7ba7ff0bff910f65d0be98857d983fb436` | 7 / 7 | +23.1429 |

The raw-array probe first showed that explicit construction of the normal
secondary bar gains one exact audited reference. Adding unused default
constructors is byte-neutral, and the typed component-assignment form produces
the identical improvement, so the typed form is retained. From that improved
baseline, normal single gains 15.4286 weighted bytes while normal primary and
compact primary each gain 7.7143; compact single is byte-neutral and compact
secondary regresses by 3.8571.

The complete three-site interaction matrix is not additive. Normal primary
combined with normal single changes stack-slot coalescing, drops two candidate
instructions, and regresses the score. The retained winner therefore combines
compact primary with normal single, gaining 23.1429 weighted bytes and two
exact references over the already-improved normal-secondary baseline. The
final source SHA-256 is
`1ded7121317cee59418e6bce73809b847d6daea91e55f8871266b45b32a59267`;
the complete append-only experiment log SHA-256 is
`29db752486c8787c2971b26d31c5e96d80b7d8f039e315051af839d62d2c30a0`.

Recovery is classified `semantic-complete` with a `compiler` residual. The
candidate preserves the native 0x18-byte frame, emits 407 instructions against
405 native instructions, and resolves all `72/0/0` audited references at
79.80%. Live instructions `0x0041a963..0x0041a976` perform the off-screen
cursor advance and return before `push edi` at `0x0041a97d`; a scoped
render-only Y-cursor alias compiled byte-identically, confirming that the
remaining prologue delta is compiler shrink-wrapping rather than missing
behavior.

## Compact-tail placement and pointer-lifetime bound

Live native control flow makes the compact two-bar arm fall through to the
shared color/cursor/return tail at `0x0041ac79`, while the single-bar arm at
`0x0041acb1` jumps backward into it. The available compiler instead places
the single-bar body before the shared tail. Two semantically equivalent
early-return plans test both source-side tail placements:

| plan | SHA-256 | evaluated |
| --- | --- | ---: |
| `compact-tail-placement-mutations.json` | `a680642e2b8120a99bddb22da61384049717a9d22d5a4617b801b72f6576d7d0` | 2/2 |
| `compact-single-tail-placement-mutations.json` | `f00176abdea00b303ec29526daf1f2c7003ba4503fa681d8a16d44cfdddc45c1` | 1/1 |

VC6 canonicalizes all three variants to the same object. They remove one
candidate instruction and gain 9.264752510129 weighted bytes, but introduce
one mismatched audited call reference. The reference-clean baseline is
therefore retained; a nominal fuzzy gain is not accepted as progress when it
adds native-reference debt.

The compact primary-bar schedule was then bounded independently.
`compact-primary-pointer-lifetime-mutations.json` has SHA-256
`6bf7bb4502dd346237dbde76de227b20f7e91c33cc5ef698a54623117113270a`
and evaluates all 9/9 named timer, position, color-pointer, and ratio
lifetimes. All seven pointer-only forms compile byte-identically. The two
named-ratio forms add 15 instructions, lose 280.195543271722 weighted bytes,
and lose sixteen aligned references. No variant wins.

These results leave the native tail placement, delayed color stores, and
render-only `edi` save classified as backend block-layout, scheduling, and
shrink-wrapping behavior. The canonical source remains reference-clean at
1,249.714285714286/1,566 weighted bytes (`79.80295566502463%`),
407/405 instructions, prefix 5, and `72/0/0` references.

## Batch 08 focused value boundaries (2026-09-05)

`batch-08-focused-value-boundaries-mutations.json` records 3 complete, compiling
controls against the 79.802956% baseline. The source forms are
`shared-row-advance-tail`, `timer-active-shared-slide-update`,
`render-row-reference-owner`.

No control improves the retained baseline without a metric tradeoff. Canonical source
and configuration are unchanged. These results bound the recorded hypothesis, not the
function's matchability.
