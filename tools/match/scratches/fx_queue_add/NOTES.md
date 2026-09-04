# `fx_queue_add`

The default VC6 profile produces a 97.44% near-match with the native 140-byte,
39-instruction shape and nine aligned references. Its only structural
difference is scheduling the `fx_queue_count` store after the remaining entry
fields instead of between the final color load and store.

The previous Processor Pack profile happened to schedule that store exactly,
but Processor Pack objects would leave product-48/49 build-9044 Rich records,
which are absent from `crimsonland.exe`. A bounded stock-compiler sweep evaluated
143 combinations of count-increment spelling, publication order, and limit
condition without improving the default result. Manual color-component copies,
alpha temporaries, assignment-in-condition forms, and alternate entry-index
expressions also regress or compile identically. The scratch is therefore kept
as an honest source-shape WIP rather than retaining the unsupported override.

Live Binary Ninja HLIL exposes that native boundary as a temporary alpha load:
the first three color words are stored, `color->a` is loaded,
`fx_queue_count` is published, and the alpha word is then stored. The recorded
`publication-alpha-mutations.json` sweep tested early publication plus manual
float, aggregate, and word-copy alpha splits under stock VC6. All five
regressed; none reproduced Processor Pack scheduling. Its spec SHA-256 is
`1255f2e9a4b0b13864fea25a76d3dc93eac02d86adbcb9d28ebc784db417a875`.

The recovered function appends one 40-byte `fx_queue_entry_t`, copying position
and a 16-byte `effect_color_t` aggregate before width, height, rotation, and
effect id. It returns a byte boolean (the native epilogue writes only `AL`). If
the incremented count reaches 128, the queue is clamped to 127 and the helper
returns false; otherwise it returns true.

This match also replaces four flattened color floats in the shared entry type
with the already-recovered `effect_color_t` aggregate. Recompiling
`effects_update`, its existing exact caller, remains 85/85 with all references
aligned after changing the parameter from a raw float pointer to the typed
color pointer.

## Count-publication lifetime sweep

`count-publication-lifetime-mutations.json` records six additional natural
forms: global and local post-increment, indexed entry selection, publication
before the position or color copy, and assignment in the limit test. Only the
local post-increment form is byte-identical to the 97.44% baseline. The other
five regress, with earlier publication moving the first mismatch before the
native color-copy boundary. This closes the ordinary counter-lifetime menu
without retaining the unsupported Processor Pack profile or a manual partial
aggregate copy.

## Exact-tail helper audit (2026-07-27)

`color-copy-helper-mutations.json` tests four inline/force-inline aggregate
copy helpers and their call-site interaction. The ordinary direct-assignment
and reference forms are byte-identical at 97.44%; materializing a local color
copy falls to 41.46% and moves the first mismatch into the prologue. Live
native disassembly still places `fx_queue_count` between the final color load
and store, so an inline source boundary cannot reproduce the Processor Pack
schedule under supported VC6.5. No source change is retained.

## Residual classification

The combined stock-VC6 counter-lifetime, publication-order, color-copy, alpha,
and helper sweeps exhaust the natural source boundaries around the sole
remaining instruction-order mismatch. Processor Pack reproduces the native
schedule, but the executable's Rich records reject that compiler profile.
The retained source is therefore semantic-complete with a `compiler` residual,
not an open analysis residual.

## Fixed-size aggregate copy replay (2026-08-11)

`color-aggregate-memcpy-mutations.json` tests four fixed-size `memcpy` forms
for the recovered 16-byte color aggregate. VC6 inlines all four byte-identically
to direct assignment at 97.44%, 39/39 instructions, and `9/0/0` references.
The native count-publication interleave is therefore not hidden behind a
source-level fixed-size copy boundary.

## Original value-signature boundary (2026-08-14)

The recovered original header declares this lineage as
`AddDecal(int, vec2_t, float, float, float, color_t)`. Its SHA-256 is
`41fa136d8de7cd17c69b10f428ec78e37763d98896ca34990a061015801c8fda`;
the MOD SDK header supplying ordinary `vec2_t` and `color_t` value classes has
SHA-256
`f56d2713518c010ce3ed8c76508678c7e5beff79a6d8a25fd7e736114bdb860f`.
All three live native callers clean six argument words (`add esp, 0x18`), which
confirms the recovered argument boundary but does not distinguish value objects
from pointer-lowered aggregates by itself.

`original-value-abi-mutations.json` therefore compiles the original-style
position and color value forms independently and together under the calibrated
stock VC6 profile. Position by value falls to 72.73%, 38/39 instructions,
prefix 3, and `4/0/3` references. Color by value falls to 72.00%, 36/39,
prefix 3, and `9/0/0`. Passing both by value falls to 59.46%, 35/39, prefix 3,
and `5/0/2`. All three move the first mismatch from instruction 22 to
instruction 3; none is a tradeoff candidate. The spec SHA-256 is
`ab6554db35a41ed28dadcdcde2b9de2f941e03942ff82e9d2bacd42ad966fa0c`.

The old declaration is useful provenance for the semantic aggregate identities,
but transplanting its value signature does not reproduce the 1.9.93 body. Keep
the current pointer-lowered compiler-facing source; the remaining publication
interleave stays classified as a compiler residual.

## Processor Pack alias closure (2026-08-14)

A corpus compiler scan found an exact 39/39-instruction, `10/0/0` result under
the `msvc6.0pp` alias. This is the same build-9044 Processor Pack optimizer
already rejected above, not new object provenance: all installed `*pp`
profiles stamp product 48/49 build 9044, and those records are absent from
`crimsonland.exe`. `scratch.conf` now marks every installed Processor Pack
alias disproven so the default corpus scan no longer reports this known
source-shape lead as an actionable exact compiler candidate. The canonical
build-9782 result remains 97.44%, 39/39 instructions, and `9/0/0` references.

## Focused follow-up (2026-09-05)

Six boolean/byte return and position/color class-copy forms were tested
against 97.44%. All are byte-neutral with 39/39 instructions and 9/0/0
references; none changes the count-publication interleave.

The complete bounded matrix is recorded in
`boolean-and-copy-owner-followup-mutations.json`. No source change is
retained; this result bounds these specific hypotheses only.

## Exact indexed queue publication (2026-09-05)

The remaining count-publication schedule was a source ownership issue. All six
fields now index the queue directly, and the final effect-id assignment advances
the global count with a post-increment. This removes the manually scaled byte
offset, cached destination pointer, and early local increment. VC6 recovers the
native count publication between loading and storing the color alpha on its own.

`indexed-final-field-publication-mutations.json` records seven complete controls.
Both fully indexed forms (local and global count) reach 100%; partial indexing
does not. Removing the unused declarations is byte-neutral. The retained clean
global form matches all 39 instructions and has 10/0/0 references, superseding
the earlier compiler-residual classification and its narrower publication probes.
