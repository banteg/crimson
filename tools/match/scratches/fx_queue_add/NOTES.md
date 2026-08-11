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
