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
