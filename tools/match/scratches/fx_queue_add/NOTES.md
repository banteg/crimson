# `fx_queue_add`

Exact 140-byte, 39-instruction match with MSVC 6.5 Processor Pack `/O2 /GB`;
all ten masked references align. The Processor Pack is material here: baseline
VC6 emits the same 39 instructions but schedules the `fx_queue_count` store
after the remaining entry fields, producing a 97.44% near-match.

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
