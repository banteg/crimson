# sfx_entry_set_volume

Maps the caller's volume through `(volume + 2) / 3`, caches it, and converts the
result into DirectSound's hundredths-of-a-decibel attenuation. Streaming entries
update only their primary buffer and skip redundant writes at the cached value;
resident samples update all 16 allocated voices.

The reconstruction has the same 45-instruction count and all five references
aligned, but remains an honest 86.67% WIP. The residual is register allocation:
native keeps the entry/buffer cursor in `EDI`, while the recovered source keeps
the entry in `ECX` before deriving `EDI`. No semantic or call difference is
hidden, and the source is not contorted to force the schedule.
