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

## Recovery classification audit

Live Binary Ninja HLIL confirms the volume mapping, cached streaming early
return, DirectSound attenuation conversion, primary-only stream update, and
16-voice resident loop. Candidate and native each have 45 instructions with
`5/0/0` references. The two localized regions are allocation/control-flow
consequences of the documented entry/cursor register choice, so recovery is
`semantic-complete` with a `compiler` residual.

`entry-alias-mutations.json` evaluated three entry/cursor lifetime forms. The
plain alias is byte-neutral and the initialized-cursor alternatives regress,
so no pointer-lifetime rewrite was retained.
