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

`post-normalization-lifetime-mutations.json` then tested whether beginning the
entry alias only after the x87 volume mapping would reproduce the native
delayed `EDI` load. Plain and `register` aliases plus scoped `for` and `do`
loops all compiled byte-identically to the 86.67% baseline. The complete
four-variant sweep is recorded under spec SHA-256
`8f2426c36e4622732531b1e240100ae0fcd95ff309c469817334a7619b6c0b33`;
the remaining allocation is not controlled by that lexical lifetime.

`mapped-volume-lifetime-mutations.json` separately evaluated named and
initialized mapped-volume locals, late cursor declarations, and a late entry
alias. All four were also byte-neutral. Its recorded spec SHA-256 is
`be623af3f1826444ee9ef9c0be5b41f3db8e5a27ca30192fe6df3de2468df75a`.
