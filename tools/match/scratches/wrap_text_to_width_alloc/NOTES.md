# wrap_text_to_width_alloc

Native target: `crimsonland.exe` at `0x0042fd00` (143 bytes).

The helper allocates and copies the input string, then measures each byte as a
temporary one-character string. It subtracts widths from a per-line budget;
on overflow it walks backward without a bounds check until it finds a space,
replaces that space with newline, resets the budget, and resumes after it.

The plausible source reproduces the allocation, two inlined string scans/copy,
register schedule, loop, unsafe backward scan, and virtual measurement call.
The VC6.5 candidate has 60 instructions against 62 native instructions and
scores 81.97%. The only structural residual is native reservation of a separate
four-byte stack slot for the two-byte glyph buffer: the tested VC6.0, VC6.5,
and VC6.6 backends instead reuse the dead first-parameter slot and materialize
the zero terminator from `AL`. VC6.5pp and VC7 diverge more broadly. This is
left as an honest WIP rather than forcing stack layout with artificial source.
