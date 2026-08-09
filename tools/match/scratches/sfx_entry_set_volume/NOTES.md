# `sfx_entry_set_volume`

Exact native match for `crimsonland.exe` at `0x0043bfa0` (120 bytes).

The function maps the requested volume through `(volume + 2) / 3`, caches the
mapped value, and converts it to DirectSound hundredths-of-a-decibel
attenuation. Streaming entries skip a redundant cached write and stop after
updating their first non-null voice; resident samples visit all 16 slots.

Live Binary Ninja disassembly resolved the former allocation residual as a
control-flow recovery error. Native's null-buffer branch jumps directly to the
loop increment, so the streaming break belongs inside the non-null buffer
block, after `SetVolume`. Expressing that nesting lets VC6 keep the entry and
buffer cursor in `EDI`. Staging `i = 0` before the cached-volume store then
reproduces native's `xor ebx` placement.

Focused results:

- baseline: 86.6667%, 45/45 instructions, prefix 2, references `5/0/0`;
- corrected non-null nesting alone: 97.7778%, prefix 18;
- corrected nesting plus staged loop initialization: exact 100%, 45/45
  instructions, prefix 45, references `5/0/0`.

Earlier alias, mapped-volume lifetime, and normalization-helper sweeps remain
useful negative evidence: none affected allocation because the missing native
branch nesting was upstream of those lifetime choices.
