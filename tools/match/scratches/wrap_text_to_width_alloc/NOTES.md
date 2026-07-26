# wrap_text_to_width_alloc

Native target: `crimsonland.exe` at `0x0042fd00` (143 bytes).

The helper allocates and copies the input string, then measures each byte as a
temporary one-character string. It subtracts widths from a per-line budget;
on overflow it walks backward without a bounds check until it finds a space,
replaces that space with newline, resets the budget, and resumes after it.

The recovered source reproduces the allocation, two inlined string scans/copy,
register schedule, loop, unsafe backward scan, and virtual measurement call.
Initializing the glyph terminator before measuring the input length gives the
two-byte buffer its native lifetime across `strlen`. VC6.5 therefore reserves
the observed local stack slot instead of reusing the now-dead first-parameter
slot, and emits the exact native 62 instructions:

```txt
match=100.00% prefix=62/62 target_insns=62 candidate_insns=62 refs=2/0/0
```
