# effect_select_texture

Exact match:

```txt
match=100.00% prefix=35/35 target_insns=35 candidate_insns=35 refs=6/0/0
```

The helper reads the eight-byte `(size_code, frame)` record for an effect id
and converts texture sizes `0x10`, `0x20`, `0x40`, and `0x80` to atlas widths
`16`, `8`, `4`, and `2`, respectively. Other size codes do nothing.

Binary Ninja shows each branch dispatching through the Grim2D interface at
vtable offset `0x104`. The recovered Grim2D API independently identifies that
slot as `grim_set_atlas_frame(int atlas_size, int frame)`. Modeling the prefix
of the interface as a C++ abstract class is therefore source-shaped evidence,
not a calling-convention shim: ordinary VC6 virtual dispatch produces the
native `ECX` receiver and stack arguments exactly.
