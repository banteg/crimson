# `vec2_add_inplace`

Native target: `crimsonland.exe` at `0x0041e400` (26 bytes).

The helper adds the two components of an immutable delta vector into an
adjacent mutable position vector. Disassembly ends with `xor eax, eax`, so the
return type remains `int` and the result is zero; Binary Ninja's former `void`
prototype was incomplete.

Recovering both pointer parameters as `vec2f_t *` / `const vec2f_t *` changes
the source and decompilation from four scalar indices to `x` and `y` fields.
MSVC 6.5 still produces the exact 10-instruction native function.
