# `vec2_normalize_dispatch_init`

Native target: `crimsonland.exe` at `0x00452f1d` (13 bytes).

This is the lazy initializer behind the vector-normalization dispatch slot at
`0x00479658`. The slot initially points back to this helper. On first use the
helper calls the stdcall `renderer_select_backend(1)`, which retargets the
slot, and tail-dispatches the original destination/source arguments through
the selected implementation. Runtime evidence observed the slot change to
`vec2_normalize_safe` at `0x00455587`.

The stdcall signatures are required by the native stack behavior:
`renderer_select_backend` returns with `ret 4`, and the selected two-argument
normalizer owns its arguments. Under the independently established VC6
Processor Pack `/O1 /Oi /G6` vector profile, natural C++ tail-call
optimization emits the complete native body: `push 1`, the selector call, and
`jmp [slot]`.

The live database now records the same shared `vec2f_t *` destination and
`const vec2f_t *` source types as the exact dispatcher scratch rather than raw
float pointers.
