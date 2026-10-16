# `fx_queue_add_random`

Exact 291-byte, 73-instruction match with MSVC 6.5 `/O2 /GB`; all 23
masked references align.

The function first honors `config_violence_disabled`, then lazily constructs a
function-local static RGBA color `(0.9, 0.9, 0.9, 0.78)`. MSVC emits the
one-byte initialization guard, empty exit-time destructor, and `_atexit`
registration visible in the native. Each invocation consumes four CRT random
values: grayscale `0.84..0.99`, square width `18..41`, rotation in hundredths
over `0..6.27`, and effect id `3..7`.

The final vector sequence exposes more source shape than the flattened
decompile. A square half-size vector is constructed on the stack, then the
already-recovered `vec2_sub` method form is inlined with that same vector as
both destination and right operand. This aliasing is material: it produces the
native x87 store/subtract schedule exactly, while two independent scalar
subtractions miss one instruction and a conventional separate right operand
requires eight extra stack bytes.

The Python `FxQueue.add_random` port already has the same violence gate, RNG
consumption order, color/size ranges, top-left conversion, and id selection, so
no runtime change was required.

## 1.9.8 (C2 9044)

1.9.8 keeps the half extent in its own 8-byte slot (0x18-byte frame) instead
of reusing `top_left`. A separate `half` vector (named local or a temporary
passed to `vec2_sub`) is exact under 9044 and costs 8966 the 0x10 frame
(93.15%); the in-place canonical spelling packs both slots under 9044 too
(93.33%). No shared spelling was found, so the half/top-left pair is a
codegen-only `CL_BUILD == 10908` guard.
