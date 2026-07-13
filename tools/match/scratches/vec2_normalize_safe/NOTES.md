# vec2_normalize_safe

The recovered C++ source matches all 57 native instructions and all three
masked references with `msvc6.5pp /O1 /Oi /G6 /W3 /GR-`.

Keeping `float_near_equal` in the same translation unit is required to recover
the native register allocation: the caller retains `src` in `ecx` across the
call only when the compiler can see the helper body. The inline `length_sq`
method and scalar multiply also recover the native vector-temporary shape.

This is an evidence-backed per-object `/G6` exception. With the global `/GB`
profile, the candidate is semantically identical and has the same 57
instructions, but it reserves both call-argument slots before loading the
vector components. `/G6` interleaves those independent pushes and x87 loads
exactly like the shipped function. The medium and exact calibration corpus
still supports `/GB` as the global default.
