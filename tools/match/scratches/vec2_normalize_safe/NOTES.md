# Residual mismatch

The candidate has the same 57 instructions and all three references audit cleanly.
Its only mismatch is scheduling: MSVC reserves both call-argument stack slots
before loading the vector components, while the native function interleaves those
two `push ecx` instructions with the x87 loads.

Keeping `float_near_equal` in the same translation unit is required to recover
the native register allocation: the caller retains `src` in `ecx` across the
call, which the compiler only does when it can see that helper's body. The
inline `length_sq` and scalar multiply recover the native vector-temporary
source shape. `/O2`, `/Og-`, and the other tested VC6-family backends all make
the match substantially worse, so the four-instruction scheduling residue is
left honest rather than shaped away.
