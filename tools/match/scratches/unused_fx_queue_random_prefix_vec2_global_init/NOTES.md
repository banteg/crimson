# `unused_fx_queue_random_prefix_vec2_global_init`

Exact 21-byte, three-instruction match with both data references proven. It
zeroes the two-word C++ startup object at `0x00490418`, immediately before the
function-local random FX color at `0x00490420`. No runtime code references the
object, so `unused` and `prefix_vec2` preserve the limits of the evidence.
