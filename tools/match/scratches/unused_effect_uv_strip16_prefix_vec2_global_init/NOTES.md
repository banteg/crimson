# `unused_effect_uv_strip16_prefix_vec2_global_init`

Exact 21-byte, three-instruction match with both data references proven. It
zeroes the two-word C++ startup object at `0x00490f78`, immediately before
`effect_uv_strip16`. Live Binary Ninja shows no runtime references to either
word, so the source and curated name stop at the evidenced vec2-shaped default
object instead of inventing behavior.
