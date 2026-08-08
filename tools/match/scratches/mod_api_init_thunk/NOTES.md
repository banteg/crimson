# mod_api_init_thunk

Binary Ninja shows the entire native function at `0x40df90` as a five-byte
tail jump to `mod_api_init` at `0x40dfa0`. The single-call wrapper is the
natural optimized C++ source and matches the native instruction and reference
exactly.
