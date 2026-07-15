# j_config_init_defaults

Binary Ninja shows the entire native function at `0x4028e0` as a five-byte
tail jump to `config_init_defaults` at `0x4028f0`. The single-call wrapper is
the natural optimized C++ source and matches the native instruction and
reference exactly.
