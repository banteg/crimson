# highscore_load_table_thunk

Binary Ninja shows the entire native function at `0x43b800` as a five-byte
tail jump to `highscore_load_table` at `0x43afa0`. The single-call wrapper is
the natural optimized C++ source and matches the native instruction and
reference exactly.
