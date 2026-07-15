# j_highscore_init_sentinels

Binary Ninja shows the entire native function at `0x412350` as a five-byte
tail jump to `highscore_init_sentinels` at `0x412360`. The callee returns the
initialization result in `eax`, so the source preserves that return value. It
matches the native instruction and reference exactly.
