# j_gameplay_run_state_init

Binary Ninja shows the entire native function at `0x4120a0` as a five-byte
tail jump to `gameplay_run_state_init` at `0x4120b0`. The callee returns the
initialization result in `eax`, so the source preserves that return value. It
matches the native instruction and reference exactly.
