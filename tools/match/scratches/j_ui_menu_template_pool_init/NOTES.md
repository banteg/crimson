# j_ui_menu_template_pool_init

Binary Ninja shows the entire native function at `0x417680` as a five-byte
tail jump to `ui_menu_template_pool_init` at `0x417690`. The single-call
wrapper is the natural optimized C++ source and matches the native instruction
and reference exactly.
