# perk_meta_global_construct_and_register

Native target: `crimsonland.exe` at `0x0042fa90` (10 bytes).

This compiler-generated startup helper constructs the global perk metadata
array and tail-calls its destructor-registration helper.

It matches both native instructions, full prefix, with both references aligned.
