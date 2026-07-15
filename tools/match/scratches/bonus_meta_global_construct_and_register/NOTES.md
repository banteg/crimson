# bonus_meta_global_construct_and_register

Native target: `crimsonland.exe` at `0x004123c0` (10 bytes).

This compiler-generated startup helper constructs the global bonus metadata
array and tail-calls its destructor-registration helper.

It matches both native instructions, full prefix, with both references aligned.
