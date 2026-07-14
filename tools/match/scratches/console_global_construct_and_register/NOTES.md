# console_global_construct_and_register

Native target: `crimsonland.exe` at `0x00401160` (10 bytes).

This compiler-generated `void` initializer calls the global console queue
constructor thunk and tail-calls the matching destructor-registration helper.
The apparent integer result is incidental state from the tail call.

The recovered wrapper matches both native instructions, full prefix, with both
references aligned.
