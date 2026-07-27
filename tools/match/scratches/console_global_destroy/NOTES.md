# console_global_destroy

Native target: `crimsonland.exe` at `0x00401190` (10 bytes).

The named provider explicitly destroys the external `console_log_queue`. VC6
lowers that natural destructor expression to the same two instructions as its
original global finalizer: load the queue as `this`, then tail-call the
recovered `console_queue_t` destructor.

The object now defines `_console_global_destroy` directly instead of keeping
the compiler-local `_$E2` identity. It remains exact at 2/2 instructions and
`2/0/0` references while becoming linkable from the recovered atexit wrapper.
