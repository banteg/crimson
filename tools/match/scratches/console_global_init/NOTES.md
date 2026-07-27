# console_global_init

Native target: `crimsonland.exe` at `0x00401170` (10 bytes).

The named provider placement-constructs the external `console_log_queue`.
Static storage makes the queue pointer non-null; expressing that invariant
lets VC6 lower the source to the same two instructions as its original global
initializer: load the queue as `this`, then tail-call the recovered
`console_queue_t` constructor.

The object now defines `_console_global_init` directly instead of keeping the
compiler-local `_$E1` identity. It remains exact at 2/2 instructions and
`2/0/0` references while becoming linkable from the recovered lifecycle
wrapper.
