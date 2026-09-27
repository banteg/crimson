# grim_mouse_poll

## Plausibility pass (2026-09-27)

The `goto reacquire` error exit is retained. A `while (result >= 0)` loop that returns on success reaches 95.56%: C2 then merges the success return into the preceding block and schedules `mov al, 1; pop esi` into the float updates. Shared-return restructurings change the loop layout (64–66%). See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md).

Polls the DirectInput mouse repeatedly so relative motion is drained into one
frame delta, reacquiring the device after a failed state query.

The post-incremented bound accepts samples 0 through 100. Failed state reads
skip cumulative updates, call `Acquire` once, and repeat only for
`DIERR_INPUTLOST`; every exit still returns true. The `"stall"` call after more
than two samples targets the binary's no-op diagnostic stub.

Clearing the frame deltas before the 20-byte state is the natural source order
that reproduces VC6's interleaved zero stores. The result matches all 90
instructions and all 42 masked references without volatile state or fake
dependencies.
