# gameplay_run_state_init

The recovered run initializer matches the shipped function exactly: 44/44
instructions and all 20 masked references. VC6 inlines both the 0x48-byte
highscore-record clear and default-name copy, then initializes its sentinels and
random tag before clearing the run, quest, creature, and timing globals.

The RNG call occurs during process-level run-state initialization, before the
capture/replay bootstrap boundary used by current recordings. Quest startup's
later highscore-tag draw remains the one that the replay drivers must consume;
this earlier draw should not be injected into an already captured run state.

The word at `0x00487028` is only cleared here in the checked-in static corpus.
It is therefore named `gameplay_run_reserved_zero` with that limitation stated
in the data map, rather than assigning speculative gameplay meaning.
