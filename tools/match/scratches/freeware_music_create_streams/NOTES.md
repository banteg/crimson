1.4.0 allocates game, intro and title streams in that order. Each allocation has
its own unwind state that calls scalar delete if the constructor throws.
VC6 with `/EHsc-` emits the three cleanup funclets and schedules the next size
push before clearing the previous state, as at 0x4051c8 and 0x4051fa.
