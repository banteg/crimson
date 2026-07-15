# effect_spawn_freeze_shatter

Native target: `crimsonland.exe` at `0x0042ee00` (339 bytes).

The emitter seeds a white, half-alpha shared effect template, launches four
effect-14 shards at quarter-turn offsets with speed 42, randomizes each shard's
18..27-pixel half extent and angular velocity, then emits four secondary freeze
shards at random centiradian angles.

The ordinary source matches all 79 native instructions and all 27 static
references. Passing the secondary angle expression directly is material: VC6
reserves its outgoing float argument with `push ecx` and stores the x87 result
in place, exactly as native; a named local adds a spill/reload pair.
