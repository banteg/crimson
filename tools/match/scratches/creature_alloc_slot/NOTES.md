# `creature_alloc_slot` notes

The scratch is exact at 39/39 instructions (100%). Live Binary Ninja evidence
confirms the source shape:

- `0x00428148..0x00428158` scans the 384-entry creature pool in order and tests
  only the active byte.
- The successful path clears flags, draws `crt_rand() & 0x17f` for the phase
  seed, clears the auxiliary word and animation phase, increments the spawned
  count, and returns the free index.
- The exhausted path may print `No free creatures to spawn!` when verbose, then
  returns the one-past-the-pool sentinel `0x180` at `0x00428182..0x00428188`.
  It does not draw RNG and never selects or replaces a live creature.

Native callers use the returned index without a bounds check, so reproducing the
sentinel literally in a memory-safe port would turn the original out-of-bounds
bug into an invalid array access. Python already models exhaustion as `None`.
Zig now does the same: direct and template spawns decline a full pool before RNG
work, split-on-death children use only genuinely free entries, and Typ-o-Shooter
stops the batch rather than overwriting slot 383. The previous Zig fallback that
randomly selected a live creature was invented behavior and has been removed.

Regression coverage:

- `full creature pool declines spawns without replacing a live entry`
- `split-on-death uses only the remaining free creature slot`
- `explosion xp uses pre-split reward when a full pool declines children`
