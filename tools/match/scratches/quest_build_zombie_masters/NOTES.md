# quest_build_zombie_masters

Native target: `crimsonland.exe` at `0x004360a0` (128 bytes).

Recovered Tier 3 Quest 10's complete four-entry spawn policy:

- `(256, 256)`, zombie-boss spawner `0x00`, 1000 ms, player count
- `(512, 256)`, zombie-boss spawner `0x00`, 6000 ms, one
- `(768, 256)`, zombie-boss spawner `0x00`, 14000 ms, player count
- `(768, 768)`, zombie-boss spawner `0x00`, 18000 ms, one

The exact source shape uses the position setter plus the same two-field spawn
metadata setter recovered independently in `quest_build_two_fronts`, followed
by an explicit count write. That natural helper boundary reproduces VC6's
otherwise surprising placement of the `768.0f` constant load between the
second entry's trigger-time and count stores.

Those setters now operate directly on the canonical `quest_spawn_entry_t`
instead of requiring a private 24-byte entry duplicate. VC6 does not inline
ordinary free helpers in this profile, but explicit `inline` preserves the
recovered helper boundaries and compiles byte-for-byte identically. Applying
the same consolidation to `quest_build_two_fronts` was rejected: its
whole-vector assignment is responsible for the native 32-byte temporary frame,
and flattening that value member drops 18 instructions.

The default VC6 profile matches all 31 instructions, the full 31-instruction
prefix, both references, and the 128-byte function exactly.
