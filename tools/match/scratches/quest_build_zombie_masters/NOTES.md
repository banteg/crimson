# quest_build_zombie_masters

Native target: `crimsonland.exe` at `0x004360a0` (128 bytes).

Recovered Tier 3 Quest 10's complete four-entry spawn policy:

- `(256, 256)`, zombie-boss spawner `0x00`, 1000 ms, player count
- `(512, 256)`, zombie-boss spawner `0x00`, 6000 ms, one
- `(768, 256)`, zombie-boss spawner `0x00`, 14000 ms, player count
- `(768, 768)`, zombie-boss spawner `0x00`, 18000 ms, one

The candidate has the same 31 instructions and references `2/0/0`, scoring
96.77%. The sole residual is VC6 scheduling the `768.0f` constant load one
store earlier than the native function. It remains a WIP rather than masking
that difference.
