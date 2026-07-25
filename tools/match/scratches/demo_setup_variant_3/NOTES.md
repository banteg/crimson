# demo_setup_variant_3

Native target: `crimsonland.exe` at `0x00403250` (278 bytes).

This one-player demo regenerates the arena from the first quest terrain, then
spawns twenty large green aliens and a small green alien on two out of every
three iterations. It centers the player, equips weapon 18, and uses a 4-second
attract-mode limit.

The recovered loop and whole-vector player assignment match all 78 native
instructions, full prefix, with all thirteen references aligned.

The large- and small-alien spawn positions are now recovered as ordinary
`vec2f_t` locals rather than raw two-float arrays. Named components and direct
vector arguments preserve the exact body and reference audit.
