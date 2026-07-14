# demo_setup_variant_1

Native target: `crimsonland.exe` at `0x004030f0` (338 bytes).

This two-player demo uses quest metadata entry 11 for terrain, spawns twenty
large green spiders plus a small spider on two out of every three iterations,
and equips both players with weapon 5. The global weapon-power-up timer is
seeded to 15 seconds for the 5-second encounter.

The recovered loop and whole-vector player assignments match all 88 native
instructions, full prefix, with all seventeen references aligned.
