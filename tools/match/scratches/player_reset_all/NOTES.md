# player_reset_all

The recovered source matches the native reset semantics and field order:

- exactly two native player slots are reset;
- spawn positions start at terrain center and alternate by `player_index * 80`
  on both axes;
- only the observed timers, weapon fields, perk counts, and reset-only words
  are cleared;
- the alternate pistol slot is initialized from weapon-table entry 1;
- the non-demo mouse position and every creature collision flag are reset
  inside the player loop.

The remaining instruction mismatch is compiler source-shape residue. Native
uses a 0x24-byte local frame and spills the center, mouse, and scalar position
temporaries before direct indexed-global stores. The current structured source
uses a 0x0c-byte frame and keeps more values in registers. Do not add volatile
or dead temporaries merely to reproduce that schedule.
