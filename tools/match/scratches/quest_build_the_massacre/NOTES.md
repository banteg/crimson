# `quest_build_the_massacre`

Native target: `crimsonland.exe` at `0x004383e0` (184 bytes).

Live Binary Ninja evidence recovers a two-lane wave builder. Every wave adds
zombies at `(terrain_texture_width + 64, terrain_texture_width / 2)`, starting
at 1500 ms and advancing by 5000 ms while the trigger is below `0x1656c`.
Zombie counts are `wave + 3`. Even waves also add red fast aliens at the
corresponding `+128` edge, with count `wave + 1`.

The recovered source retains the cursor and emitted-entry count as the same
small builder aggregate used throughout the neighboring quest constructors.
A loop-local `next_wave` matches the native register lifetime: it supplies both
spawn counts, survives the destructive signed `% 2` lowering, and replaces the
current wave at the loop tail. Keeping those two builder fields under one
source lifetime prevents VC6 from filling the `pos.y` conversion latency with
metadata stores. The resulting candidate is an exact 61/61-instruction,
184/184-byte match with all four references aligned.
