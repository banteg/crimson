# game_mode_label

Native target: `crimsonland.exe` at `0x00412960` (176 bytes).

The helper selects the user-facing Survival, Rush, Quests, or Typ'o'Shooter
label for the current mode, falls back to Unknown, copies it into the shared
scratch buffer, and returns that buffer.

This remains an honest WIP candidate. The recovered branch topology explains
why VC6 emits private inline copies for Survival and Typ'o'Shooter but shares a
copy tail for Rush, Quests, and Unknown. The candidate is behaviorally exact
and scores 75.41%; differing basic-block scheduling prevents an instruction
match, so it is not counted as exact.
