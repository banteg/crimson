# game_mode_label

Native target: `crimsonland.exe` at `0x00412960` (176 bytes).

The helper selects the user-facing Survival, Rush, Quests, or Typ'o'Shooter
label for the current mode, falls back to Unknown, copies it into the shared
scratch buffer, and returns that buffer.

This remains an honest WIP candidate. Returning `strcpy` directly from the
Survival and Typ-o branches recovers the native's two private inline copies,
while Rush, Quests, and Unknown still share one copy tail. VC6 now emits the
same 69 instructions as native and all ten references resolve, improving the
match from 75.41% to 86.96%. The residual is limited to register scheduling
inside the two private copies: native returns the known destination buffer,
whereas direct `strcpy` returns the destination register. Re-expressing those
branches as copy-then-return makes VC6 tail-merge them and loses sixteen native
instructions, so the candidate records this honest boundary instead of adding
an artificial anti-merge dependency.
