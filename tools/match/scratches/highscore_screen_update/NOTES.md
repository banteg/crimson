# `highscore_screen_update`

Native target: `crimsonland.exe` at `0x004423d0` (8,026 bytes).

Live Binary Ninja disassembly and decompilation recover the complete high-score
screen callback:

- derives both UI panels from element slots 09 and 33, draws the current-mode
  title, quest selector, score headings, Hardcore toggle, and ten formatted
  score rows;
- distinguishes time-based Rush/Quest records from score-based modes, preserves
  the native internet-record marker, and renders the hovered record detail with
  its one-based rank;
- implements the date, player-count, game-mode, internet-score, and profile
  controls, including the native one/two-player choices and Typ'o'Shooter clamp;
- handles Update/Receive, Shift batch synchronization, every connection status,
  post-sync update checks, and the update-notice widget;
- routes Play, Back, Escape, keyboard quest navigation, and mouse arrow actions,
  including return-to-results pool cleanup and restoration of the saved mode;
  and
- proves all nine local-static destructor thunks at `0x00444330` through
  `0x004443b0` as exact one-instruction returns.

The natural `msvc6.5 /O2 /GB` reconstruction matches 75.85% of 2,004 target
instructions with 1,954 candidate instructions. The candidate has the native
`0x84`-byte frame, a 41-instruction matching prefix, and audited references of
`567/0/8` (ok/unresolved/mismatch). The eight residual reference mismatches are
instruction-alignment or x87 temporary-order differences; every corresponding
field, constant, string, and gameplay object is present in the recovered flow.

This remains an honest work in progress: no register hints, dead expressions,
fake aliases, unreachable shaping, or platform substitutions are used.
