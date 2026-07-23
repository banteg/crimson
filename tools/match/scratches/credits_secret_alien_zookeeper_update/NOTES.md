# credits_secret_alien_zookeeper_update

Native target: `crimsonland.exe` at `0x0040f4f0`, 2,612 bytes and 638
normalized instructions.

This scratch recovers the complete frame callback for the credits-secret
AlienZooKeeper minigame:

- positions and draws the title, subtitle, score, board, and countdown bar;
- advances the animation clock and expires the countdown with the native
  death sound;
- draws the selected cell and all visible members of the 6x6 board;
- accepts two arbitrary cell selections, swaps them, finds the first
  horizontal or vertical triple, marks its three members as `-3`, increments
  the score, plays the bonus sound, and adds two seconds;
- replaces only `-1` cells with random values during the per-frame fill pass;
- rerolls the whole board on Reset until it contains no immediate match, then
  clears the selection and score and starts a 9,600 ms countdown; and
- queues the statistics menu when Back is activated.

The function-local Reset and Back buttons and their two initialization guards
are represented as native-style local statics. The data labels at
`credits_secret_board + 4`, `+8`, `+24`, and `+48` are overlapping aliases of
board cells 1, 2, 6, and 12, not four independent match-mask arrays.

Native behavior intentionally retained:

- opening the panel does not initialize or reroll the process-lifetime board;
- the two swapped cells need not be adjacent;
- only the first match reported by `credits_secret_match3_find` is cleared;
- cleared value `-3` is not refilled by the ordinary `-1` fill pass; and
- this callback does not mutate any unlock flag.

Best verified MSVC 6.5 result:

- 83.70% matched;
- exact 638/638 normalized instruction count;
- exact `0x54` stack frame;
- 15-instruction exact prefix; and
- 153 resolved references, with no missing or extra references.

MSVC 6.6 produced the same useful shape during compiler-profile testing.
MSVC 6.5 Processor Pack regressed substantially. The remaining mismatch
regions are dominated by register choice, spill-slot assignment, and nearby
instruction scheduling inside the nested drawing loops; the recovered control
flow, globals, calls, constants, and game behavior are complete.

The source uses normal C++ vector operators and direct global updates because
those reproduce native x87 and register scheduling best. It contains no
volatile coercions, dummy calls, dead arithmetic, inline assembly, fabricated
reference aliases, or other fakematching devices.
