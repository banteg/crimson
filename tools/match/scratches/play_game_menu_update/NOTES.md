# `play_game_menu_update`

Native target: `crimsonland.exe` at `0x0044ed80` (777 normalized
instructions).

Live Binary Ninja recovers the complete Play Game mode-select callback. The
natural reconstruction is a high-confidence WIP at 87.44%, with 776 candidate
instructions, a 120-instruction exact prefix, the native `0x2c` stack frame,
and reference audit `275/0/28` (no unresolved references). It uses Microsoft
Visual C++ 6.5 with `/O2 /GB /W3 /GR-` and passes the fakematch validator.

The residual is code generation rather than missing behavior: VC6 schedules
the opening vector temporaries differently and lays out the roomy/tight menu
branches in the opposite order. The candidate is one instruction shorter.
The VC6.5 processor-pack compiler (79.51%) and VC7.0 (61.25%) are both worse,
which supports retaining the repository's standard VC6.5 profile. No volatile
state, dead expressions, register hints, or other match-only shaping is used.

## Recovered source shape

- Six function-local static controls build under the native guard bits:
  Quests, Rush, Survival, Typ-o-Shooter, a residual Hardcore checkbox, and
  Tutorial. A seventh static holds the player-count list. The Hardcore control
  is labelled but otherwise unused by this callback, matching the executable.
- The callback anchors to menu element 11, draws the Play Game title quad, and
  optionally renders the native F1 `times played:` overlay. Quest plays sum the
  40 counters at indices 11 through 50; the cheap tutorial-placement test only
  uses counter 11 plus Rush and Survival totals.
- The roomy layout is selected while fewer than 40 quests are unlocked or more
  than one player is active, with 32-pixel rows. The single-player completed
  layout uses 28-pixel rows and conditionally exposes Typ-o-Shooter. Tutorial
  moves from the first row to the last after any relevant mode has been played.
  Live HLIL exposes this as the direct structured condition
  `quest_unlock_index < 40 || config_player_count > 1`; the scratch now keeps
  that `if`/`else` shape instead of reconstruction-only labels and gotos. This
  cleanup is byte-neutral at the score and audits reported above.
- Four local player labels are present, but the native list deliberately exposes
  only the one- and two-player entries. Changing it reloads the high-score table;
  opening it disables the three always-visible mode buttons.
- Five hover timers drive the exact tooltip offsets and alpha scale. Activated
  buttons reproduce native state routing: Quests opens quest selection, while
  Rush, Survival, Typ-o-Shooter, and Tutorial configure their mode, transition,
  sign focus, music fades, and pending gameplay state. Escape delegates to the
  contextual Back action.

The strict aliases cover every static object, the shared initialization guard,
and all seven `atexit` destructor thunks. Each destructor thunk is separately
verified as the native one-byte `ret` function.
