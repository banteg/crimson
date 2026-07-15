# `tutorial_prompt_dialog`

Native target: `crimsonland.exe` at `0x00408530` (1084 bytes).

Live Binary Ninja callsite and body evidence recovers the prompt panel, the
completion/skip action split, and a previously omitted third byte parameter.
The main tutorial call passes `tutorial_stage_index == 8`; transient hint calls
pass zero.

Exact verified match: 100.00%, with 254/254 normalized instructions and
masked references `80/0/0`, using Microsoft Visual C++ 6.5 with
`/O2 /GB /W3 /GR-`.

## Recovered source shape

- The panel is centered from the measured text width. Ordinary one-line or
  newline prompts use one or two 16-pixel rows; the completion prompt reserves
  four rows. Fill, outline, and text alpha use the native 0.8 / 1.0 / 0.9
  multipliers.
- The panel position is naturally scoped and rebuilt before the outline draw.
  VC6 consequently reuses that stack storage for the later color assignment;
  no stack padding or dead expression is used.
- Two ordinary function-local static buttons retain the native shared guard
  byte and empty atexit destructors. Completion mode displays Play a game and
  Repeat tutorial; other prompts expose Skip tutorial after a clamped one-second
  fade-in.
- Play/Skip clear the Crimson-sign focus lock, queue the Play Game menu, reset
  the render transition, flush input, and begin the tutorial close timeline.
  Repeat resets player level, all 128 perk counters, pending perk choices, and
  the tutorial timers.

The strict reference audit names both static button objects, their compiler
guard, and their destructor thunks. The fakematch validator passes.

