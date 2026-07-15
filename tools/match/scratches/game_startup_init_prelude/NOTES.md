# `game_startup_init_prelude`

Native target: `crimsonland.exe` at `0x0042b090` (435 bytes).

Live Binary Ninja evidence recovers the pre-Grim startup defaults, core table
initialization, seasonal balloon resource load, random seed setup, initial
terrain generation, and persisted play-time load.

Exact verified match: 100.00%, with 113/113 normalized instructions and
masked references `45/0/0`, using Microsoft Visual C++ 6.5 with
`/O2 /GB /W3 /GR-`.

## Recovered source shape

- Startup owns a heap copy of the shared empty string and sets Grim config
  slots `0x12`, `0x13`, and `0x14` before initializing effects, perks, weapons,
  and the core game state.
- September 12, November 8, and December 18 conditionally load the `balloon`
  texture while a narrowly scoped staging byte is asserted.
- Grim config slot `0x10` receives the shared empty string. A stack
  `LARGE_INTEGER` is initialized from `SYSTEMTIME.wMilliseconds`, overwritten
  by `QueryPerformanceCounter`, and its low word seeds the CRT PRNG.
- Initial terrain generation runs under a startup guard byte. The routine then
  opens the per-user Crimsonland registry key and restores `timePlayed`, using
  the successful `RegCreateKeyExA` result as the read fallback.

The same evidence corrects `0x00495ad6`: it is the
`SYSTEMTIME.wMilliseconds` field, not global QPC scratch storage. The QPC
destination is the routine's stack-local `LARGE_INTEGER`.
