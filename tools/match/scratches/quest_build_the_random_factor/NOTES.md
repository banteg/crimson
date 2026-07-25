# `quest_build_the_random_factor`

Native target: `crimsonland.exe` at `0x00436350` (237 bytes).

Live Binary Ninja evidence recovers waves from 1500 ms while below 101500 ms,
advancing by 10000 ms. Every wave adds template `0x1d` from the right edge with
count `player_count * 2 + 4`, then from the left edge 200 ms later with count
6. When `crt_rand() % 5 == 3`, it also adds template `0x29` at the bottom-edge
midpoint with the current trigger and player count.

Keeping the entries base and emitted count in a builder object recovers the
native base-plus-scaled-index addressing and register allocation instead of
VC6 strength-reducing the loop to a cursor. The candidate has the same 74
instructions and scores 90.54%. Residuals are independent template/trigger
stores moving around `pos.y` conversions and analogous scheduling in the
optional AlienBigGray entry. No ordering-only dependency is added.
