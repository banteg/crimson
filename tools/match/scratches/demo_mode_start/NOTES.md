# demo_mode_start

Native target: `crimsonland.exe` at `0x00403390` (155 bytes).

The coordinator enters gameplay state, enables demo mode, resets gameplay, and
selects one of four demo setups, repeats variant zero for slot four, or starts
the purchase interstitial for the remaining slot. It then clears the quest
timeline and fade ramp and advances the variant modulo six.

Live Binary Ninja shows five gameplay callers and no meaningful return use.
The decompiler's integer return is the quotient incidentally left in `EAX` by
the signed division used for `% 6`; the plausible source function is `void`.
The recovered if/else ladder matches all 40 instructions, full prefix, with all
seventeen global and call references aligned.
