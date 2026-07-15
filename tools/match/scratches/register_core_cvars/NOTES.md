# `register_core_cvars`

Native target: `crimsonland.exe` at `0x00402c00` (326 bytes).

Live Binary Ninja evidence recovers the thirteen core console variables, their
defaults, and the global handles retained by the game. In particular, the
native registration order includes `cv_terrainFilter` between silent loading
and body fading.

VC6 `/O2 /GB` reproduces the function exactly: 66/66 normalized instructions
and all 65 masked references agree.
