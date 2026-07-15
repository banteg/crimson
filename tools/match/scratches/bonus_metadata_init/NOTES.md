# `bonus_metadata_init`

Native target: `crimsonland.exe` at `0x00412660` (735 bytes).

Live Binary Ninja evidence recovers the fourteen nonzero bonus metadata entries,
including their heap-owned labels, width-wrapped descriptions, icon ids, and
default amounts. The reconstruction preserves the native initialization order
and its original text, including `firerate`, the missing article in the fire
bullets description, and MediKit's doubled final period.

VC6 `/O2 /GB` reproduces the function exactly: 131/131 normalized
instructions and all 109 masked references agree.
