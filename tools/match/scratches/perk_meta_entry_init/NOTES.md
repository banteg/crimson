# perk_meta_entry_init

Native target: `crimsonland.exe` at `0x0042fac0` (27 bytes).

The natural constructor clears both owned strings and availability, seeds
flags to 3, and uses prerequisite sentinel -1.

It matches all eight native instructions, full prefix, with no references.
