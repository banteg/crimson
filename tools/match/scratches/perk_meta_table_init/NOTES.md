# perk_meta_table_init

Native target: `crimsonland.exe` at `0x0042faa0` (28 bytes).

Defining the 128-entry global perk metadata array makes VC6 emit this guarded
array-construction helper with its native 0x14 stride.

The generated helper matches all seven instructions, full prefix, with all four
references aligned.
