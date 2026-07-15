# bonus_meta_table_init

Native target: `crimsonland.exe` at `0x004123d0` (25 bytes).

Defining the 15-entry global bonus metadata array makes VC6 emit this guarded
array-construction helper with its native 0x14 stride.

The generated helper matches all seven instructions, full prefix, with all four
references aligned.
