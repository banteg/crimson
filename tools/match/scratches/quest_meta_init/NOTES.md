# quest_meta_init

Native target: `crimsonland.exe` at `0x00412190` (25 bytes).

Defining the 50-entry global quest metadata array makes VC6 emit this guarded
array-construction helper, including the 0x2c stride and the entry destructor
used for exception unwinding.

The generated helper matches all seven instructions, full prefix, with all four
references aligned.
