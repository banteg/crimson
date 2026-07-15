# bonus_meta_table_destroy

Native target: `crimsonland.exe` at `0x00412450` (20 bytes).

Defining the 15-entry global bonus metadata array makes VC6 emit this reverse
array-destruction callback with the native 0x14 stride.

The generated callback matches all six instructions, full prefix, with all
three references aligned.
