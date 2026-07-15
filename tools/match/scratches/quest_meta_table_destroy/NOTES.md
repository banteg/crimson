# quest_meta_table_destroy

Native target: `crimsonland.exe` at `0x00412200` (20 bytes).

Defining the 50-entry global quest metadata array makes VC6 emit this reverse
array-destruction callback with the native 0x2c stride.

The generated callback matches all six instructions, full prefix, with all
three references aligned.
