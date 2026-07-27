# bonus_meta_table_destroy

Native target: `crimsonland.exe` at `0x00412450` (20 bytes).

Defining the 15-entry global bonus metadata array makes VC6 emit this reverse
array-destruction callback with the native 0x14 stride.

The generated callback matches all six instructions, full prefix, with all
three references aligned.

## Native-link closure

VC6 emits this exact callback as COFF-local `_$E2` (`IMAGE_SYM_CLASS_STATIC`),
so it cannot satisfy an external `_bonus_meta_table_destroy` reference from a
separate registrar object. A named source callback either expands to a
different explicit reverse loop or leaves the vector destructor in a separate
class destructor and becomes a two-instruction tail thunk. Resolving this
without an alias, wrapper, or exact-match regression therefore requires
co-locating the lifecycle cluster in its original translation unit.
