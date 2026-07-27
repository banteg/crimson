# quest_meta_table_destroy

Native target: `crimsonland.exe` at `0x00412200` (20 bytes).

Defining the 50-entry global quest metadata array makes VC6 emit this reverse
array-destruction callback with the native 0x2c stride.

The generated callback matches all six instructions, full prefix, with all
three references aligned.

## Native-link closure

VC6 emits this exact callback as COFF-local `_$E2` (`IMAGE_SYM_CLASS_STATIC`),
so it cannot satisfy an external `_quest_meta_table_destroy` reference from a
separate registrar object. An explicit named reverse loop emits 26 bytes
instead of the native 20-byte `??_M` helper call. An implicit holder destructor
preserves `??_M`, but VC6 emits that body separately and reduces the named
callback to a two-instruction tail thunk (0% match). Resolving this without an
alias, wrapper, or exact-match regression therefore requires co-locating the
lifecycle cluster in its original translation unit.
