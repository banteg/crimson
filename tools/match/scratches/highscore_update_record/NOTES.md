# highscore_update_record

The updater scans an existing `r+b` file with the recovered reader and equality
predicate. A matching stored record with flag bit `2` is treated as an already
protected success; an unflagged match promotes the replacement to flag `2`.
Otherwise it seeks back one 72-byte record plus its four-byte checksum, rewrites
the entry, flushes, and closes. EOF without a match also flushes before close.

This source matches all 95 native instructions and all 13 references exactly.

## 1.9.8 (C2 9044): the record reset through `this`

The scratch record is a `highscore_record_cpp_t` reset by its inline member
`reset_light()` (`crimsonland_highscore_record.h`), so the file compiles as
C++ (`/TP`), as the game did. Through `this`, 9044 copies the default name
with native's pointer-difference loop (`mov eax, offset name; sub edx, eax`);
the free inline helper, an explicit copy loop, a local record pointer, `void *`
or `const` formals, `__fastcall` and cast destinations all fold the frame
address into an indexed copy. 1.9.93 compiles every one of them identically.
A `highscore_record_t` constructor would also explain the dynamic initializer
`highscore_init_sentinels`, but would touch every C++ user of the record.
