# highscore_write_record

The native writer stamps an unstamped record from the shared `SYSTEMTIME`, then
copies it to a 72-byte local image. It checksums the signed bytes with
`(index + 3) * byte * 7`, applies the inverse of `highscore_read_record`'s byte
transform, and writes the encoded image followed by the four-byte checksum.

Keeping both an index and a byte cursor recovers the VC6 induction-variable
shape used by the checksum loop. The resulting body matches all 103
instructions and all 13 function, data, string, and import references.

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

1.9.8 also drops the reset's dead `random_tag` store (the record copy
overwrites it) only with `highscore_iso_week`, which precedes this function in
the unit and reads no memory, compiled first: guarded translation-unit context.
