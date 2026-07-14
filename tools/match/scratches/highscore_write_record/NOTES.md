# highscore_write_record

The native writer stamps an unstamped record from the shared `SYSTEMTIME`, then
copies it to a 72-byte local image. It checksums the signed bytes with
`(index + 3) * byte * 7`, applies the inverse of `highscore_read_record`'s byte
transform, and writes the encoded image followed by the four-byte checksum.

Keeping both an index and a byte cursor recovers the VC6 induction-variable
shape used by the checksum loop. The resulting body matches all 103
instructions and all 13 function, data, string, and import references.
