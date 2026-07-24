# `highscore_read_record`

Native target: `crimsonland.exe` at `0x0043ab10` (284 bytes).

The routine reads one 0x48-byte high-score record and its checksum, decodes the
record bytes in place, recomputes the signed-byte checksum, and rejects corrupt
records after terminating the player name. The candidate is an exact
80/80-instruction match with all five native references aligned.

The stream parameter now uses the recovered 0x20-byte MSVC 6 `_iobuf` layout.
The early EOF test is the named `FILE::_flag & 0x10` field access at
`0x0043ab35`, rather than an opaque `fp+0x0c` expression.
