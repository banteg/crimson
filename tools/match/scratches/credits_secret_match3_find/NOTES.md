# credits_secret_match3_find

Native target: `crimsonland.exe` at `0x0040f400` (230 bytes).

The complete Alien Zookeeper match policy is recovered over a 6-by-6 integer
board. Horizontal runs are searched first, row-major over four possible starts
per row; vertical runs then search six columns and four starts per column.
Negative cells are empty. On success the helper writes the leftmost/topmost
row-major index and direction byte (`1` horizontal, `0` vertical).

The vertical pass keeps a current-cell pointer and reads the next two rows at
positive `+6` and `+12` element offsets. Its row counter is initialized before
that cursor, and the loop increments the row before advancing the cursor by one
six-cell stride. This is the ordinary source shape behind the native positive
offsets; re-indexing the two-dimensional array instead made VC6 pre-bias the
cursor by twelve cells and emit one extra instruction.

The recovered row-stride cursor and increment expression produce an exact
MSVC 6.5 `/O2 /GB` match: 96/96 instructions, 100.00%, with the full function
as the exact prefix.

The native success result is the one-byte boolean emitted by this exact source,
not a four-byte `uint`. The matching map now preserves the recovered
`unsigned char` return type for callers and decompilation.
