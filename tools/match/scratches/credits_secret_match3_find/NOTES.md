# credits_secret_match3_find

Native target: `crimsonland.exe` at `0x0040f400` (230 bytes).

The complete Alien Zookeeper match policy is recovered over a 6-by-6 integer
board. Horizontal runs are searched first, row-major over four possible starts
per row; vertical runs then search six columns and four starts per column.
Negative cells are empty. On success the helper writes the leftmost/topmost
row-major index and direction byte (`1` horizontal, `0` vertical).

The natural two-dimensional-array source scores 89.12%, with a 24-instruction
exact prefix. The candidate has one extra instruction because VC6 pre-biases
the vertical cursor by 12 cells and uses negative offsets, while the native
keeps the current cell and positive `+6`/`+12` offsets. The recovered logic,
loop bounds, scan order, outputs, and byte return agree; this remains a WIP
rather than introducing a synthetic pointer dependency to force the schedule.
