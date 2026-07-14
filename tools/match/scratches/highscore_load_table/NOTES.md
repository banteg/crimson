# highscore_load_table

The recovered loader initializes all 100 records with the native light-reset
sentinels, reads and validates records from the mode-specific path, applies the
Quest hardcore marker and score-load gates, and implements the daily, weekly,
and monthly date filters with the native integer promotions. At capacity it
replaces the mode-specific worst record, sorts all 100 slots with the native
comparator, and promotes the loaded flags either wholesale or by choosing the
best same-name record.

The scratch matches 67.53% of the 354-instruction function with all 51
normalized references aligned. Its zero-length prefix is caused by a single
stack-frame difference: the target spills one more byte-offset temporary and
reserves `0x58` bytes, while structured C reserves `0x54`. The largest remaining
body residue is also compiler-shaped: the target retains four separately
expanded 72-byte record copies, while the C candidate tail-merges them into one
shared `rep movsd` block. The source preserves the recovered control flow and
does not introduce artificial volatile state or byte-offset locals to force
either artifact.
