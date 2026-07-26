# highscore_load_table

The recovered loader initializes all 100 records with the native light-reset
sentinels, reads and validates records from the mode-specific path, applies the
Quest hardcore marker and score-load gates, and implements the daily, weekly,
and monthly date filters with the native integer promotions. At capacity it
replaces the mode-specific worst record, sorts all 100 slots with the native
comparator, and promotes the loaded flags either wholesale or by choosing the
best same-name record.

The same-name promotion loop compares every inner record against the fixed
outer record's name, while separately tracking the best score index. Comparing
against the moving best record is behaviorally equivalent because a best record
can only be selected after a successful same-name comparison, but it lets VC6
coalesce the outer and best byte offsets. Restoring the fixed outer name
naturally recovers the native fourth stack local and exact `0x58` frame.

The scratch now matches 77.08% of the 354-instruction function, produces
344/354 instructions, reaches a 67-instruction exact prefix, and aligns 55
normalized references without a mismatch. The largest remaining body residue
is compiler-shaped: the target retains separately expanded 72-byte record
copies in the duplicate, Rush, Quest, Survival, and append paths, while this
VC6 candidate tail-merges equivalent aggregate assignments into a shared
`rep movsd` block. Spelling those assignments as explicit `memcpy` calls is
byte-neutral. The source keeps the aggregate assignments and recovered control
flow rather than adding volatile state, byte-offset locals, or artificial
dependencies to defeat the optimizer.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live Binary Ninja output confirms the fixed-name promotion loop, all
mode/date filters, capacity replacement arms, three-way comparator selection,
and both loaded-flag tails. The candidate retains the exact native `0x58`
frame, 344/354 instructions, a 67-instruction prefix, and `55/0/0` references;
the remaining missing instructions are the target's separately expanded
72-byte record copies.
