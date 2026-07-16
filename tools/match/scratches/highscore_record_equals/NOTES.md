# highscore_record_equals

The recovered field order, all six numeric early-out comparisons, and the
inlined two-byte `strcmp` loop match the native function exactly: 74/74
instructions with no reference mismatches.

The decisive source-shape detail is that the player-name comparison is a
seventh early-out followed by `return 1`, rather than returning the `strcmp`
boolean expression directly. MSVC 6 then keeps the comparison result in `eax`
and materializes the byte return directly in `al`, reproducing both native
epilogue paths without type or register tricks.
