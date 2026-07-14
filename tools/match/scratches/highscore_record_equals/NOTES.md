# highscore_record_equals

The recovered field order and all six early-out comparisons match the native
function exactly through its first 49 instructions. MSVC then inlines `strcmp`
with the same two-byte loop, but the scratch materializes the final boolean in
`cl` before moving it to `al`; the target writes `al` directly. The four-instruction
residue is documented rather than reproduced with byte-shaped source.
