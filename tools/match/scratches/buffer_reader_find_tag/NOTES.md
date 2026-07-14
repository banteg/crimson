# buffer_reader_find_tag

Scans the entire configured buffer for the first byte-for-byte tag match. On
success it positions the global cursor immediately after the tag; on failure it
leaves the cursor unchanged. The native loop does not stop early when fewer than
`tag_len` bytes remain, so the recovered source preserves that unchecked read.

The signed `char` data and tag pointers are source-significant: they let MSVC
compare bytes directly and hoist the data base outside the loops. The result is
an exact 41/41-instruction match with all four native references aligned.
