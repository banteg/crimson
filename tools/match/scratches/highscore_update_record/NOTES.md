# highscore_update_record

The updater scans an existing `r+b` file with the recovered reader and equality
predicate. A matching stored record with flag bit `2` is treated as an already
protected success; an unflagged match promotes the replacement to flag `2`.
Otherwise it seeks back one 72-byte record plus its four-byte checksum, rewrites
the entry, flushes, and closes. EOF without a match also flushes before close.

This source matches all 95 native instructions and all 13 references exactly.
