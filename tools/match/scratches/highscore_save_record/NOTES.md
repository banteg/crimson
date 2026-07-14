# highscore_save_record

The save coordinator trims trailing spaces from the player name, ensures the
`scores5` directory exists, refreshes record metadata unless the observed skip
flag is set, and attempts an in-place update for records carrying flag bit `1`.
When no update succeeds it opens the mode-specific path in append-binary mode,
writes one encoded record, and closes it.

The recovered source matches all 70 instructions and all 16 references.
