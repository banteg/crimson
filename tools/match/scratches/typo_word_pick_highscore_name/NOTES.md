# typo_word_pick_highscore_name

Native target: `crimsonland.exe` at `0x004451b0` (345 bytes, 123
instructions).

MSVC 6.5 `/O2 /GB` reproduces the function exactly:

```txt
match=100.00% prefix=123/123 target_insns=123 candidate_insns=123 refs=20/0/0
```

## Recovered source shape

- The first call goes through the observed `j_highscore_load_table` thunk and
  lazily builds a process-lifetime cache. Later calls reuse it.
- The routine scans all 100 loaded 72-byte high-score records, not only the
  persisted-record count. Accepted names are stored in 32-byte cache slots.
- Cache comparison is case-sensitive. A candidate is skipped when it exactly
  matches any earlier accepted entry.
- Every byte of a nonempty candidate must satisfy `isalpha` or equal `'.'`.
  A zero-length name vacuously passes that loop. Unused native table records
  have already been initialized to the fixed `default_player_name` literal
  `"10tons"`, which is rejected here because it contains digits.
- On acceptance, the count and destination cursor advance, the full name is
  copied, and `"%d. unique: %s\n"` is written to the console log with the
  one-based cache index.
- A zero-entry cache stores `"quickbrownfox"` while leaving its count at zero.
  Selection returns that base slot without consuming RNG when the count is not
  positive; otherwise one `rand() % count` draw selects a 32-byte slot.

The guarded nonempty-cache loop is represented as a single post-tested search:
the cursor comparison guarantees at least one entry, and the body exits after
the accepted-count bound. Capturing the old destination before advancing the
cursor, incrementing the count, and then copying reproduces VC6's inline
`strcpy` scheduling exactly. The thunk name is material reference evidence: a
direct call to the implementation is instruction-identical but points at
`0x0043afa0` instead of the native jump thunk at `0x0043b800`.

No volatile state, dummy references, artificial dependencies, or forced
addresses are used.

## Port parity

Python and Zig already read Typ-o records, preserve their order, filter names
to alphabetic bytes/dots, deduplicate them, and use the same zero-list fallback
and tagged selection draw. They scan only saved records rather than native's
100-entry table, but the remaining native slots all contain the rejected
`"10tons"` default, so the ordinary candidate set and fresh-profile fallback
are unchanged.

Both ports intentionally reject an empty saved name. Native's zero-length loop
accepts one and can generate an untypeable empty target; retaining the port
guard avoids reproducing that presentation/gameplay trap.
