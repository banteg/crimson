# `highscore_find_name_entry`

Exact 101-byte, 48-instruction match with MSVC 6.5 `/O2 /GB`; both masked
references align.

The helper scans at most `count` records in the 72-byte `highscore_table`, uses
VC6's inlined two-byte-at-a-time `strcmp` expansion against each
`player_name`, and returns the matching record pointer or null. A nonpositive
count exits before reading the table. This recovers the first argument as a
name string and the return as `highscore_record_t *`, replacing the flattened
byte-pointer signature.

The Python persistence layer does not expose this legacy name lookup; its
upsert path ranks and inserts complete records directly, so no equivalent
runtime helper is missing.
