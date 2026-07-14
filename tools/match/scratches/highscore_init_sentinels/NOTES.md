# `highscore_init_sentinels`

Exact 96-byte, 38-instruction match with MSVC 6.5 `/O2 /GB`; all three masked
references align (`highscore_table`, `default_player_name`, and `crt_rand`).

The function initializes 100 records: zero the full 0x48-byte entry, copy the
default `10tons` name, clear `flags`, write the `|`/`0xff` tail sentinels, and
seed `random_tag` with `crt_rand() & 0x0fee050f`. It returns the final record's
tag as an incidental result.

The exact offset disproves IDA's field guess here: native clears offset `0x44`
(`flags`), not offset `0x45` (`hardcore_marker`). Naming the dword at offset
`0x38` as `random_tag` also removes a raw reserved-byte cast from the already
exact `gameplay_run_state_init`, which remains 44/44 after the type refinement.
