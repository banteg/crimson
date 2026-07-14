# highscore_build_path

The recovered path policy caches a 511-byte current-working-directory prefix,
selects Rush, Survival, Quest, or unknown filenames, replaces `.hi` with
`_2.hi` for two-player games, and appends the selected saved-name slot when it
is nonzero. The native Quest branch intentionally uses the `questhc` filename
when `config_hardcore` is zero; the scratch preserves that observed behavior.

The first 75 instructions match exactly. The remaining semantic body differs
only in VC6 stack cleanup scheduling between the named-path `sprintf` and its
diagnostic `console_printf`: the target cleans 16 bytes immediately and then
12 bytes, while the structured scratch combines both cleanups into 28 bytes.
The source leaves that compiler artifact honest rather than introducing an
artificial dependency between the calls.
