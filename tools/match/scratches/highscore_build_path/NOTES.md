# highscore_build_path

The recovered path policy caches a 511-byte current-working-directory prefix,
selects Rush, Survival, Quest, or unknown filenames, replaces `.hi` with
`_2.hi` for two-player games, and appends the selected saved-name slot when it
is nonzero. The native Quest branch intentionally uses the `questhc` filename
when `config_hardcore` is zero; the scratch preserves that observed behavior.

The source is compiled through VC6's C++ frontend with C linkage. That frontend
emits the native caller cleanup between the named-path `sprintf` and its
diagnostic `console_printf`; C mode instead combines both cleanups after the
second call. No source dependency or dummy operation is needed.

Verified exact with MSVC 6.5 `/O2 /GB /W3 /GR- /TP`: 104/104 instructions and
all 54 masked references audited.
