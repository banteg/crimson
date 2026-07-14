# console_init

Native target: `crimsonland.exe` at `0x00401560` (382 bytes).

This is the natural `console_queue_t` constructor. It enables echo, initializes
the 300-pixel console and its `-300.0f` slide offset, clears log/scroll state,
and creates the built-in `version` cvar with numeric value `1.0`, string value
`"0.7"`, and its reserved flag set.

It then registers `con_monoFont`, clears the first 16 bytes of tokenizer state,
registers the nine core commands (`cmdlist`, `vars`, `echo`, `set`, `quit`,
`clear`, `extendconsole`, `minimizeconsole`, and `exec`), and creates the blank
history sentinel.

The recovered constructor and inline cvar/history constructors match all 107
instructions, full prefix, with all 44 references aligned.
