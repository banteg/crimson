# console_tokenize_line

Native target: `crimsonland.exe` at `0x00402580` (161 bytes).

The `__stdcall` parser clears the published argument count first, ignores null
input and whole-line `//` comments, copies accepted input into the 1024-byte
scratch buffer, and tokenizes it on spaces and newlines. Token zero becomes the
command name; later tokens are stored contiguously as arguments, and the count
is published only after tokenization completes.

An explicit infinite token loop with a null-token break reproduces the native
call-at-loop-head schedule. The resulting source matches all 55 instructions,
full prefix, with all ten string/global/call references aligned.
