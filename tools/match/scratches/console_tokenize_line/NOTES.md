# console_tokenize_line

Native target: `crimsonland.exe` at `0x00402580` (161 bytes).

The `console_queue_t` member parser clears the published argument count first,
ignores null input and whole-line `//` comments, copies accepted input into the
1024-byte scratch buffer, and tokenizes it on spaces and newlines. Token zero
becomes the command name; later tokens are stored contiguously as arguments,
and the count is published only after tokenization completes. Native callsites
preserve the queue in `ECX`, and the callee returns with `ret 4`, confirming the
`__thiscall` boundary.

An explicit infinite token loop with a null-token break reproduces the native
call-at-loop-head schedule. The resulting source matches all 55 instructions,
full prefix, with all ten string/global/call references aligned.

The argument store is the plain indexed `console_cmd_name[argc] = token`. C2
8966 (1.9.93) strength-reduces it to the native pointer walk, while 9044
(1.9.8) keeps the native `[esi*4+console_cmd_name]` store and saves EDI only
around the inline `strlen`. A hand-advanced argument pointer matched 1.9.93
but cost 1.9.8 a second loop register. Both builds are exact.
