# sfx_load_sample

Allocates the first free resident-sample slot, rejects a bare `.ogg` name with
the native trooper fallback, routes OGG files through the packed-or-loose path
and other files through the WAV loader, reports failures, optionally logs the
allocated id, advances startup progress, and returns the slot.

Current VC6 `/O2 /GB` result: 84.21% (134 target instructions, 132 candidate,
29 audited references). Every path after slot discovery aligns. The residual is
the optimizer's equivalent first-slot load hoist plus its merging of the two
`-1` exits; native keeps the pointer load in the loop and emits both epilogues.
