# sfx_load_sample

Allocates the first free resident-sample slot, rejects a bare `.ogg` name with
the native trooper fallback, routes OGG files through the packed-or-loose path
and other files through the WAV loader, reports failures, optionally logs the
allocated id, advances startup progress, and returns the slot.

Current VC6 `/O2 /GB` result: 96.60% (134 target instructions, 131 candidate,
29 audited references). The residual is the structured post-loop exhaustion
check sharing the existing `-1` epilogue; native branches from the loop bound to
a separate but equivalent exhaustion epilogue.
