# sfx_load_sample

Allocates the first free resident-sample slot, rejects a bare `.ogg` name with
the native trooper fallback, routes OGG files through the packed-or-loose path
and other files through the WAV loader, reports failures, optionally logs the
allocated id, advances startup progress, and returns the slot.

The exact VC6 `/O2 /GB` source uses an inlined resident-sample free-slot helper.
The helper returns the first empty index or `-1`, after which the caller checks
the sentinel before loading. That split produces the native's distinct
exhaustion epilogue and matches all 134 instructions and 29 references.
