# sfx_load_sample

Allocates the first free resident-sample slot, rejects a bare `.ogg` name with
the native trooper fallback, routes OGG files through the packed-or-loose path
and other files through the WAV loader, reports failures, optionally logs the
allocated id, advances startup progress, and returns the slot.

The exact VC6 `/O2 /GB` source uses an inlined resident-sample free-slot helper.
The helper returns the first empty index or `-1`, after which the caller checks
the sentinel before loading. That split produces the native's distinct
exhaustion epilogue and matches all 134 instructions and 29 references.

The freeware callers supply the slot index and filename and receive a boolean.
1.0.2 (0x401440) and 1.3.0 (0x402d90) store the result of FMOD's
`FSOUND_Sample_Load` in that slot and disable looping on a successful load.
1.3.0 adds an early success return when sound is disabled.

1.4.0 (0x4050e0) passes the filename to the dynamically loaded `SFX_LoadSfx`
and `SFX_GetSfx` exports. With `sounds.paq` open, it uses only the part after
the last forward slash. The two slot clears bracket that filename scan in the
native code. The lookup at 0x4030f0 pins both exports by name.
