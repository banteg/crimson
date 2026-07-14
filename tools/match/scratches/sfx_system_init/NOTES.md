# sfx_system_init

Skips initialization when sound is disabled, initializes DirectSound for the
native stereo 44.1 kHz 16-bit format, disables both sound and music on failure,
logs the selected backend, clears the cooldown and active-voice tables, and
returns the native byte success flag.
