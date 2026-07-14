# dsound_init

Replaces any prior DirectSound interface, creates the native device, applies the
requested cooperative level, creates the primary buffer, configures its PCM
format from the caller's channels/rate/depth tuple, releases the temporary
primary-buffer interface, and returns a byte success flag.
