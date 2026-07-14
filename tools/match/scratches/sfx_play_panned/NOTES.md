# sfx_play_panned

Validates the resident sample and per-id cooldown, applies the demo attenuation,
maps the Reflex Boost timer to the global playback rate (including the native
exactly-one stale-rate edge), arms the flamer or default cooldown, maps world X
through the camera and configured screen width into a clamped DirectSound pan,
starts a voice, applies configured SFX gain, and returns the id.
