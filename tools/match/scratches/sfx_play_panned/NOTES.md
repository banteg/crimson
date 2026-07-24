# sfx_play_panned

Validates the resident sample and per-id cooldown, applies the demo attenuation,
maps the Reflex Boost timer to the global playback rate (including the native
exactly-one stale-rate edge), arms the flamer or default cooldown, maps world X
through the camera and configured screen width into a clamped DirectSound pan,
starts a voice, applies configured SFX gain, and returns the id.

The recovered position boundary is a read-only `vec2f_t`: the implementation
uses `pos->x` for pan and never reads or mutates `y`. The shared audio and
gameplay declarations now also preserve the native integer return value.
Binary Ninja at `0x0043d260` shows the same typed position and return contract.
The source remains exact at 110/110 instructions with all 34 references.
