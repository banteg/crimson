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

The freeware function takes the sample index, volume and pan by value and
returns the playback channel. In 1.0.2 (0x401630) and 1.3.0 (0x403000), it
starts an FMOD channel paused, applies volume and pan in the 0–255 range and
unpauses the channel. Each import thunk jumps to its named fmod.dll IAT slot.
1.3.0 adds the sound-disabled check. The routine immediately after playback
in each build updates the cooldowns once per frame.

1.4.0 (0x405630) calls the dynamically loaded SFX_PlaySfx and
SFX_SetChannelVolume exports. The native loader stores their GetProcAddress
returns at 0x4369c0 and 0x4369d0 respectively. Playback uses a longer
cooldown for sample 14 and passes (volume + 4) / 6 to the volume setter.
