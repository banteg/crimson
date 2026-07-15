# `init_audio_and_terrain`

Native target: `crimsonland.exe` at `0x0042a9f0` (480 bytes).

Live Binary Ninja evidence recovers the sound-system startup gate, terrain
dimension/scale policy, render-target retry, safe-mode fallback, and log flush.

Exact verified match: 100.00%, with 116/116 normalized instructions and
masked references `65/0/0`, using Microsoft Visual C++ 6.5 with
`/O2 /GB /W3 /GR-`.

## Recovered source shape

- Startup prints the Grim-success and sound-section banners. The sound system
  initializes unless the staging disabled flag is already set; a failed SFX
  initialization sets that same flag, while a pre-disabled run prints the
  no-sounds message.
- Terrain dimensions reset to 1024 by 1024 and texture scale clamps to
  `[0.5, 4.0]` before render-target creation.
- The first `ground` texture attempt uses `1024 / scale` for both dimensions.
  On failure, scale doubles and a second attempt uses the terrain width and
  height independently.
- A successful retry keeps the doubled scale and logs creation. A failed retry
  restores the prior scale, sets `terrain_texture_failed`, and logs both the
  failure and safe-mode transition.
- Existing or newly entered safe mode emits the static-terrain warning, then
  the console queue is flushed to `console.log` in every path.

Live xrefs also identify `0x004aaeea` as the sound-disabled startup staging
byte: `crimsonland_main` loads it from Grim config slot `0x53`, copies it into
`config_blob.sound_disabled`, and this function sets it after SFX init failure.
