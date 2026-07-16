# `terrain_generate`

Native target: `crimsonland.exe` at `0x00417b80` (1,569 bytes).

Live Binary Ninja evidence shows that this routine bakes three texture layers
into the terrain render target selected by a `quest_meta_t`. Each layer uses a
different area density but the same 128-unit patch size and overscanned square
placement range. The native RNG order is rotation, Y, then X for every patch.

The recovered VC6 source matches all 408 normalized instructions exactly. The
`camera_offset` reference alias records the independently established adjacent
`camera_offset_x`/`camera_offset_y` vector, yielding references `88/0/0`.

The three pass counts are the signed integer expressions
`width * height * {800, 35, 15} / 0x80000`. Each pass binds the corresponding
`terrain_id`, `terrain_id_b`, or `terrain_id_c` texture, rotates every patch by
`(rand() % 314) * 0.01`, constructs an unscaled position vector from the next
two RNG draws, then scales it in place by `1 / config_texture_scale`. That
constructor-plus-`operator*=` shape explains both native RNG order and the x87
temporary layout without register or stack coercion.

When terrain texture creation has failed, the function selects the base quest
texture as the fallback render target and returns. Otherwise it reproduces the
complete Grim2D render-target setup, tinting, batch boundaries, camera reset,
and final render-state restoration. No inline assembly, volatile state, dummy
references, or dead expressions are used.
