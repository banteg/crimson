# effect_spawn_explosion_burst

Native target: `crimsonland.exe` at `0x0042f6c0` (964 bytes).

The emitter has four phases: a contracting gray effect-1 core; two expanding
effect-17 shockwaves only above detail preset 3; a fast-growing white effect-0
flash; and one, three, or four effect-12 debris sprites depending on detail.
The debris phase randomizes full-turn rotation, square velocity, signed-looking
scale growth through masked arithmetic, and a small positive rotation step.

All 182 native instructions and all 75 static references match. The shockwave
phase reuses one `scale * 5` local across its two entries and derives age and
lifetime from the same `index * 0.2` x87 value. The debris tier is a compact
inline policy returning 1 below detail 2, 3 at detail 2..3, and 4 at detail 4+;
that policy boundary preserves native's common positive-count guard.
