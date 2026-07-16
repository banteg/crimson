# `creature_render_all`

Native target: `crimsonland.exe` at `0x00419680` (1302 bytes).

Exact MSVC 6.6 match: 349/349 normalized instructions, with all 87 native
references explained.

Recovered behavior:

- Rendering is skipped while the transition alpha is non-positive or either
  the current or previous state is Mods Menu / Plugin Runtime.
- The first 384-entry creature pass draws the Monster Vision, collision, and
  self-damage overlays. Lifecycle values below zero fade in from
  `(lifecycle + 10) * 0.1`; only the Monster Vision path explicitly clamps
  that alpha to `[0, 1]`.
- Per-type creature sprites are dispatched in native order: zombie, spider
  SP1, spider SP2, alien, then lizard.
- A positive freeze timer adds the rotated white freeze overlay. Its alpha is
  clamped, multiplied by the transition alpha and `0.7`, and each creature's
  rotation includes `creature_index * 0.01`.
- The final renderer color is restored to cyan.

Source-shape evidence:

- Indexed loops over `creature_pool` are significant: VC6 strength-reduces
  them to the native field-anchored pointer walks in both passes.
- The freeze quad uses the natural repeated inline expression
  `creature->size * 0.5f` for its X and Y origins. Writing an explicit
  `half_size` temporary preserves behavior but changes VC6's load scheduling;
  the repeated expression produces the exact native common-subexpression
  lowering.
- A single `freeze_alpha * transition_alpha * 0.7f` expression reproduces the
  native floating-point scheduling around the batch call.
