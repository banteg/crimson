# fx_spawn_particle

The fast particle constructor matches the shipped function exactly: 67/67
instructions and all 18 masked references. It confirms the same fixed-pool
scan, random replacement, inline four-float scale copy, wide x87 trig, and
spin initialization recovered independently for the slow constructor.

The third argument is accepted but unused. The final argument is copied
directly into particle intensity, while the slow constructor uses a constant
intensity and initializes Bubblegun-only style and target fields.
