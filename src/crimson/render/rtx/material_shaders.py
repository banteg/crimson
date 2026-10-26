"""Ground material shaders adapted from the crimson-night-argon look development study."""

from .shaders import glsl

GROUND_FRAGMENT = glsl("ground.frag")
# Scalar visibility for every ground source, on a coarse world-anchored grid.
BEAM_VISIBILITY_FRAGMENT = GROUND_FRAGMENT.replace("\n", "\n#define BEAM_VISIBILITY_PASS\n", 1)
STAMP_FRAGMENT = glsl("ground_stamp.frag")
