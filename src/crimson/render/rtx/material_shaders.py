"""Ground material shaders adapted from the crimson-night-argon look development study."""

from .shaders import glsl

GROUND_FRAGMENT = glsl("ground.frag")
# The beams' visibility at a lower resolution (materials.py's BEAM_VISIBILITY_SCALE).
BEAM_VISIBILITY_FRAGMENT = GROUND_FRAGMENT.replace("\n", "\n#define BEAM_VISIBILITY_PASS\n", 1)
STAMP_FRAGMENT = glsl("ground_stamp.frag")
