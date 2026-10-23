"""Ground material shaders adapted from the crimson-night-argon look development study."""

from .shaders import glsl

GROUND_FRAGMENT = glsl("ground.frag")
MONSTER_VISION_FRAGMENT = GROUND_FRAGMENT.replace("#version 330\n", "#version 330\n#define MONSTER_VISION_PASS\n", 1)
STAMP_FRAGMENT = glsl("ground_stamp.frag")
