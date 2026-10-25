#version 330
// Monster Vision's trail buffer passes (src/crimson/render/rtx/shaders/heat_trail.frag under HEAT_STAMP,
// render/rtx/heat_vision.py): fade it by u_fade, or stamp footprints into it.
#define HEAT_STAMP
#include "heat_trail.frag"
