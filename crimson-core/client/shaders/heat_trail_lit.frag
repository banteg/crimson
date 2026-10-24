#version 330
// Monster Vision's heat trails added to the ground in view (src/crimson/render/rtx/shaders/heat_trail.frag), over the
// client's trail buffer, whose v runs down the world.
#define GROUND_V_DOWN
#include "heat_trail.frag"
