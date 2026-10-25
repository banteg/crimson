#version 330
// The RTX ground's beam visibility pass (src/crimson/render/rtx/shaders/ground.frag's BEAM_VISIBILITY_PASS) over the
// client's ground textures, whose v runs down the world where raylib's run up.
#define GROUND_V_DOWN
#define BEAM_VISIBILITY_PASS
#include "ground.frag"
