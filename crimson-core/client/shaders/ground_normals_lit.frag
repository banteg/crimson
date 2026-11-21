#version 330
// The Python port's baked ground normals (src/crimson/render/rtx/shaders/ground_normals.frag)
// over the client's ground textures, whose v runs down the world where raylib's run up.
#define GROUND_V_DOWN
#include "ground_normals.frag"
