#version 330
// Monster Vision's additive ground light (src/crimson/render/rtx/shaders/ground.frag under MONSTER_VISION_PASS,
// render/rtx/perk_lighting.py) over the client's ground textures, whose v runs down the world.
#define GROUND_V_DOWN
#define MONSTER_VISION_PASS
#include "ground.frag"
