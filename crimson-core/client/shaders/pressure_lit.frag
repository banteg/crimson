#version 330
// The Python port's RTX pressure fronts (src/crimson/render/rtx/shaders/pressure.frag) over the client's HDR world,
// whose v runs down the target where raylib's run up.
#define TARGET_V_DOWN
#include "pressure.frag"
