#version 330
// Monster Vision in RTX (render/rtx/heat_vision.py): the world-space trail buffer, two passes.
// HEAT_STAMP: u_fade >= 0 fades the whole buffer by that much; otherwise a soft footprint of the tint's alpha.
// Without it: the buffer under the view, added to the ground as faint ironbow heat. GROUND_V_DOWN: the client's
// render targets keep row 0 at the top, where raylib's are stored upside down.
#include "ironbow.glsl"
in vec2 fragTexCoord;
in vec4 fragColor;
in vec2 world;
#ifdef HEAT_STAMP
uniform float u_fade;
#else
uniform sampler2D u_heat;
uniform vec2 u_ground_size;
uniform float u_alpha; // the scene's transition fade
#endif
out vec4 finalColor;
void main() {
#ifdef HEAT_STAMP
    if (u_fade >= 0.) {
        finalColor = vec4(0., 0., 0., u_fade);
        return;
    }
    float r = length(fragTexCoord * 2. - 1.);
    float h = fragColor.a * exp(-3. * r * r) * (1. - smoothstep(.8, 1., r));
    finalColor = vec4(h, h, h, 1.);
#else
#ifdef GROUND_V_DOWN
    vec2 uv = world / u_ground_size;
#else
    vec2 uv = vec2(world.x, u_ground_size.y - world.y) / u_ground_size;
#endif
    float h = all(greaterThanEqual(uv, vec2(0.))) && all(lessThanEqual(uv, vec2(1.))) ? textureLod(u_heat, uv, 0.).r : 0.;
    vec3 heat = ironbow(.12 + .4 * h) * pow(h, 1.5) * .45 * u_alpha;
    finalColor = vec4(pow(heat, vec3(1. / 2.2)), 1.);
#endif
}
