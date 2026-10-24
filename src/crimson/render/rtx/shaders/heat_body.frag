#version 330
// Monster Vision in RTX (render/rtx/heat_vision.py): a monster's body as heat, hottest where it is thickest.
// The tint carries Monster Vision's fade, not the creature's own alpha, so near-invisible monsters show in full.
#include "filtering.glsl"
#include "ironbow.glsl"
in vec2 fragTexCoord;
in vec4 fragColor;
uniform sampler2D texture0;
uniform sampler2D u_thickness;
out vec4 finalColor;
void main() {
    float a = alphaBilinear(texture0, fragTexCoord).a;
    if (a * fragColor.a < 4. / 255.)
        discard;
    // The per-cell opening proxy (creature_translucency.py), softened: legs are a texel or two, the core several.
    vec2 cell = floor(fragTexCoord * 8.) / 8.;
    vec2 texel = 1. / vec2(textureSize(u_thickness, 0));
    float thickness = 0.;
    for (int y = -2; y <= 2; y++)
        for (int x = -2; x <= 2; x++)
            thickness += textureLod(u_thickness, clamp(fragTexCoord + vec2(x, y) * texel, cell + .5 * texel,
                                                       cell + vec2(.125) - .5 * texel), 0.).r;
    thickness *= 16. / 25.;
    float core = smoothstep(.5, 6., thickness);
    // Red is warmth: 1 while alive, cooling with the corpse's fade.
    float warmth = fragColor.r;
    vec3 heat = ironbow(mix(.04, .25 + .62 * core, warmth)) * 1.25;
    finalColor = vec4(pow(heat, vec3(1. / 2.2)), a * fragColor.a);
}
