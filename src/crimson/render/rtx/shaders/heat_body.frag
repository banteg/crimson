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
    // The per-cell opening proxy (creature_translucency.py), box-blurred per cell on upload: legs are a texel or
    // two, the core several.
    vec2 cell = floor(fragTexCoord * 8.) / 8.;
    vec2 half_texel = .5 / vec2(textureSize(u_thickness, 0));
    float thickness = textureLod(u_thickness, clamp(fragTexCoord, cell + half_texel, cell + vec2(.125) - half_texel), 0.).r * 16.;
    float core = smoothstep(.5, 6., thickness);
    // Red is warmth: 1 while alive, cooling with the corpse's fade.
    float warmth = fragColor.r;
    vec3 heat = ironbow(mix(.04, .25 + .62 * core, warmth)) * 1.25;
    finalColor = vec4(pow(heat, vec3(1. / 2.2)), a * fragColor.a);
}
