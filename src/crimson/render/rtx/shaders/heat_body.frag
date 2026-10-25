#version 330
// Monster Vision in RTX (render/rtx/heat_vision.py): cool extremities, hot internal lobes and artwork detail.
// The tint carries Monster Vision's fade, not the creature's own alpha, so near-invisible monsters show in full.
#include "filtering.glsl"
#include "ironbow.glsl"
in vec2 fragTexCoord;
in vec4 fragColor;
uniform sampler2D texture0;
uniform sampler2D u_density;
out vec4 finalColor;
void main() {
    vec4 art = alphaBilinear(texture0, fragTexCoord);
    float a = art.a;
    if (a * fragColor.a < 4. / 255.)
        discard;
    // Two cell-local 5x5 alpha blurs on first use (creature_translucency.py): continuous coverage avoids the
    // square-opening proxy's whole-body jumps when an animation pose gains or loses a texel of support.
    vec2 cell = floor(fragTexCoord * 8.) / 8.;
    vec2 half_texel = .5 / vec2(textureSize(u_density, 0));
    float density = textureLod(u_density, clamp(fragTexCoord, cell + half_texel, cell + vec2(.125) - half_texel), 0.).r;
    // Preserve a wide cool-to-hot range instead of saturating the entire silhouette to yellow.
    float core = pow(density, 1.15);
    // Two soft lobes in sprite-local space: a fixed abdomen and a head, which green/blue place where a zombie
    // walking frame's head is (render/rtx/heat_heads.py); zero keeps it fixed.
    vec2 p = fract(fragTexCoord * 8.) - .5;
    vec2 abdomen = (p - vec2(-.12, 0.)) * vec2(12., 10.);
    vec2 head = (p - (fragColor.g > 0. ? fragColor.gb - .5 : vec2(.025, 0.))) * vec2(18., 13.);
    float organs = .34 * exp(-dot(abdomen, abdomen)) + .28 * exp(-dot(head, head));
    // Recover the original sprite's small surface features from the color already fetched with its alpha.
    // Bound their contribution so baked artwork shading cannot bring back the large temperature pops.
    float detail = .24 * clamp(dot(art.rgb, vec3(.2126, .7152, .0722)) - .45, -.35, .35);
    float temperature = .13 + .52 * core + organs + detail;
    // Red is warmth: 1 while alive, cooling with the corpse's fade.
    float warmth = fragColor.r;
    vec3 heat = ironbow(mix(.04, temperature, warmth)) * 1.25;
    finalColor = vec4(pow(heat, vec3(1. / 2.2)), a * fragColor.a);
}
