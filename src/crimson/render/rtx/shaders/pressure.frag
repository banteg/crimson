#version 330
// Thin, non-emissive explosion pressure fronts over the HDR world (render/rtx/shockwaves.py): a narrow
// compression and rarefaction band displaces and shades what lies under each. V_UP is the direction of texture v
// toward the target's top: up in raylib's render textures, down in the client's, which defines TARGET_V_DOWN.
#ifdef TARGET_V_DOWN
const float V_UP = -1.0;
#else
const float V_UP = 1.0;
#endif
in vec2 fragTexCoord;
out vec4 finalColor;
uniform sampler2D texture0;
uniform vec2 u_size;
uniform int u_count;
uniform vec4 u_fronts[16];
uniform vec4 u_strength[4]; // four fronts per vec4
void main() {
    vec2 uv = fragTexCoord;
    vec2 pixel = vec2(uv.x, V_UP > 0.0 ? 1.0 - uv.y : uv.y) * u_size;
    vec2 displacement = vec2(0.0);
    float contrast = 0.0;
    for (int i = 0; i < u_count; i++) {
        vec2 delta = pixel - u_fronts[i].xy;
        vec2 radius = max(u_fronts[i].zw, vec2(1.0));
        float radial = length(delta / radius);
        float distance = (radial - 1.0) * min(radius.x, radius.y);
        float width = max(3.0, min(radius.x, radius.y) * 0.022);
        float x = distance / width;
        float crest = exp(-0.5 * x * x);
        vec2 normal = normalize(delta / (radius * radius) + vec2(1e-10));
        float strength = u_strength[i / 4][i % 4];
        displacement += normal * (-x * crest) * (4.5 * strength);
        contrast += strength * (0.16 * crest - 0.14 * exp(-pow((distance + width) / width, 2.0)));
    }
    displacement = clamp(displacement, vec2(-6.0), vec2(6.0));
    vec2 offset = vec2(displacement.x, -V_UP * displacement.y) / u_size;
    vec3 color = texture(texture0, clamp(uv + offset, 0.5 / u_size, 1.0 - 0.5 / u_size)).rgb;
    finalColor = vec4(color * (1.0 + clamp(contrast, -0.15, 0.15)), 1.0);
}
