#version 330
// The ground material targets' stamps (render/rtx/materials.py): one pass per target channel.
in vec2 fragTexCoord;
in vec4 fragColor;
uniform sampler2D texture0;
uniform int u_kind; // 0 terrain, 1 blood, 2 corpse, 3 brass, 4 scorch, 5 ice
uniform int u_pass; // 0 coverage, 1 specularity/wetness/volume, 2 substrate height, 3 wetness rebase
uniform float u_wetness; // exp((deposit - epoch) / 45), or multiplicative rebase factor
out vec4 finalColor;
void main() {
    if (u_pass == 3) { finalColor = vec4(0., u_wetness, 0., 0.); return; }
    vec4 t = texture(texture0, fragTexCoord);
    float a = t.a * fragColor.a;
    if (floor(a * 255.0 + 0.5) < 4.0) discard;
    float lum = dot(t.rgb, vec3(.299, .587, .114));
    if (u_kind == 0) {
        finalColor = vec4(.04, 0., 0., clamp(.45 + (lum - .42) * .65, .05, .95));
        return;
    }
    if (u_pass == 0) {
        finalColor = vec4(float(u_kind == 1), float(u_kind == 2), float(u_kind == 3), a);
        return;
    }
    if (u_kind == 1) {
        // All five blood sprites occupy the atlas's 8x8 grid. Local UV needs no per-decal uniform.
        vec2 q = fract(fragTexCoord * 8.) * 2. - 1.;
        float radial = 1. - smoothstep(.10, 1., min(1., dot(q, q)));
        float volume = clamp(a * (.34 + .26 * radial), 0., .62);
        finalColor = vec4(0., volume * u_wetness, volume, volume);
        return;
    }
    float spec = u_kind == 2 ? .28 : (u_kind == 3 ? .96 : (u_kind == 5 ? .92 : .01));
    float height = u_kind == 2 ? (.045 + .075 * lum) : (u_kind == 3 || u_kind == 5 ? .14 : 0.);
    // Pass 2 accumulates relief: H' = H + (1-H)*height*a, rather than replacing terrain height.
    // Corpses/casings rise above the substrate while inheriting some of its texture; scorch adds no relief.
    finalColor = u_pass == 1 ? vec4(spec, 0., 0., a) : vec4(0., 0., 0., height * a);
}
