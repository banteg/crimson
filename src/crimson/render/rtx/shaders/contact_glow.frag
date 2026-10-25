#version 330
// An ion arc's contact glow on the ground (render/rtx/contact_glow.py), drawn instead of taking a light: rgb its
// hue at full value, alpha its peak radiance over GLOW_PEAK, a smooth disc over the quad's [0, 1] UVs.
// Shared with the client (crimson-core/client/shaders.py).
in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;
const float GLOW_PEAK = 4.;
// Fitted against the contact light it replaces: the light reached about this much on the arena's ground.
const float GLOW_GAIN = .2;
void main() {
    float r = length(fragTexCoord * 2. - 1.);
    float falloff = pow(max(0., 1. - r), 2.);
    vec3 glow = fragColor.rgb * fragColor.a * GLOW_PEAK * GLOW_GAIN * falloff;
    finalColor = vec4(pow(glow, vec3(1. / 2.2)), 1.);
}
