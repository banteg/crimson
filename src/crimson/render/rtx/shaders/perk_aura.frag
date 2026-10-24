#version 330
// Monster Vision's aura in RTX (render/rtx/perk_lighting.py): a smooth radial fit over the quad's [0, 1] UVs.
in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;
void main() {
    float r = length((fragTexCoord - .5) * 2.);
    float envelope = 1. - smoothstep(.8, 1., r);
    // Fit to the original AURA cell's alpha; retain its 90-unit footprint and yellow tint.
    float alpha = clamp(1.04770258 * exp(-4.85 * r) * envelope, 0., 1.);
    finalColor = vec4(fragColor.rgb, fragColor.a * alpha);
}
