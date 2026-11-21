#version 330
// Compact per-texel height and exposed blood amount for ground.frag's normal stencil.
// Baked on initialization and whenever decals modify surface or coverage;
// wetness aging and epoch rebasing only touch surface.g and leave these channels exact.
in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;

uniform sampler2D u_surface_tex;  // R=specularity, G=wet amount at epoch, B=volume, A=substrate height
uniform sampler2D u_material_tex; // Ordered RGBA coverage: blood, corpse, brass, ice

float blood_below_ice(vec4 surface, vec4 coverage) {
    float exposed = max(1.0 - coverage.a, 0.001);
    return clamp(surface.b * coverage.r / (exposed * exposed), 0.0, 0.999);
}

void main() {
    vec4 surf = texture(u_surface_tex, fragTexCoord);
    vec4 weights = texture(u_material_tex, fragTexCoord);
    finalColor = vec4(surf.a, blood_below_ice(surf, weights), 0.0, 1.0);
}
