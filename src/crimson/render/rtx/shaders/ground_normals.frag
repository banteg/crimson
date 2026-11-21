#version 330
// Compact per-texel (substrate height, blood volume, blood coverage, exposed fraction)
// for ground.frag's 8-tap normal stencil. Storing 1.0 - ice keeps half-float precision
// near opaque ice while preserving exact linear bilinear filtering at fractional UVs;
// wetness aging and epoch rebasing only touch surface.g and leave this cache exact.
in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;

uniform sampler2D u_surface_tex;  // R=specularity, G=wet amount at epoch, B=volume, A=substrate height
uniform sampler2D u_material_tex; // Ordered RGBA coverage: blood, corpse, brass, ice

void main() {
    vec4 surf = texture(u_surface_tex, fragTexCoord);
    vec4 weights = texture(u_material_tex, fragTexCoord);
    finalColor = vec4(surf.a, surf.b, weights.r, 1.0 - weights.a);
}
