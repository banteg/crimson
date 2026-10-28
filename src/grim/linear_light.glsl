// The RTX world target holds linear light: everything in it is radiance, it blends and adds as light does, and the
// tonemap (src/crimson/render/rtx/shaders/hdr_tonemap.frag) is the one place it is compressed and encoded for the
// display. Shared with the client (crimson-core/client/shaders.py). Colors are the
// original's artwork or look-dev picks, gamma-2.2 encoded, and decode where they enter; amounts of light (an alpha,
// a glow's profile, an intensity) are already linear and stay as they are.
const float ART_GAMMA = 2.2;

vec3 decodeArt(vec3 art) { return pow(max(art, vec3(0.)), vec3(ART_GAMMA)); }
vec3 encodeDisplay(vec3 light) { return pow(max(light, vec3(0.)), vec3(1. / ART_GAMMA)); }

// Premultiplied art, a color times its amount: its hue decodes, its amount stays.
vec3 decodeGlow(vec3 premultiplied) {
    float peak = max(premultiplied.r, max(premultiplied.g, premultiplied.b));
    return peak > 0. ? decodeArt(premultiplied / peak) * peak : vec3(0.);
}

// A draw's color as it lands: decoded in the world (its target's linear flag, texture_mode.py), as drawn anywhere else.
vec3 worldColor(vec3 art, int in_world) { return in_world != 0 ? decodeArt(art) : art; }
