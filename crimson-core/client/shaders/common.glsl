// What the client's shaders share between OpenGL and WebGPU (crimson-core/client/shaders.py builds both): WebGPU's
// stages match varyings by location, and its clip space puts y = +1 at a target's row 0, where OpenGL puts y = -1.
#ifdef VULKAN
#extension GL_ARB_separate_shader_objects : enable
#define LOC(n) layout(location = n)
#else
#define LOC(n)
#endif

// A logical pixel position on a target whose row 0 is the image's top row. Direct3D 8 puts pixel centers at integer
// coordinates; OpenGL and WebGPU at half-integers.
vec4 target_position(vec2 pixel, vec2 size) {
    vec2 clip = (pixel + 0.5) / size * 2.0 - 1.0;
#ifdef VULKAN
    clip.y = -clip.y;
#endif
    return vec4(clip, 0.0, 1.0);
}

// A target-filling quad's corner (gl_VertexID 0..3, a strip) in clip space.
vec2 corner_of(int vertex) { return vec2(float(vertex & 1), float(vertex >> 1)); }
vec4 corner_position(vec2 corner) {
    vec2 clip = corner * 2.0 - 1.0;
#ifdef VULKAN
    clip.y = -clip.y;
#endif
    return vec4(clip, 0.0, 1.0);
}
