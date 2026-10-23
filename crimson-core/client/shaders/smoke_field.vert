#version 330
// The fluid smoke field's quad on a target (src/crimson/render/rtx/shaders/smoke.frag): its edges in the target's
// logical pixels, its texture coordinates across the field from its world origin.
#include "common.glsl"
uniform vec4 rect; // left, top, width, height
uniform vec2 target_size;
LOC(0) out vec2 fragTexCoord;
LOC(1) out vec4 fragColor;
void main() {
    vec2 corner = corner_of(gl_VertexID);
    gl_Position = target_position(rect.xy + corner * rect.zw - 0.5, target_size);
    fragTexCoord = corner;
    fragColor = vec4(1.0);
}
