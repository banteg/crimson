#version 330
// A world rectangle, independent of the ground geometry and receiving target.
#include "common.glsl"
uniform vec4 u_visibility_world;
uniform vec2 u_ground_size;
LOC(0) out vec2 fragTexCoord;
LOC(1) out vec4 fragColor;
void main() {
    vec2 corner = corner_of(gl_VertexID);
    gl_Position = corner_position(corner);
    fragTexCoord = (u_visibility_world.xy + corner * u_visibility_world.zw) / u_ground_size;
    fragColor = vec4(1.);
}
