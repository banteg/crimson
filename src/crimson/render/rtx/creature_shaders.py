"""Art-directed dome and silhouette lighting for the original 8x8 creature atlases."""

from .shaders import glsl

# raylib's vertices for creature.frag, with each light's visibility at the quad's corners (creature_visibility.glsl).
# The normal carries the quad's center in screen coordinates (creatures.py's centered body quads): the creature whose
# body its corners spare.
CREATURE_VERTEX = r"""
#version 330
in vec3 vertexPosition;
in vec2 vertexTexCoord;
in vec4 vertexColor;
in vec3 vertexNormal;
uniform mat4 mvp;
uniform vec2 u_camera;
uniform vec2 u_view_scale;
out vec2 fragTexCoord;
out vec4 fragColor;
out vec2 world;
out vec4 lightVisibility0;
out vec4 lightVisibility1;
out vec4 lightVisibility2;
out vec4 lightVisibility3;
out vec4 lightVisibility4;
out vec4 lightVisibility5;
out vec4 lightVisibility6;
out vec4 lightVisibility7;
out vec4 specVisibility0;
out vec4 specVisibility1;
out vec4 specVisibility2;
out vec4 specVisibility3;
flat out vec4 quadFlat;
""" + glsl("creature_visibility.glsl") + r"""
void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    world = vertexPosition.xy / u_view_scale - u_camera;
    vec2 owner = vertexNormal.xy / u_view_scale - u_camera;
    vec2 d00 = vec2(vertexPosition.z, vertexNormal.z) / u_view_scale;
    quadFlat = vec4(owner, d00);
    vec2 corner_wp = world;
    if (dot(d00, d00) > 1e-12) {
        vec2 d = world - owner;
        vec2 d01 = vec2(d00.y, -d00.x);
        vec2 d10 = vec2(-d00.y, d00.x);
        float s00 = dot(d, d00);
        float s01 = dot(d, d01);
        corner_wp = abs(s00) >= abs(s01)
            ? (s00 >= 0. ? owner + d00 : owner - d00)
            : (s01 >= 0. ? owner + d01 : owner + d10);
    }
    lightVisibility0 = cornerVisibilities(0, corner_wp, owner);
    lightVisibility1 = cornerVisibilities(1, corner_wp, owner);
    lightVisibility2 = cornerVisibilities(2, corner_wp, owner);
    lightVisibility3 = cornerVisibilities(3, corner_wp, owner);
    lightVisibility4 = cornerVisibilities(4, corner_wp, owner);
    lightVisibility5 = cornerVisibilities(5, corner_wp, owner);
    lightVisibility6 = cornerVisibilities(6, corner_wp, owner);
    lightVisibility7 = cornerVisibilities(7, corner_wp, owner);
    fillSpecVisibilities(corner_wp, owner, specVisibility0, specVisibility1, specVisibility2, specVisibility3);
    gl_Position = mvp * vec4(vertexPosition.xy, 0.0, 1.0);
}
"""

CREATURE_FRAGMENT = glsl("creature.frag")
