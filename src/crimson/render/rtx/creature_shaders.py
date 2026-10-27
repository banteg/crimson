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
""" + glsl("creature_visibility.glsl") + r"""
void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    world = vertexPosition.xy / u_view_scale - u_camera;
    vec2 owner = vertexNormal.xy / u_view_scale - u_camera;
    lightVisibility0 = cornerVisibilities(0, world, owner);
    lightVisibility1 = cornerVisibilities(1, world, owner);
    lightVisibility2 = cornerVisibilities(2, world, owner);
    lightVisibility3 = cornerVisibilities(3, world, owner);
    lightVisibility4 = cornerVisibilities(4, world, owner);
    lightVisibility5 = cornerVisibilities(5, world, owner);
    lightVisibility6 = cornerVisibilities(6, world, owner);
    lightVisibility7 = cornerVisibilities(7, world, owner);
    gl_Position = mvp * vec4(vertexPosition, 1.0);
}
"""

CREATURE_FRAGMENT = glsl("creature.frag")
