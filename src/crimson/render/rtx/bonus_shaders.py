"""Analytical dark bonus shells and lit foil emblems, adapted from the Argon lookdev."""

from .shaders import glsl

BONUS_VERTEX = r"""
#version 330
in vec3 vertexPosition;
in vec2 vertexTexCoord;
in vec4 vertexColor;
uniform mat4 mvp;
uniform vec2 u_camera;
uniform vec2 u_view_scale;
out vec2 fragTexCoord;
out vec4 fragColor;
out vec2 world;
void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    world = vertexPosition.xy / u_view_scale - u_camera;
    gl_Position = mvp * vec4(vertexPosition, 1.0);
}
"""

BONUS_FRAGMENT = glsl("bonus.frag")
