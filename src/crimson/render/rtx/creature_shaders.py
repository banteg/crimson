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
uniform float u_quad_aspect;
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
flat out vec4 quadCenterD00;
flat out vec2 quadD01;
""" + glsl("creature_visibility.glsl") + r"""
void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    world = vertexPosition.xy / u_view_scale - u_camera;
    vec2 owner = vertexNormal.xy / u_view_scale - u_camera;
    vec2 d00_screen = vec2(vertexPosition.z, vertexNormal.z);
    float r = u_quad_aspect > 0. ? u_quad_aspect : 1.;
    vec2 hx_screen = vec2(-d00_screen.x - r * d00_screen.y, r * d00_screen.x - d00_screen.y) / (1. + r * r);
    vec2 hy_screen = r * vec2(-hx_screen.y, hx_screen.x);
    vec2 d00 = d00_screen / u_view_scale;
    vec2 d01 = (-hx_screen + hy_screen) / u_view_scale;
    quadCenterD00 = vec4(owner, d00);
    quadD01 = d01;
    vec2 corner_wp = world;
    if (dot(d00, d00) > 1e-12 && dot(d01, d01) > 1e-12) {
        vec2 c00 = owner + d00, c01 = owner + d01, c11 = owner - d00, c10 = owner - d01;
        corner_wp = c00;
        float best = dot(world - c00, world - c00);
        float dist = dot(world - c01, world - c01);
        if (dist < best) { best = dist; corner_wp = c01; }
        dist = dot(world - c11, world - c11);
        if (dist < best) { best = dist; corner_wp = c11; }
        dist = dot(world - c10, world - c10);
        if (dist < best) { corner_wp = c10; }
    }
    lightVisibility0 = cornerVisibilities(0, world, corner_wp, owner);
    lightVisibility1 = cornerVisibilities(1, world, corner_wp, owner);
    lightVisibility2 = cornerVisibilities(2, world, corner_wp, owner);
    lightVisibility3 = cornerVisibilities(3, world, corner_wp, owner);
    lightVisibility4 = cornerVisibilities(4, world, corner_wp, owner);
    lightVisibility5 = cornerVisibilities(5, world, corner_wp, owner);
    lightVisibility6 = cornerVisibilities(6, world, corner_wp, owner);
    lightVisibility7 = cornerVisibilities(7, world, corner_wp, owner);
    fillSpecVisibilities(corner_wp, owner, quadRadius(d00, d01), specVisibility0, specVisibility1, specVisibility2);
    gl_Position = mvp * vec4(vertexPosition.xy, 0.0, 1.0);
}
"""

CREATURE_FRAGMENT = glsl("creature.frag")
