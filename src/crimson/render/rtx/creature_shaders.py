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
out vec2 quadCoord;
flat out uvec4 specVis0;
flat out uvec4 specVis1;
flat out uvec4 specVis2;
flat out uvec4 specVis3;
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
    vec2 corner_wp = world;
    vec2 quad_coord = vec2(0., 0.);
    int corner_id = 0;
    bool has_quad = dot(d00, d00) > 1e-12 && dot(d01, d01) > 1e-12;
    if (has_quad) {
        vec2 c00 = owner + d00, c01 = owner + d01, c11 = owner - d00, c10 = owner - d01;
        corner_wp = c00;
        quad_coord = vec2(0., 0.);
        corner_id = 0;
        float best = dot(world - c00, world - c00);
        float dist = dot(world - c01, world - c01);
        if (dist < best) { best = dist; corner_wp = c01; quad_coord = vec2(0., 1.); corner_id = 1; }
        dist = dot(world - c11, world - c11);
        if (dist < best) { best = dist; corner_wp = c11; quad_coord = vec2(1., 1.); corner_id = 2; }
        dist = dot(world - c10, world - c10);
        if (dist < best) { corner_wp = c10; quad_coord = vec2(1., 0.); corner_id = 3; }
    }
    quadCoord = quad_coord;
    fillLightVisibilities(
        world, owner,
        lightVisibility0, lightVisibility1, lightVisibility2, lightVisibility3,
        lightVisibility4, lightVisibility5, lightVisibility6, lightVisibility7
    );
    fillSpecVisibilities(corner_wp, owner, d00, d01, has_quad, corner_id, specVis0, specVis1, specVis2, specVis3);
    gl_Position = mvp * vec4(vertexPosition.xy, 0.0, 1.0);
}
"""

CREATURE_FRAGMENT = glsl("creature.frag")
