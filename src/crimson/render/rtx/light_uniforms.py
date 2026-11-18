"""The view and material-light uniforms shared by the three sprite shaders."""

from collections.abc import Sequence

from grim.geom import Vec2
from grim.raylib_api import rl

from .continuous_beam import beam_uniform
from .material_lights import MAX_MATERIAL_LIGHTS, MaterialLight

LIGHT_UNIFORMS = ("u_camera", "u_view_scale", "u_count", "u_pos", "u_rgb", "u_dir", "u_response", "u_beam_shape")


def upload_material_lights(
    shader: rl.Shader, locations: dict[str, int], lights: Sequence[MaterialLight], *, camera: Vec2, view_scale: Vec2,
) -> int:
    rl.rl_draw_render_batch_active()
    for name, value in (("u_camera", camera), ("u_view_scale", view_scale)):
        buf = rl.ffi.new("float[2]", [value.x, value.y])
        rl.set_shader_value(
            shader,
            locations[name],
            rl.ffi.cast("void *", buf),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC2,
        )
    lights = lights[:MAX_MATERIAL_LIGHTS]
    rl.set_shader_value(
        shader,
        locations["u_count"],
        rl.ffi.new("int *", len(lights)),
        rl.ShaderUniformDataType.SHADER_UNIFORM_INT,
    )
    if not lights:
        return 0
    values = {
        "u_pos": [v for light in lights for v in (light.pos.x, light.pos.y, light.radius, light.height)],
        "u_rgb": [v for light in lights for v in (*light.rgb, light.ring_radius)],
        "u_dir": [v for light in lights for v in (light.direction.x, light.direction.y, light.reflection_tail, light.length)],
        "u_response": [v for light in lights for v in light.response],
    }
    if locations["u_beam_shape"] >= 0:
        values["u_beam_shape"] = [v for light in lights for v in beam_uniform(light)]
    for name, value in values.items():
        buf = rl.ffi.new("float[]", value)
        rl.set_shader_value_v(
            shader,
            locations[name],
            rl.ffi.cast("void *", buf),
            rl.ShaderUniformDataType.SHADER_UNIFORM_VEC4,
            len(lights),
        )
    return len(lights)
