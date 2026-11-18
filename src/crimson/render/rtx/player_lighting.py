"""Lazy player lighting resources; no extra textures, transmission, or specular pass."""

from __future__ import annotations

from collections.abc import Generator, Sequence
from contextlib import contextmanager

import msgspec

from grim.geom import Vec2
from grim.raylib_api import rl

from .light_uniforms import LIGHT_UNIFORMS, upload_material_lights
from .material_lights import MaterialLight
from .player_shaders import PLAYER_FRAGMENT, PLAYER_VERTEX


class PlayerLighting(msgspec.Struct):
    shader: rl.Shader | None = None
    locations: dict[str, int] = msgspec.field(default_factory=dict)
    active: bool = False

    def ensure_shader(self) -> rl.Shader:
        if self.shader is None:
            shader = rl.load_shader_from_memory(PLAYER_VERTEX, PLAYER_FRAGMENT)
            if int(shader.id) <= 0 or shader.id == rl.rl_get_shader_id_default():
                raise RuntimeError("RTX player lighting shader compilation failed")
            self.shader = shader
            self.locations = {
                name: int(rl.get_shader_location(shader, name))
                for name in LIGHT_UNIFORMS
            }
        return self.shader

    def prepare(self, lights: Sequence[MaterialLight], *, camera: Vec2, view_scale: Vec2) -> None:
        self.active = bool(lights)
        if not self.active:
            return
        shader = self.ensure_shader()
        upload_material_lights(shader, self.locations, lights, camera=camera, view_scale=view_scale)

    @contextmanager
    def scope(self, *, restore_shader: rl.Shader | None) -> Generator[None]:
        if not self.active or self.shader is None:
            yield
            return
        rl.rl_draw_render_batch_active()
        rl.begin_shader_mode(self.shader)
        try:
            yield
        finally:
            rl.rl_draw_render_batch_active()
            if restore_shader is None:
                rl.end_shader_mode()
            else:
                rl.begin_shader_mode(restore_shader)

    def close(self) -> None:
        if self.shader is not None:
            rl.unload_shader(self.shader)
        self.shader = None
        self.locations.clear()
        self.active = False
