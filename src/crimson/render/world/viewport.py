from __future__ import annotations

import msgspec

from grim.config import CrimsonConfig
from grim.geom import Vec2


class ViewTransform(msgspec.Struct, frozen=True):
    camera: Vec2
    view_scale: Vec2
    screen_size: Vec2
    out_size: Vec2

    @property
    def scale(self) -> float:
        return view_scale_avg(self.view_scale)

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return world_to_screen_with(pos, camera=self.camera, view_scale=self.view_scale)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return screen_to_world_with(pos, camera=self.camera, view_scale=self.view_scale)


def camera_screen_size(
    *,
    world_size: float,
    config: CrimsonConfig | None,
    runtime_w: float,
    runtime_h: float,
) -> Vec2:
    if runtime_w > 0.0 and runtime_h > 0.0:
        # Prefer live framebuffer dimensions. Config values can lag behind
        # the actual game window resolution during launcher/state handoff.
        screen_w = runtime_w
        screen_h = runtime_h
    elif config is not None:
        screen_w = float(config.display.width)
        screen_h = float(config.display.height)
    else:
        screen_w = max(1.0, runtime_w)
        screen_h = max(1.0, runtime_h)
    world = float(world_size)
    if world <= 0.0:
        return Vec2(max(1.0, screen_w), max(1.0, screen_h))
    out_w = max(1.0, screen_w)
    out_h = max(1.0, screen_h)
    scale = max(out_w / world, out_h / world, 1.0)
    return Vec2(min(world, out_w / scale), min(world, out_h / scale))


def clamp_camera(*, world_size: float, camera: Vec2, screen_size: Vec2) -> Vec2:
    cam_x = camera.x
    cam_y = camera.y
    if cam_x > -1.0:
        cam_x = -1.0
    if cam_y > -1.0:
        cam_y = -1.0
    min_x = screen_size.x - float(world_size)
    min_y = screen_size.y - float(world_size)
    if cam_x < min_x:
        cam_x = min_x
    if cam_y < min_y:
        cam_y = min_y
    return Vec2(cam_x, cam_y)


def view_transform(
    *,
    world_size: float,
    config: CrimsonConfig | None,
    camera: Vec2,
    out_size: Vec2,
) -> ViewTransform:
    screen_size = camera_screen_size(
        world_size=world_size,
        config=config,
        runtime_w=out_size.x,
        runtime_h=out_size.y,
    )
    clamped_camera = clamp_camera(world_size=world_size, camera=camera, screen_size=screen_size)
    scale_x = out_size.x / screen_size.x if screen_size.x > 0.0 else 1.0
    scale_y = out_size.y / screen_size.y if screen_size.y > 0.0 else 1.0
    return ViewTransform(clamped_camera, Vec2(scale_x, scale_y), screen_size, out_size)


def world_to_screen_with(pos: Vec2, *, camera: Vec2, view_scale: Vec2) -> Vec2:
    return (pos + camera).mul_components(view_scale)


def screen_to_world_with(pos: Vec2, *, camera: Vec2, view_scale: Vec2) -> Vec2:
    safe_scale = Vec2(
        view_scale.x if view_scale.x > 0.0 else 1.0,
        view_scale.y if view_scale.y > 0.0 else 1.0,
    )
    return pos.div_components(safe_scale) - camera


def view_scale_avg(view_scale: Vec2) -> float:
    return view_scale.avg_component()
