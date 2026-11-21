"""Exact world-space 32x32 tile light bitmask matching crimson-core/client/ground_tiles.h."""

from __future__ import annotations

import math
from collections.abc import Sequence

import msgspec

from grim.raylib_api import rl

from .material_lights import MAX_MATERIAL_LIGHTS, MaterialLight

TILE_SIZE = 32
_MARGIN = 0.01


def _point_box_dist_sq(px: float, py: float, x0: float, y0: float, x1: float, y1: float) -> float:
    dx = x0 - px if px < x0 else (px - x1 if px > x1 else 0.0)
    dy = y0 - py if py < y0 else (py - y1 if py > y1 else 0.0)
    return dx * dx + dy * dy


def _point_seg_dist_sq(
    px: float, py: float, cx: float, cy: float, ux: float, uy: float, half: float,
) -> float:
    dx = px - cx
    dy = py - cy
    along = dx * ux + dy * uy
    if along < -half:
        along = -half
    elif along > half:
        along = half
    rx = dx - ux * along
    ry = dy - uy * along
    return rx * rx + ry * ry


def _segment_intersects_box(
    ax: float, ay: float, ex: float, ey: float, x0: float, y0: float, x1: float, y1: float,
) -> bool:
    dx = ex - ax
    dy = ey - ay
    t0 = 0.0
    t1 = 1.0
    for p, q in ((-dx, ax - x0), (dx, x1 - ax), (-dy, ay - y0), (dy, y1 - ay)):
        if p == 0.0:
            if q < 0.0:
                return False
            continue
        r = q / p
        if p < 0.0:
            if r > t1:
                return False
            if r > t0:
                t0 = r
        else:
            if r < t0:
                return False
            if r < t1:
                t1 = r
    return True


def _capsule_hits_box(
    cx: float, cy: float, ux: float, uy: float, half: float, radius: float,
    x0: float, y0: float, x1: float, y1: float,
) -> bool:
    r2 = radius * radius
    if half <= 0.0:
        return _point_box_dist_sq(cx, cy, x0, y0, x1, y1) < r2
    ax = cx - ux * half
    ay = cy - uy * half
    ex = cx + ux * half
    ey = cy + uy * half
    if _segment_intersects_box(ax, ay, ex, ey, x0, y0, x1, y1):
        return True
    if (
        _point_box_dist_sq(ax, ay, x0, y0, x1, y1) < r2
        or _point_box_dist_sq(ex, ey, x0, y0, x1, y1) < r2
    ):
        return True
    return (
        _point_seg_dist_sq(x0, y0, cx, cy, ux, uy, half) < r2
        or _point_seg_dist_sq(x1, y0, cx, cy, ux, uy, half) < r2
        or _point_seg_dist_sq(x0, y1, cx, cy, ux, uy, half) < r2
        or _point_seg_dist_sq(x1, y1, cx, cy, ux, uy, half) < r2
    )


def _ring_hits_box(
    cx: float, cy: float, ring: float, radius: float, x0: float, y0: float, x1: float, y1: float,
) -> bool:
    outer = ring + radius
    if _point_box_dist_sq(cx, cy, x0, y0, x1, y1) >= outer * outer:
        return False
    inner = ring - radius
    if inner <= 0.0:
        return True
    fx = max(abs(cx - x0), abs(cx - x1))
    fy = max(abs(cy - y0), abs(cy - y1))
    return fx * fx + fy * fy > inner * inner


def build_ground_tiles(
    world_width: float,
    world_height: float,
    lights: Sequence[MaterialLight],
    shapes: Sequence[float] = (),
    *,
    beams: bool = False,
) -> tuple[int, int, bytearray]:
    """Return `(width, height, rgba8_masks)` with bit `i` set on tiles light `i` can reach."""
    count = min(len(lights), MAX_MATERIAL_LIGHTS)
    if not count or not (0.0 < world_width <= 65536.0 and 0.0 < world_height <= 65536.0):
        return 0, 0, bytearray()
    width = math.ceil(world_width / TILE_SIZE)
    height = math.ceil(world_height / TILE_SIZE)
    masks = bytearray(width * height * 4)
    has_shapes = beams and len(shapes) >= count * 4
    for i in range(count):
        light = lights[i]
        has_diff = light.illumination_gain > 0.0
        has_spec = light.reflection_gain > 0.0 and light.reflection_reach > 0.0
        if not has_diff and not has_spec:
            continue
        cx = light.pos.x
        cy = light.pos.y
        ring = light.ring_radius
        is_ring = ring > 0.0
        dx = light.direction.x
        dy = light.direction.y
        square = dx * dx + dy * dy
        has_dir = square > 0.0001
        if has_dir:
            inv_len = 1.0 / math.sqrt(square)
            ux = dx * inv_len
            uy = dy * inv_len
        else:
            ux = 1.0
            uy = 0.0
        beam_half = shapes[4 * i + 3] if has_shapes else 0.0
        continuous = not is_ring and has_shapes and beam_half > 0.0 and has_diff
        spec_half = max(0.0, light.length * 0.5) if has_dir else 0.0
        diff_half = beam_half if continuous else spec_half
        diff_rad = max(1.0, light.radius) + _MARGIN if has_diff else 0.0
        spec_rad = max(0.01, light.reflection_reach) + _MARGIN if has_spec else 0.0
        max_rad = max(diff_rad, spec_rad)
        if is_ring:
            ex = ey = max_rad + ring
        else:
            ex = max(
                diff_rad + abs(ux) * diff_half if has_diff else 0.0,
                spec_rad + abs(ux) * spec_half if has_spec else 0.0,
            )
            ey = max(
                diff_rad + abs(uy) * diff_half if has_diff else 0.0,
                spec_rad + abs(uy) * spec_half if has_spec else 0.0,
            )
        x0 = max(0, math.floor((cx - ex) / TILE_SIZE))
        y0 = max(0, math.floor((cy - ey) / TILE_SIZE))
        x1 = min(width - 1, math.floor((cx + ex) / TILE_SIZE))
        y1 = min(height - 1, math.floor((cy + ey) / TILE_SIZE))
        bit = 1 << (i % 8)
        byte = i // 8
        shared_capsule = has_diff and has_spec and diff_half == spec_half
        for ty in range(y0, y1 + 1):
            by0 = float(ty * TILE_SIZE)
            by1 = by0 + TILE_SIZE
            row = ty * width
            for tx in range(x0, x1 + 1):
                bx0 = float(tx * TILE_SIZE)
                bx1 = bx0 + TILE_SIZE
                if is_ring:
                    hit = _ring_hits_box(cx, cy, ring, max_rad, bx0, by0, bx1, by1)
                elif shared_capsule:
                    hit = _capsule_hits_box(cx, cy, ux, uy, diff_half, max_rad, bx0, by0, bx1, by1)
                else:
                    hit = (
                        (has_diff and _capsule_hits_box(cx, cy, ux, uy, diff_half, diff_rad, bx0, by0, bx1, by1))
                        or (has_spec and _capsule_hits_box(cx, cy, ux, uy, spec_half, spec_rad, bx0, by0, bx1, by1))
                    )
                if hit:
                    masks[(row + tx) * 4 + byte] |= bit
    return width, height, masks


class GroundLightTiles(msgspec.Struct):
    texture: rl.Texture | None = None

    def close(self) -> None:
        if self.texture is not None:
            rl.unload_texture(self.texture)
            self.texture = None

    def upload(self, width: int, height: int, masks: bytearray) -> rl.Texture:
        if self.texture is not None and (int(self.texture.width) != width or int(self.texture.height) != height):
            self.close()
        buf = rl.ffi.from_buffer("unsigned char[]", masks)
        if self.texture is None:
            image = rl.Image(
                rl.ffi.cast("void *", buf),
                width,
                height,
                1,
                rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R8G8B8A8,
            )
            self.texture = rl.load_texture_from_image(image)
            if self.texture.id <= 0:
                self.texture = None
                raise RuntimeError("Could not upload ground light tiles")
            rl.set_texture_filter(self.texture, rl.TextureFilter.TEXTURE_FILTER_POINT)
            rl.set_texture_wrap(self.texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
        else:
            rl.update_texture(self.texture, rl.ffi.cast("void *", buf))
        return self.texture
