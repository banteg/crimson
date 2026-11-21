"""Conservative world-space 32x32 tile light bitmask for ground.frag."""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

import msgspec

from grim.edr import load_texture_with_reclaim
from grim.raylib_api import rl

from .material_lights import MAX_MATERIAL_LIGHTS, MaterialLight

TILE_SIZE = 32
MAX_TILES = 16384  # caps vectorized working set (up to 4096x4096 world units)
_HALF_TILE = TILE_SIZE * 0.5
_TILE_DIAG_RADIUS = _HALF_TILE * math.sqrt(2.0)
_MARGIN = 0.01

_NP: Any = ...  # sentinel: lazy-loaded on first RTX ground tile build
_TILE_CENTERS_CACHE: dict[tuple[int, int], tuple[Any, Any]] = {}


def _numpy() -> Any:
    global _NP
    if _NP is ...:
        try:
            import numpy as np
        except ImportError:  # pragma: no cover - optional acceleration outside dev installs
            _NP = None
        else:
            _NP = np
    return _NP


def _tile_centers(np: Any, width: int, height: int) -> tuple[Any, Any]:
    cached = _TILE_CENTERS_CACHE.get((width, height))
    if cached is not None:
        return cached
    mx = (np.arange(width, dtype=np.float32) * TILE_SIZE + _HALF_TILE)[None, None, :]
    my = (np.arange(height, dtype=np.float32) * TILE_SIZE + _HALF_TILE)[None, :, None]
    if len(_TILE_CENTERS_CACHE) >= 8:
        _TILE_CENTERS_CACHE.clear()
    _TILE_CENTERS_CACHE[(width, height)] = (mx, my)
    return mx, my


def _capsule_hits(
    np: Any,
    mx: Any,
    my: Any,
    cx: Any,
    cy: Any,
    ux: Any,
    uy: Any,
    half: Any,
    rad: Any,
) -> Any:
    """Exact disc hits (`half == 0`) and tight conservative capsule hits (`half > 0`)."""
    dx = mx - cx
    dy = my - cy
    abs_dx = np.abs(dx)
    abs_dy = np.abs(dy)
    # Exact disc test (also exact for the axis-aligned box vs point distance).
    bx = np.maximum(0.0, abs_dx - _HALF_TILE)
    by = np.maximum(0.0, abs_dy - _HALF_TILE)
    disc_hit = (bx * bx + by * by) < (rad * rad)
    if not np.any(half > 0.0):
        return disc_hit
    # Tight conservative capsule test: AABB + exact normal-strip SAT + rounded-cap center distance.
    ex = rad + np.abs(ux) * half + _HALF_TILE
    ey = rad + np.abs(uy) * half + _HALF_TILE
    perp_limit = rad + _HALF_TILE * (np.abs(ux) + np.abs(uy))
    perp = np.abs(-dx * uy + dy * ux)
    along = np.clip(dx * ux + dy * uy, -half, half)
    rx = dx - ux * along
    ry = dy - uy * along
    cap_r = rad + _TILE_DIAG_RADIUS
    cap_hit = (abs_dx < ex) & (abs_dy < ey) & (perp < perp_limit) & ((rx * rx + ry * ry) < (cap_r * cap_r))
    return np.where(half > 0.0, cap_hit, disc_hit)


def build_ground_tiles(
    world_width: float,
    world_height: float,
    lights: Sequence[MaterialLight],
    shapes: Sequence[float] = (),
    *,
    beams: bool = False,
) -> tuple[int, int, bytes]:
    """Return `(width, height, rgba8_masks)` with bit `i` set on tiles light `i` can reach."""
    count = min(len(lights), MAX_MATERIAL_LIGHTS)
    if not count or not (0.0 < world_width <= 65536.0 and 0.0 < world_height <= 65536.0):
        return 0, 0, b""
    width = math.ceil(world_width / TILE_SIZE)
    height = math.ceil(world_height / TILE_SIZE)
    if width * height > MAX_TILES:
        return 0, 0, b""
    np = _numpy()
    if np is None:
        return 0, 0, b""
    has_shapes = beams and len(shapes) >= count * 4

    # Collect active lights into small contiguous float32 arrays (N <= 32).
    indices: list[int] = []
    ring_idx: list[int] = []
    ring_data: list[tuple[float, float, float, float]] = []
    cap_idx: list[int] = []
    cap_data: list[tuple[float, float, float, float, float, float]] = []

    for i in range(count):
        light = lights[i]
        has_diff = light.illumination_gain > 0.0
        has_spec = light.reflection_gain > 0.0 and light.reflection_reach > 0.0
        if not has_diff and not has_spec:
            continue
        indices.append(i)
        cx = light.pos.x
        cy = light.pos.y
        ring = light.ring_radius
        diff_rad = max(1.0, light.radius) + _MARGIN if has_diff else 0.0
        spec_rad = max(0.01, light.reflection_reach) + _MARGIN if has_spec else 0.0
        if ring > 0.0:
            ring_idx.append(i)
            ring_data.append((cx, cy, ring, max(diff_rad, spec_rad)))
            continue
        dx = float(np.float32(light.direction.x))
        dy = float(np.float32(light.direction.y))
        square = float(np.float32(dx * dx + dy * dy))
        beam_half = shapes[4 * i + 3] if has_shapes else 0.0
        continuous = has_shapes and beam_half > 0.0 and has_diff
        # Near ground.frag's `dot(sp_dir.xy, sp_dir.xy) > 0.0001` cutoff, FMA or precision
        # differences could flip between `normalize(dir)` and the fallback axis; stay conservative.
        if 0.00009 <= square <= 0.00011:
            spec_half = max(0.0, light.length * 0.5)
            diff_half = max(beam_half, spec_half) if continuous else spec_half
            rad = max(diff_rad + diff_half if has_diff else 0.0, spec_rad + spec_half if has_spec else 0.0)
            cap_idx.append(i)
            cap_data.append((cx, cy, 1.0, 0.0, 0.0, rad))
            continue
        has_dir = square > 0.0001
        if has_dir:
            inv_len = 1.0 / math.sqrt(square)
            ux = dx * inv_len
            uy = dy * inv_len
        else:
            ux = 1.0
            uy = 0.0
        spec_half = max(0.0, light.length * 0.5) if has_dir else 0.0
        diff_half = beam_half if continuous else spec_half
        if has_diff and has_spec and diff_half == spec_half:
            cap_idx.append(i)
            cap_data.append((cx, cy, ux, uy, diff_half, max(diff_rad, spec_rad)))
        else:
            if has_diff:
                cap_idx.append(i)
                cap_data.append((cx, cy, ux, uy, diff_half, diff_rad))
            if has_spec:
                cap_idx.append(i)
                cap_data.append((cx, cy, ux, uy, spec_half, spec_rad))

    if not indices:
        return width, height, bytes(width * height * 4)

    mx, my = _tile_centers(np, width, height)
    bits = np.zeros((MAX_MATERIAL_LIGHTS, height, width), dtype=np.bool_)

    if cap_data:
        arr = np.asarray(cap_data, dtype=np.float32)
        hits = _capsule_hits(
            np,
            mx, my,
            arr[:, 0:1, None], arr[:, 1:2, None],
            arr[:, 2:3, None], arr[:, 3:4, None],
            arr[:, 4:5, None], arr[:, 5:6, None],
        )
        # Multiple entries can target the same light index when diffuse & specular halves differ.
        if len(cap_idx) == len(set(cap_idx)):
            bits[cap_idx] = hits
        else:
            for j, light_i in enumerate(cap_idx):
                bits[light_i] |= hits[j]

    if ring_data:
        arr = np.asarray(ring_data, dtype=np.float32)
        cx = arr[:, 0:1, None]
        cy = arr[:, 1:2, None]
        ring = arr[:, 2:3, None]
        rad = arr[:, 3:4, None]
        abs_dx = np.abs(mx - cx)
        abs_dy = np.abs(my - cy)
        bx = np.maximum(0.0, abs_dx - _HALF_TILE)
        by = np.maximum(0.0, abs_dy - _HALF_TILE)
        outer = ring + rad
        inner = ring - rad
        fx = abs_dx + _HALF_TILE
        fy = abs_dy + _HALF_TILE
        hits = ((bx * bx + by * by) < (outer * outer)) & ((inner <= 0.0) | ((fx * fx + fy * fy) > (inner * inner)))
        bits[ring_idx] = hits

    packed = np.packbits(bits, axis=0, bitorder="little")  # (4, H, W) uint8
    rgba = np.ascontiguousarray(packed.transpose(1, 2, 0))
    return width, height, rgba.tobytes()


class GroundLightTiles(msgspec.Struct):
    texture: rl.Texture | None = None

    def close(self) -> None:
        if self.texture is not None:
            rl.unload_texture(self.texture)
            self.texture = None

    def upload(self, width: int, height: int, masks: bytes) -> rl.Texture | None:
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
            self.texture = load_texture_with_reclaim(image)
            if self.texture.id <= 0:
                self.texture = None
                return None
            rl.set_texture_filter(self.texture, rl.TextureFilter.TEXTURE_FILTER_POINT)
            rl.set_texture_wrap(self.texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
        else:
            rl.update_texture(self.texture, rl.ffi.cast("void *", buf))
        return self.texture
