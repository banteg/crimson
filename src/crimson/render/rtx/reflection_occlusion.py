"""Rounded living-body proxies shared by reflections and weapon illumination."""

from __future__ import annotations

import math
from collections.abc import Sequence

import msgspec

from grim.geom import Vec2
from grim.raylib_api import rl

from ...creatures.runtime import CreatureState
from ...creatures.spawn import CreatureTypeId
from .material_lights import MaterialLight

CELL_SIZE = 64.0
TEXTURE_WIDTH = 256
# Local sprite coordinates (right, down), fractions of the drawn square size.
# Center x/y, planar radii x/y, and total height. Atlas bodies face right.
# Fitted to the central masses of the base frames; animated limbs and tails are
# deliberately absent, rather than making their whole sprite square opaque.
BODY_PROFILES = {
    CreatureTypeId.SPIDER_SP1: ((-.225, 0., .16, .09, .36), (-.005, 0., .13, .055, .28)),
    CreatureTypeId.SPIDER_SP2: ((-.225, 0., .14, .12, .40), (-.005, 0., .13, .055, .28)),
    CreatureTypeId.ALIEN: ((-.065, 0., .065, .13, .36), (-.11, 0., .05, .06, .30)),
    CreatureTypeId.LIZARD: ((.07, 0., .08, .09, .32), (.15, -.015, .07, .055, .30)),
    CreatureTypeId.ZOMBIE: ((-.11, 0., .05, .13, .40), (-.035, 0., .07, .065, .46)),
}


class BodyVolume(msgspec.Struct, frozen=True):
    pos: Vec2
    radii: Vec2
    height: float
    angle: float
    opacity: float = 1.0
    # Unowned volumes never match a recoverable sprite center.
    owner: Vec2 = Vec2(1e20, 1e20)


def creature_body_volumes(creature: CreatureState) -> list[BodyVolume]:
    if not creature.active or creature.hp <= 0 or creature.size <= 0:
        return []
    profile = BODY_PROFILES.get(creature.type_id)
    if profile is None:
        return []
    angle = creature.heading - math.pi / 2
    right = Vec2(math.cos(angle), math.sin(angle))
    down = Vec2(-right.y, right.x)
    return [
        BodyVolume(
            creature.pos + (right * x + down * y) * creature.size,
            Vec2(rx * creature.size, ry * creature.size),
            height * creature.size, angle, min(1.0, max(0.0, creature.tint.a)), creature.pos,
        )
        for x, y, rx, ry, height in profile
    ]


class OcclusionGrid(msgspec.Struct, frozen=True):
    origin: Vec2
    cell_size: float
    columns: int
    rows: int
    values: list[float]
    body_count: int
    references: int


def build_occlusion_grid(
    bodies: Sequence[BodyVolume], lights: Sequence[MaterialLight], *, width: float, height: float,
    illumination: bool = True,
) -> OcclusionGrid:
    """Retain every relevant body; no priority cap or nearest-N popping.

    The grid covers the arena plus one cell outside it. Bodies further outside
    cannot intersect an in-arena receiver/source segment unless the source is
    outside too; extend the grid to include those selected source endpoints.
    """
    sources = [light for light in lights if light.reflection_gain > 0 or (illumination and light.illumination_gain > 0)]
    if not sources:
        return OcclusionGrid(Vec2(), CELL_SIZE, 0, 0, [], 0, 0)
    # Fine cells reduce candidate fetches in dense crowds. Small scenes retain
    # cheaper CPU construction. Both grids retain the same volumes/visibility.
    cell_size = CELL_SIZE * .5 if len(bodies) >= 512 else CELL_SIZE
    padding = max((max(.1, light.source_width) for light in sources), default=0.0)
    lo = Vec2(-cell_size, -cell_size)
    hi = Vec2(width + cell_size, height + cell_size)
    supports = []
    for light in sources:
        direction = light.direction.normalized() if light.direction.length_sq() > .0001 else Vec2()
        reach = max(
            light.reflection_reach if light.reflection_gain > 0 else 0.,
            light.radius if illumination and light.illumination_gain > 0 else 0.,
        )
        supports.append((light.pos.x, light.pos.y, direction.x, direction.y, light.length * .5, reach))
        axis = direction * (light.length * .5)
        for point in (light.pos - axis, light.pos + axis):
            lo = Vec2(min(lo.x, point.x - cell_size), min(lo.y, point.y - cell_size))
            hi = Vec2(max(hi.x, point.x + cell_size), max(hi.y, point.y + cell_size))
    origin = Vec2(math.floor(lo.x / cell_size) * cell_size, math.floor(lo.y / cell_size) * cell_size)
    columns = math.ceil((hi.x - origin.x) / cell_size)
    rows = math.ceil((hi.y - origin.y) / cell_size)
    # Mark the conservative source-support rectangles once. Body-cell overlap
    # then culls against all sources together, avoiding bodies * sources work.
    active = [False] * (columns * rows)
    for x, y, ax, ay, half, reach in supports:
        rx, ry = abs(ax) * half + reach, abs(ay) * half + reach
        x0 = max(0, math.floor((x - rx - origin.x) / cell_size))
        x1 = min(columns - 1, math.floor((x + rx - origin.x) / cell_size))
        y0 = max(0, math.floor((y - ry - origin.y) / cell_size))
        y1 = min(rows - 1, math.floor((y + ry - origin.y) / cell_size))
        for row in range(y0, y1 + 1):
            active[row * columns + x0:row * columns + x1 + 1] = [True] * (x1 - x0 + 1)
    cells: list[list[int]] = [[] for _ in range(columns * rows)]
    values = [0.0] * (columns * rows * 4)
    body_count = 0
    for body in bodies:
        if body.opacity <= 0:
            continue
        c, s = math.cos(body.angle), math.sin(body.angle)
        radius = max(body.radii.x, body.radii.y)
        soft_margin = max(.015 * radius, padding * radius / min(body.radii.x, body.radii.y))
        rx = math.hypot(c * body.radii.x, s * body.radii.y) + soft_margin
        ry = math.hypot(s * body.radii.x, c * body.radii.y) + soft_margin
        x0 = max(0, math.floor((body.pos.x - rx - origin.x) / cell_size))
        x1 = min(columns - 1, math.floor((body.pos.x + rx - origin.x) / cell_size))
        y0 = max(0, math.floor((body.pos.y - ry - origin.y) / cell_size))
        y1 = min(rows - 1, math.floor((body.pos.y + ry - origin.y) / cell_size))
        occupied = [
            y * columns + x for y in range(y0, y1 + 1) for x in range(x0, x1 + 1) if active[y * columns + x]
        ]
        if not occupied:
            continue
        address = len(values) // 4
        body_count += 1
        values.extend((body.pos.x, body.pos.y, body.height * .4, radius + soft_margin))
        values.extend((1 / body.radii.x, 1 / body.radii.y, 1 / (body.height * .6), body.owner.x))
        values.extend((c, s, body.opacity, body.owner.y))
        for cell in occupied:
            cells[cell].append(address)
    references = 0
    for i, cell in enumerate(cells):
        values[i * 4:i * 4 + 2] = (len(values) // 4, len(cell))
        for address in cell:
            values.extend((address, 0, 0, 0))
        references += len(cell)
    return OcclusionGrid(origin, cell_size, columns, rows, values, body_count, references)


class ReflectionOcclusion(msgspec.Struct):
    texture: rl.Texture | None = None
    grid: OcclusionGrid | None = None

    def close(self) -> None:
        self.grid = None
        if self.texture is not None:
            rl.unload_texture(self.texture)
            self.texture = None

    def upload(self, grid: OcclusionGrid) -> rl.Texture:
        height = max(1, math.ceil(len(grid.values) / (TEXTURE_WIDTH * 4)))
        # Grow in powers of two, so swarm fluctuations do not reallocate every frame.
        height = 1 << (height - 1).bit_length()
        if self.texture is not None and self.texture.height < height:
            self.close()
        if self.texture is not None:
            height = self.texture.height
        data = rl.ffi.new("float[]", grid.values + [0.] * (TEXTURE_WIDTH * height * 4 - len(grid.values)))
        if self.texture is None:
            image = rl.Image(rl.ffi.cast("void *", data), TEXTURE_WIDTH, height, 1,
                             rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
            self.texture = rl.load_texture_from_image(image)
            if self.texture.id <= 0:
                self.texture = None
                raise RuntimeError("Could not upload reflection occlusion grid")
            rl.set_texture_filter(self.texture, rl.TextureFilter.TEXTURE_FILTER_POINT)
        else:
            rl.update_texture(self.texture, data)
        self.grid = grid
        return self.texture
