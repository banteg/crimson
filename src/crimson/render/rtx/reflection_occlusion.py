"""Rounded visible-body proxies shared by reflections and weapon illumination."""

from __future__ import annotations

import math
from collections.abc import Sequence

import msgspec

from grim.geom import Vec2
from grim.raylib_api import rl

from ...creatures.lifecycle import CREATURE_LIFECYCLE_ALIVE
from ...creatures.runtime import CreatureState
from ...creatures.spawn import CreatureTypeId
from .material_lights import MaterialLight

CELL_SIZE = 64.0
# A cell listing more bodies than this is a crowd: it holds their density and height instead of the list, and rays
# cross it as an absorbing medium (light_visibility.glsl), at a cost that no longer grows with the crowd. Packed
# bodies' shadows merge into one dark mass anyway; testing each one made dense swarms cost seconds per frame.
CROWD_BODIES = 16
TEXTURE_WIDTH = 256
# Local sprite coordinates (right, down), fractions of the drawn square size.
# Center x/y, planar radii x/y, and total height. Atlas bodies face right.
# Fitted to the central masses of the base frames; animated limbs and tails are
# deliberately absent, rather than making their whole sprite square opaque.
# One ellipse fitted to the combined planar bounds of the former body parts,
# retaining their maximum height. A single convex mass avoids forked shadows;
# it is a visual fit, not an enclosing hull of the animated sprite.
BODY_PROFILES = {
    CreatureTypeId.SPIDER_SP1: ((-.13, 0., .255, .09, .36),),
    CreatureTypeId.SPIDER_SP2: ((-.12, 0., .245, .12, .40),),
    CreatureTypeId.ALIEN: ((-.08, 0., .08, .13, .36),),
    CreatureTypeId.LIZARD: ((.105, 0., .115, .09, .32),),
    CreatureTypeId.ZOMBIE: ((-.0625, 0., .0975, .13, .46),),
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
    if not creature.active or creature.size <= 0 or creature.death_timer <= 0:
        return []
    # HP reaches zero before the drawn body finishes its death slide. Follow
    # that existing timer and current geometry, rather than dropping its shadow
    # on the killing hit or retaining a full-height ghost after corpse baking.
    remaining = min(1.0, creature.death_timer / CREATURE_LIFECYCLE_ALIVE)
    height_scale = remaining * remaining * (3.0 - 2.0 * remaining)
    fade = min(1.0, remaining * 4.0)
    opacity = min(1.0, max(0.0, creature.tint.a)) * fade * fade * (3.0 - 2.0 * fade)
    if opacity <= 0.0:
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
            height * creature.size * height_scale, angle, opacity, creature.pos,
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
    beam_references: int = 0


def build_occlusion_grid(
    bodies: Sequence[BodyVolume], lights: Sequence[MaterialLight], *, width: float, height: float,
    illumination: bool = True, beam_margin: float = 0.,
) -> OcclusionGrid:
    """Retain every relevant body; no priority cap or nearest-N popping.

    The grid covers the arena plus one cell outside it. Bodies further outside
    cannot intersect an in-arena receiver/source segment unless the source is
    outside too; extend the grid to include those selected source endpoints.

    Beam sections walk their own cell lists, padded by `beam_margin` (the
    largest section half-span) in world units near beam sources only. Other
    lights keep the transverse source-width margin.

    A list longer than CROWD_BODIES becomes a crowd header instead: the bodies
    centered in that cell as their summed footprint over the cell's area
    (opacity-weighted), negated, and their footprint-weighted top height.
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
        beam = beam_margin > 0 and illumination and light.beam_profile is not None and light.illumination_gain > 0
        supports.append((light.pos.x, light.pos.y, direction.x, direction.y, light.length * .5, reach + light.ring_radius, beam))
        axis = direction * (light.length * .5)
        extent = Vec2(abs(axis.x) + light.ring_radius, abs(axis.y) + light.ring_radius)
        for point in (light.pos - extent, light.pos + extent):
            lo = Vec2(min(lo.x, point.x - cell_size), min(lo.y, point.y - cell_size))
            hi = Vec2(max(hi.x, point.x + cell_size), max(hi.y, point.y + cell_size))
    origin = Vec2(math.floor(lo.x / cell_size) * cell_size, math.floor(lo.y / cell_size) * cell_size)
    columns = math.ceil((hi.x - origin.x) / cell_size)
    rows = math.ceil((hi.y - origin.y) / cell_size)

    def bounds(x: float, y: float, rx: float, ry: float) -> tuple[int, int, int, int]:
        return (
            max(0, math.floor((x - rx - origin.x) / cell_size)),
            min(columns - 1, math.floor((x + rx - origin.x) / cell_size)),
            max(0, math.floor((y - ry - origin.y) / cell_size)),
            min(rows - 1, math.floor((y + ry - origin.y) / cell_size)),
        )

    def covered(box: tuple[int, int, int, int], active: list[bool] | None = None) -> list[int]:
        x0, x1, y0, y1 = box
        cells = (row * columns + column for row in range(y0, y1 + 1) for column in range(x0, x1 + 1))
        return [cell for cell in cells if active is None or active[cell]]

    # Mark the conservative source-support rectangles once. Body-cell overlap
    # then culls against all sources together, avoiding bodies * sources work.
    active = [False] * (columns * rows)
    beam_active = [False] * (columns * rows)
    for x, y, ax, ay, half, reach, beam in supports:
        for cell in covered(bounds(x, y, abs(ax) * half + reach, abs(ay) * half + reach)):
            active[cell] = True
            beam_active[cell] |= beam
    cells: list[list[int]] = [[] for _ in range(columns * rows)]
    crowd_cover = [0.0] * (columns * rows)
    crowd_top = [0.0] * (columns * rows)
    beam_cells: list[list[tuple[int, int, int]]] = [[] for _ in range(columns * rows)]
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
        occupied = covered(bounds(body.pos.x, body.pos.y, rx, ry), active)
        # A section's rays fan out from the walked center ray by at most its half-span.
        beam_box = bounds(body.pos.x, body.pos.y, rx + beam_margin, ry + beam_margin)
        beam_occupied = covered(beam_box, beam_active)
        if not occupied and not beam_occupied:
            continue
        home_x = math.floor((body.pos.x - origin.x) / cell_size)
        home_y = math.floor((body.pos.y - origin.y) / cell_size)
        if 0 <= home_x < columns and 0 <= home_y < rows:
            footprint = math.pi * body.radii.x * body.radii.y * body.opacity / (cell_size * cell_size)
            crowd_cover[home_y * columns + home_x] += footprint
            crowd_top[home_y * columns + home_x] += body.height * footprint
        address = len(values) // 4
        body_count += 1
        values.extend((body.pos.x, body.pos.y, body.height * .4, radius + soft_margin))
        values.extend((1 / body.radii.x, 1 / body.radii.y, 1 / (body.height * .6), body.owner.x))
        values.extend((c, s, body.opacity, body.owner.y))
        for cell in occupied:
            cells[cell].append(address)
        # Beam entries carry their cell range, packed as first + last * 4096 per
        # axis, so a walk tests each body only in the first walked cell holding it.
        x0, x1, y0, y1 = beam_box
        for cell in beam_occupied:
            beam_cells[cell].append((address, x0 + x1 * 4096, y0 + y1 * 4096))
    # Headers: ordinary list offset and count, then the beam sections' list.
    for i, (cell, beam_cell) in enumerate(zip(cells, beam_cells, strict=True)):
        crowd = (crowd_top[i] / crowd_cover[i] if crowd_cover[i] > 0. else 0., -max(crowd_cover[i], 1e-6))
        if len(cell) > CROWD_BODIES:
            values[i * 4:i * 4 + 2] = crowd
        else:
            values[i * 4:i * 4 + 2] = (len(values) // 4, len(cell))
            for address in cell:
                values.extend((address, 0, 0, 0))
        if len(beam_cell) > CROWD_BODIES:
            values[i * 4 + 2:i * 4 + 4] = crowd
        else:
            values[i * 4 + 2:i * 4 + 4] = (len(values) // 4, len(beam_cell))
            for entry in beam_cell:
                values.extend((*entry, 0))
    references = sum(map(len, cells))
    beam_references = sum(map(len, beam_cells))
    return OcclusionGrid(origin, cell_size, columns, rows, values, body_count, references, beam_references)


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
