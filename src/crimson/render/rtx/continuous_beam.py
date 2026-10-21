"""Opt-in longitudinal emitter experiment; no simulation state or RNG consumption."""
from __future__ import annotations

import math
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from functools import lru_cache

import msgspec

from grim.geom import Vec2
from grim.raylib_api import rl

from .material_lights import MAX_MATERIAL_LIGHTS, MaterialLight
from .reflection_occlusion import BodyVolume, OcclusionGrid, ReflectionOcclusion

CELLS = 8
KNOTS = 33
SUPPORT = .85998995
TILE = 128.


class BeamExperiment(msgspec.Struct):
    enabled: bool = False
    ion_gain: float = 4.
    ambient_dip: float = .25


# Presentation-only developer control; intentionally not saved in replays/config.
experiment = BeamExperiment()


def configure(args: Sequence[str]) -> str:
    if not args:
        return f"Continuous beam: {experiment.enabled}; Ion gain {experiment.ion_gain:g}; ambient dip {experiment.ambient_dip:g}"
    if len(args) > 3 or args[0] not in ("on", "off"):
        raise ValueError("rtxbeam <on|off> [Ion gain 0..8] [local ambient dip 0..0.6]")
    gain = float(args[1]) if len(args) > 1 else experiment.ion_gain
    dip = float(args[2]) if len(args) > 2 else experiment.ambient_dip
    if not math.isfinite(gain) or not 0 <= gain <= 8 or not math.isfinite(dip) or not 0 <= dip <= .6:
        raise ValueError("Ion gain must be 0..8; local ambient dip must be 0..0.6")
    experiment.enabled, experiment.ion_gain, experiment.ambient_dip = args[0] == "on", gain, dip
    return configure(())


@contextmanager
def experiment_scope(*, enabled: bool) -> Iterator[None]:
    """Restore process presentation state after a standalone replay, including errors."""
    previous = (experiment.enabled, experiment.ion_gain, experiment.ambient_dip)
    experiment.enabled = enabled
    try:
        yield
    finally:
        experiment.enabled, experiment.ion_gain, experiment.ambient_dip = previous


@lru_cache(maxsize=1)
def radial_marginal() -> tuple[float, ...]:
    """Integrate the authored radial stamp across its width once, in double precision."""
    values = []
    steps = 256
    for i in range(513):
        x = SUPPORT * i / 512
        total = 0.
        for j in range(steps + 1):
            y = SUPPORT * j / steps
            radius = math.hypot(x, y)
            density = min(1., max(0., 1.3 * math.exp(-4.8 * radius - radius * radius) - .01))
            total += density * (.5 if j in (0, steps) else 1.)
        values.append(total * 2 * SUPPORT / steps)
    return tuple(values)


@lru_cache(maxsize=64)
def moments(length: float, radius: float, step: float, head_multiplier: float) -> tuple[tuple[float, ...], float]:
    """Transverse-marginal stamp-energy moments, locally rebased for precision.

    One narrow emitting core retains continuous longitudinal energy, rather than
    treating the whole visible halo as an area emitter. This is the research
    model, not a physically calibrated power distribution. Cache is bounded.
    """
    pad = radius * head_multiplier * SUPPORT
    span = length + 2 * pad
    stamps = [(i * step, i * step / length) for i in range(math.ceil(length / step))] if length > 0 else []
    stamps.append((length, 1.))
    values: list[float] = []
    radial = radial_marginal()
    total = 0.
    for cell in range(CELLS):
        acc = [0., 0., 0.]
        previous = [0., 0., 0.]
        for knot in range(257):
            u = knot / 256
            x = -pad + (cell + u) * span / CELLS
            energy = 0.
            for j, (position, weight) in enumerate(stamps):
                stamp_radius = radius * head_multiplier if j == len(stamps) - 1 else radius
                r = abs(x - position) / stamp_radius
                if r < SUPPORT:
                    index = r / SUPPORT * 512
                    low = min(511, int(index))
                    density = radial[low] + (radial[low + 1] - radial[low]) * (index - low)
                    energy += weight * stamp_radius * density
            current = [energy, energy * u, energy * u * u]
            if knot:
                for n in range(3):
                    acc[n] += (previous[n] + current[n]) * .5 / 256
            if knot % 8 == 0:
                values.extend((*acc, 0.))
            previous = current
        total += acc[0]
    return tuple(v / total for v in values), pad


def projected_bounds(body: BodyVolume, light: MaterialLight, pad: float) -> tuple[float, float, float, float]:
    """Conservative ground projection of an ellipsoid from every point of a line.

    An emitter at/below the body's top can cast an unbounded shadow. Keep it in
    all source-support tiles instead of dividing by a near-zero height ratio.
    """
    z, rz = body.height * .4, body.height * .6
    d = light.height - z
    denom = d * d - rz * rz
    if d <= rz or denom <= 1e-8:
        return (-math.inf, -math.inf, math.inf, math.inf)
    c, s = math.cos(body.angle), math.sin(body.angle)
    variance = ((c * body.radii.x) ** 2 + (s * body.radii.y) ** 2,
                (s * body.radii.x) ** 2 + (c * body.radii.y) ** 2)
    axis = light.direction.normalized() if light.direction.length_sq() > .0001 else Vec2(1, 0)
    ends = (light.pos - axis * (light.length * .5 + pad), light.pos + axis * (light.length * .5 + pad))
    k, e, zz = light.height * d / denom, light.height / math.sqrt(denom), rz * rz / denom
    lows, highs = [], []
    for coordinate, variance_axis in zip((0, 1), variance, strict=True):
        b = body.pos.x if coordinate == 0 else body.pos.y
        bounds = []
        for endpoint in ends:
            source = endpoint.x if coordinate == 0 else endpoint.y
            center = source + k * (b - source)
            extent = e * math.sqrt(variance_axis + (b - source) ** 2 * zz)
            bounds.append((center - extent, center + extent))
        lows.append(min(v[0] for v in bounds) - .01)
        highs.append(max(v[1] for v in bounds) + .01)
    return (*lows, *highs)


def pack_candidates(bodies: Sequence[BodyVolume], lights: Sequence[MaterialLight], *, width: float, height: float) -> OcclusionGrid:
    columns, rows = math.ceil(width / TILE), math.ceil(height / TILE)
    headers = len(lights) * columns * rows
    values = [0.] * (headers * 4)
    cells: list[list[int]] = [[] for _ in range(headers)]
    retained = 0
    for body in bodies:
        if body.opacity <= 0 or min(body.radii.x, body.radii.y, body.height) <= 0:
            continue
        address = len(values) // 4
        values.extend((body.pos.x, body.pos.y, body.height * .4, 0.,
                       1 / body.radii.x, 1 / body.radii.y, 1 / (body.height * .6), 0.,
                       math.cos(body.angle), math.sin(body.angle), body.opacity, 0.))
        retained += 1
        for i, light in enumerate(lights):
            if light.beam_profile is None or light.illumination_gain <= 0:
                continue
            radius, _, head = light.beam_profile
            pad = radius * head * SUPPORT
            axis = light.direction.normalized() if light.direction.length_sq() > .0001 else Vec2(1, 0)
            reach_x = abs(axis.x) * (light.length * .5 + pad) + light.radius
            reach_y = abs(axis.y) * (light.length * .5 + pad) + light.radius
            x0, y0, x1, y1 = projected_bounds(body, light, pad)
            x0, y0 = max(x0, light.pos.x - reach_x, 0.), max(y0, light.pos.y - reach_y, 0.)
            x1, y1 = min(x1, light.pos.x + reach_x, width), min(y1, light.pos.y + reach_y, height)
            if x1 < x0 or y1 < y0:
                continue
            for row in range(max(0, math.floor(y0 / TILE)), min(rows - 1, math.floor(y1 / TILE)) + 1):
                for col in range(max(0, math.floor(x0 / TILE)), min(columns - 1, math.floor(x1 / TILE)) + 1):
                    cells[i * rows * columns + row * columns + col].append(address)
    references = 0
    for i, cell in enumerate(cells):
        values[4 * i:4 * i + 2] = (len(values) // 4, len(cell))
        for address in cell:
            values.extend((address, 0., 0., 0.))
        references += len(cell)
    return OcclusionGrid(Vec2(), TILE, columns, rows, values, retained, references)


class ContinuousBeam(msgspec.Struct):
    candidates: ReflectionOcclusion = msgspec.field(default_factory=ReflectionOcclusion)
    moment_texture: rl.Texture | None = None
    moment_key: tuple = ()

    def close(self) -> None:
        self.candidates.close()
        if self.moment_texture is not None:
            rl.unload_texture(self.moment_texture)
            self.moment_texture = None
        self.moment_key = ()

    def prepare(self, bodies: Sequence[BodyVolume], lights: Sequence[MaterialLight], *, width: float, height: float) -> list[tuple[float, float, float, float]]:
        assert len(lights) <= MAX_MATERIAL_LIGHTS
        # Eligibility is part of the key: selection may retain a source for
        # reflections while moving its illumination slot to another projectile.
        key = tuple(
            (light.length, light.beam_profile)
            if light.beam_profile is not None and light.illumination_gain > 0 else None
            for light in lights
        ) + (None,) * (MAX_MATERIAL_LIGHTS - len(lights))
        infos = []
        for light, row in zip(lights, key, strict=False):
            if row is None:
                infos.append((0., 0., 0., 0.))
            else:
                length, profile = row
                pad = profile[0] * profile[2] * SUPPORT
                infos.append((pad, length + 2 * pad, float(light.beam_ion), 1.))
        if key != self.moment_key or self.moment_texture is None:
            data = []
            for row in key:
                data.extend(moments(row[0], *row[1])[0] if row is not None else [0.] * (CELLS * KNOTS * 4))
            raw = rl.ffi.new("float[]", data)
            if self.moment_texture is None:
                image = rl.Image(rl.ffi.cast("void *", raw), CELLS * KNOTS, MAX_MATERIAL_LIGHTS, 1,
                                 rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
                self.moment_texture = rl.load_texture_from_image(image)
                if self.moment_texture.id <= 0:
                    self.moment_texture = None
                    raise RuntimeError("Could not upload continuous beam moments")
                rl.set_texture_filter(self.moment_texture, rl.TextureFilter.TEXTURE_FILTER_POINT)
            else:
                rl.update_texture(self.moment_texture, raw)
            self.moment_key = key
        grid = pack_candidates(bodies, lights, width=width, height=height)
        self.candidates.upload(grid)
        return infos
