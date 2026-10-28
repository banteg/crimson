"""Presentation-only, a growing, open 2D fluid domain driven by native smoke emissions.

Velocity is planar. Temperature controls the renderer's assumed vertical slab,
not simulated vertical momentum. The pressure solve is a graphics approximation.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

import numpy as np
from numpy.typing import NDArray

from grim.geom import Vec2

from .smoke_constants import FADE_SECONDS, SOURCE_HEAT, STEP_SECONDS

if TYPE_CHECKING:
    from ...sim.smoke_events import SmokeEmission

GRID_SIZE = 144
CELL_SIZE = 2.0
FIELD_SIZE = GRID_SIZE * CELL_SIZE
MAX_GRID_SIZE = 640
DOMAIN_PADDING = 96.0
GROWTH_CELLS = 32
MAX_IDLE_SECONDS = 10.0
FloatGrid = NDArray[np.float32]


class SmokeField:
    def __init__(self, origin: Vec2, identity: int) -> None:
        self.origin = origin
        self.identity = identity
        self.density: FloatGrid = np.zeros((GRID_SIZE, GRID_SIZE), dtype=np.float32)
        self.temperature = self.density.copy()
        self.u = self.density.copy()
        self.v = self.density.copy()
        self.idle_seconds = 0.0
        self.retention_seconds = MAX_IDLE_SECONDS
        self.density_decay = .20
        self.accumulator = 0.0
        self.version = 0
        self._coordinates()

    @property
    def fade(self) -> float:
        return min(1.0, max(0.0, (self.retention_seconds - self.idle_seconds) / FADE_SECONDS))

    def _coordinates(self) -> None:
        self.y, self.x = np.mgrid[:self.density.shape[0], :self.density.shape[1]].astype(np.float32)

    @property
    def size(self) -> Vec2:
        return Vec2(self.density.shape[1] * CELL_SIZE, self.density.shape[0] * CELL_SIZE)

    def _trim_empty(self) -> None:
        """Reclaim negligible outer air before a capped domain follows combat."""
        ys, xs = np.nonzero((self.density > .0001) | (self.temperature > .0001))
        if not len(xs):
            return
        h, w = self.density.shape
        left, top = max(0, int(xs.min()) - 32), max(0, int(ys.min()) - 32)
        right, bottom = min(w, int(xs.max()) + 33), min(h, int(ys.max()) + 33)
        right, bottom = min(w, max(right, left + GRID_SIZE)), min(h, max(bottom, top + GRID_SIZE))
        left, top = min(left, right - GRID_SIZE), min(top, bottom - GRID_SIZE)
        if left or top or right < w or bottom < h:
            for name in ("density", "temperature", "u", "v"):
                setattr(self, name, getattr(self, name)[top:bottom, left:right].copy())
            self.origin += Vec2(left * CELL_SIZE, top * CELL_SIZE)
            self._coordinates()
            self.version += 1

    def include(self, pos: Vec2, margin: float) -> bool:
        """Grow on the world lattice. Capacity limits padding, not valid deposits."""
        def growth() -> tuple[int, int, int, int]:
            def cells(distance: float) -> int:
                return max(0, math.ceil(distance / CELL_SIZE / GROWTH_CELLS)) * GROWTH_CELLS
            return (cells(self.origin.x + margin - pos.x), cells(self.origin.y + margin - pos.y),
                    cells(pos.x + margin - self.origin.x - self.size.x),
                    cells(pos.y + margin - self.origin.y - self.size.y))

        left, top, right, bottom = growth()
        if self.density.shape[1] + left + right > MAX_GRID_SIZE or self.density.shape[0] + top + bottom > MAX_GRID_SIZE:
            self._trim_empty()
            left, top, right, bottom = growth()
        spare_x, spare_y = MAX_GRID_SIZE - self.density.shape[1], MAX_GRID_SIZE - self.density.shape[0]
        left, top = min(left, spare_x), min(top, spare_y)
        right, bottom = min(right, spare_x - left), min(bottom, spare_y - top)
        if left or top or right or bottom:
            for name in ("density", "temperature", "u", "v"):
                setattr(self, name, np.pad(getattr(self, name), ((top, bottom), (left, right))))
            self.origin -= Vec2(left * CELL_SIZE, top * CELL_SIZE)
            self._coordinates()
            self.version += 1
        return (self.origin.x <= pos.x < self.origin.x + self.size.x
                and self.origin.y <= pos.y < self.origin.y + self.size.y)

    def _grow_for_flow(self) -> None:
        # Include advected smoke before it reaches the artificial domain edge.
        ys, xs = np.nonzero(self.density > .015)
        if len(xs):
            lo = self.origin + Vec2(float(xs.min()), float(ys.min())) * CELL_SIZE
            hi = self.origin + Vec2(float(xs.max()), float(ys.max())) * CELL_SIZE
            self.include(lo, DOMAIN_PADDING)
            self.include(hi, DOMAIN_PADDING)

    def inject(self, emission: SmokeEmission) -> None:
        # Preserve the displayed amount of old smoke when a fresh source extends
        # this shared patch's lifetime. Resetting only the age would resurrect it.
        fade = self.fade
        self.density *= fade
        self.temperature *= fade
        self.retention_seconds = max(
            self.retention_seconds - self.idle_seconds,
            min(15.0, max(FADE_SECONDS, emission.retention_seconds)),
        )
        size = max(emission.scale, emission.expansion * 2.0 * STEP_SECONDS)
        speed = emission.vel.length()
        direction = emission.vel / speed if speed > 1e-5 else Vec2()
        center = (emission.pos + direction * (size * .35) - self.origin) / CELL_SIZE
        sigma = max(2.0, size * .5 / CELL_SIZE)
        source = np.exp(-((self.x - center.x) ** 2 + (self.y - center.y) ** 2) / (2 * sigma * sigma))
        strength = emission.color.a
        if emission.source == "effect":
            # Large native explosion puffs use a dark (.1) tint, unlike the
            # white SpriteEffect smoke. Mapping their alpha alone into our gray
            # scattering medium makes their much larger area dominate all wisps.
            # This tonal weight is an artistic source conversion, not mass units.
            tint = emission.color.r * .2126 + emission.color.g * .7152 + emission.color.b * .0722
            strength *= min(1.0, max(0.0, tint))
        if emission.profile == "nuke":
            strength *= 8.0
            # A shared patch retains the slower dissipation after a nuke deposit.
            # Existing mass is never increased by changing the decay rate.
            self.density_decay = .12
        if emission.profile == "nuke":
            # Several overlapping billows, not a single smooth Gaussian disc.
            # Rotation comes from the native event; no gameplay RNG is consumed.
            source = source * .3
            for i in range(7):
                angle = emission.rotation + i * math.tau / 7 + .18 * math.sin(i * 2.4)
                radius = size * (.42 + .10 * math.sin(i * 1.7 + emission.rotation)) / CELL_SIZE
                cx, cy = center.x + math.cos(angle) * radius, center.y + math.sin(angle) * radius
                lobe = np.exp(-((self.x - cx) ** 2 + (self.y - cy) ** 2) / (2 * (sigma * .85) ** 2))
                source += lobe * .25
                turn = 5.0 * math.sin(i * 2.1 + emission.rotation)
                self.u -= lobe * (self.y - cy) / sigma * turn
                self.v += lobe * (self.x - cx) / sigma * turn
            wx, wy = self.x + self.origin.x / CELL_SIZE, self.y + self.origin.y / CELL_SIZE
            source *= .75 + .125 * (np.sin(wx * .27 + wy * .14) + np.sin(wx * .11 - wy * .23))
        self.density += source * strength * 1.7
        self.temperature += source * strength * 2.0 * SOURCE_HEAT[emission.profile]
        self.u += source * emission.vel.x * .22
        self.v += source * emission.vel.y * .22
        if emission.expansion > 0.0:
            expansion = 2.0 * emission.expansion / max(size, .001) * .44
            self.u += source * (self.x - center.x) * expansion
            self.v += source * (self.y - center.y) * expansion
        self.idle_seconds = 0.0
        self.version += 1

    def _donors(self, u: FloatGrid, v: FloatGrid, dt: float) -> tuple[NDArray[np.int32], NDArray[np.int32], FloatGrid, FloatGrid]:
        x = np.clip(self.x - dt * u, 0.0, self.density.shape[1] - 1.001)
        y = np.clip(self.y - dt * v, 0.0, self.density.shape[0] - 1.001)
        ix, iy = x.astype(np.int32), y.astype(np.int32)
        return ix, iy, x - ix.astype(np.float32), y - iy.astype(np.float32)

    def _advect(self, q: FloatGrid, u: FloatGrid, v: FloatGrid, dt: float) -> FloatGrid:
        ix, iy, fx, fy = self._donors(u, v, dt)
        inside = ((self.x - dt * u >= 0) & (self.x - dt * u <= q.shape[1] - 1)
                  & (self.y - dt * v >= 0) & (self.y - dt * v <= q.shape[0] - 1))
        return inside * (
            (q[iy, ix] * (1 - fx) + q[iy, ix + 1] * fx) * (1 - fy)
            + (q[iy + 1, ix] * (1 - fx) + q[iy + 1, ix + 1] * fx) * fy
        )

    def _scalar(self, q: FloatGrid, u: FloatGrid, v: FloatGrid, dt: float) -> FloatGrid:
        forward = self._advect(q, u, v, dt)
        backward = self._advect(forward, u, v, -dt)
        ix, iy, _, _ = self._donors(u, v, dt)
        donors = (q[iy, ix], q[iy + 1, ix], q[iy, ix + 1], q[iy + 1, ix + 1])
        corrected = np.clip(forward + .5 * (q - backward), np.minimum.reduce(donors), np.maximum.reduce(donors))
        safe = ((self.x - np.abs(dt * u) >= 2) & (self.x + np.abs(dt * u) < q.shape[1] - 2)
                & (self.y - np.abs(dt * v) >= 2) & (self.y + np.abs(dt * v) < q.shape[0] - 2))
        return np.where(safe, corrected, forward)

    def advance(self, dt: float) -> None:
        self._grow_for_flow()
        self.idle_seconds += dt
        self.accumulator += dt
        while self.accumulator + 1e-9 >= STEP_SECONDS:
            self._step(STEP_SECONDS)
            self.accumulator = max(0.0, self.accumulator - STEP_SECONDS)

    def _step(self, dt: float) -> None:
        self.u += dt * (1.0 - self.u) * .025
        self.v += dt * (-.3 - self.v) * .025
        u = self._advect(self.u, self.u, self.v, dt)
        v = self._advect(self.v, self.u, self.v, dt)
        curl = np.gradient(v, axis=1) - np.gradient(u, axis=0)
        magnitude = np.abs(curl)
        gx = np.gradient(magnitude, axis=1)
        gy = np.gradient(magnitude, axis=0)
        norm = np.sqrt(gx * gx + gy * gy) + 1e-5
        u += dt * 3.0 * gy / norm * curl
        v -= dt * 3.0 * gx / norm * curl
        # Matched backward divergence / forward pressure gradient gives the
        # same one-cell Laplacian as Jacobi, avoiding odd/even pressure modes.
        divergence = np.zeros_like(u)
        divergence[:, 1:] = u[:, 1:] - u[:, :-1]
        divergence[1:, :] += v[1:, :] - v[:-1, :]
        pressure = np.zeros_like(divergence)
        for _ in range(24):
            pressure[1:-1, 1:-1] = (
                pressure[1:-1, 2:] + pressure[1:-1, :-2] + pressure[2:, 1:-1] + pressure[:-2, 1:-1]
                - divergence[1:-1, 1:-1]
            ) * .25
        u[:, :-1] -= pressure[:, 1:] - pressure[:, :-1]
        v[:-1, :] -= pressure[1:, :] - pressure[:-1, :]
        # Thermal expansion represents the unresolved vertical plume spreading
        # in projection. Apply after incompressible planar projection.
        thermal = 4.0 * np.tanh(self.temperature / 4.0)
        tx = np.gradient(thermal, axis=1)
        ty = np.gradient(thermal, axis=0)
        self.density_decay += dt * (.20 - self.density_decay) * .07
        u -= dt * 18.0 * tx
        v -= dt * 18.0 * ty
        self.density = self._scalar(self.density, u, v, dt) * math.exp(-dt * self.density_decay)
        self.temperature = self._scalar(self.temperature, u, v, dt) * math.exp(-dt * .70)
        self.u = u * math.exp(-dt * .12)
        self.v = v * math.exp(-dt * .12)
        # Open boundaries: transported material can leave; never zero normal
        # velocity or clamp donors into a reflecting wall. Outer cells absorb
        # residual mass only if the maximum domain allocation has been reached.
        edge_distance = np.minimum.reduce((self.x, self.y,
            self.density.shape[1] - 1 - self.x, self.density.shape[0] - 1 - self.y))
        absorber = np.exp(-dt * 3.0 * np.clip(1.0 - edge_distance / 16.0, 0.0, 1.0) ** 2)
        # Art-directed unresolved planar mixing: 32 world units squared/second.
        for field in (self.density, self.temperature):
            padded = np.pad(field, 1)
            laplacian = (padded[2:, 1:-1] + padded[:-2, 1:-1]
                         + padded[1:-1, 2:] + padded[1:-1, :-2] - 4 * field)
            field += 8 * dt * laplacian
            field *= absorber
            field[0] = field[-1] = 0.0
            field[:, 0] = field[:, -1] = 0.0
        self.version += 1


class SmokeSimulation:
    def __init__(self) -> None:
        self.fields: dict[int, SmokeField] = {}
        self._next_identity = 0

    def reset(self) -> None:
        self.fields.clear()

    def consume(self, emissions: tuple[SmokeEmission, ...], dt_sim: float) -> None:
        if not math.isfinite(dt_sim) or dt_sim < 0.0:
            raise ValueError("smoke presentation delta must be finite and nonnegative")
        ready = [emission for emission in emissions if emission.color.a > 0.0 and all(math.isfinite(v) for v in (
            emission.pos.x, emission.pos.y, emission.vel.x, emission.vel.y, emission.scale,
            emission.color.r, emission.color.g, emission.color.b, emission.color.a,
            emission.expansion, emission.retention_seconds,
        ))]
        for emission in ready:
            size = max(emission.scale, emission.expansion * 2.0 * STEP_SECONDS)
            if size <= 0.0:
                continue
            margin = max(DOMAIN_PADDING, size * 2.5)
            if margin * 2 > MAX_GRID_SIZE * CELL_SIZE:
                continue
            field = self.fields.get(0)
            if field is None:
                origin = Vec2(
                    math.floor(emission.pos.x / CELL_SIZE) * CELL_SIZE - FIELD_SIZE / 2,
                    math.floor(emission.pos.y / CELL_SIZE) * CELL_SIZE - FIELD_SIZE / 2,
                )
                field = SmokeField(origin, self._next_identity)
                self._next_identity += 1
                if not field.include(emission.pos, margin):
                    continue
                self.fields[0] = field
            elif not field.include(emission.pos, margin):
                # Bounded presentation allocation: omit outlying deposits;
                # never bring back native smoke or evict the visible plume.
                continue
            field.inject(emission)
        if dt_sim <= 0.0:
            return
        for slot, field in tuple(self.fields.items()):
            field.advance(dt_sim)
            if field.fade <= 0.0 or (field.idle_seconds > .5 and float(field.density.max()) < .001):
                del self.fields[slot]
