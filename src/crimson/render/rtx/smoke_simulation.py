"""Presentation-only, bounded 2D fluid fields driven by native smoke emissions.

Velocity is planar. Temperature controls the renderer's assumed vertical slab,
not simulated vertical momentum. The pressure solve is a graphics approximation.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

import numpy as np
from numpy.typing import NDArray

from grim.geom import Vec2

from ...math_parity import f32

if TYPE_CHECKING:
    from ...sim.smoke_events import SmokeEmission

GRID_SIZE = 144
CELL_SIZE = 2.0
FIELD_SIZE = GRID_SIZE * CELL_SIZE
MAX_FIELDS = 4
MAX_PENDING_EMISSIONS = 1024
STEP_SECONDS = 1.0 / 60.0
MAX_IDLE_SECONDS = 10.0
FADE_SECONDS = 2.0
_Y, _X = np.mgrid[:GRID_SIZE, :GRID_SIZE].astype(np.float32)
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

    @property
    def fade(self) -> float:
        return min(1.0, max(0.0, (self.retention_seconds - self.idle_seconds) / FADE_SECONDS))

    def accepts(self, pos: Vec2, margin: float = 24.0) -> bool:
        return (
            self.origin.x + margin <= pos.x <= self.origin.x + FIELD_SIZE - margin
            and self.origin.y + margin <= pos.y <= self.origin.y + FIELD_SIZE - margin
        )

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
        source = np.exp(-((_X - center.x) ** 2 + (_Y - center.y) ** 2) / (2 * sigma * sigma))
        strength = emission.color.a
        if emission.source == "effect":
            # Large native explosion puffs use a dark (.1) tint, unlike the
            # white SpriteEffect smoke. Mapping their alpha alone into our gray
            # scattering medium makes their much larger area dominate all wisps.
            # This tonal weight is an artistic source conversion, not mass units.
            tint = emission.color.r * .2126 + emission.color.g * .7152 + emission.color.b * .0722
            strength *= min(1.0, max(0.0, tint))
        if emission.profile == "nuke":
            strength *= 3.0
            # A shared patch retains the slower dissipation after a nuke deposit.
            # Existing mass is never increased by changing the decay rate.
            self.density_decay = .12
        self.density += source * strength * 1.7
        self.temperature += source * strength * 2.0
        self.u += source * emission.vel.x * .22
        self.v += source * emission.vel.y * .22
        if emission.expansion > 0.0:
            expansion = 2.0 * emission.expansion / max(size, .001) * .44
            self.u += source * (_X - center.x) * expansion
            self.v += source * (_Y - center.y) * expansion
        self.idle_seconds = 0.0
        self.version += 1

    @staticmethod
    def _donors(u: FloatGrid, v: FloatGrid, dt: float) -> tuple[NDArray[np.int32], NDArray[np.int32], FloatGrid, FloatGrid]:
        x = np.clip(_X - dt * u, 0.0, GRID_SIZE - 1.001)
        y = np.clip(_Y - dt * v, 0.0, GRID_SIZE - 1.001)
        ix, iy = x.astype(np.int32), y.astype(np.int32)
        return ix, iy, x - ix.astype(np.float32), y - iy.astype(np.float32)

    @classmethod
    def _advect(cls, q: FloatGrid, u: FloatGrid, v: FloatGrid, dt: float) -> FloatGrid:
        ix, iy, fx, fy = cls._donors(u, v, dt)
        return (
            (q[iy, ix] * (1 - fx) + q[iy, ix + 1] * fx) * (1 - fy)
            + (q[iy + 1, ix] * (1 - fx) + q[iy + 1, ix + 1] * fx) * fy
        )

    @classmethod
    def _scalar(cls, q: FloatGrid, u: FloatGrid, v: FloatGrid, dt: float) -> FloatGrid:
        forward = cls._advect(q, u, v, dt)
        backward = cls._advect(forward, u, v, -dt)
        ix, iy, _, _ = cls._donors(u, v, dt)
        donors = (q[iy, ix], q[iy + 1, ix], q[iy, ix + 1], q[iy + 1, ix + 1])
        return np.clip(forward + .5 * (q - backward), np.minimum.reduce(donors), np.maximum.reduce(donors))

    def advance(self, dt: float) -> None:
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
        curl = (np.roll(v, -1, 1) - np.roll(v, 1, 1) - np.roll(u, -1, 0) + np.roll(u, 1, 0)) * .5
        magnitude = np.abs(curl)
        gx = (np.roll(magnitude, -1, 1) - np.roll(magnitude, 1, 1)) * .5
        gy = (np.roll(magnitude, -1, 0) - np.roll(magnitude, 1, 0)) * .5
        norm = np.sqrt(gx * gx + gy * gy) + 1e-5
        u += dt * 3.0 * gy / norm * curl
        v -= dt * 3.0 * gx / norm * curl
        u[:, [0, -1]] = 0.0
        v[[0, -1], :] = 0.0
        divergence = (np.roll(u, -1, 1) - np.roll(u, 1, 1) + np.roll(v, -1, 0) - np.roll(v, 1, 0)) * .5
        pressure = np.zeros_like(divergence)
        for _ in range(48):
            pressure[1:-1, 1:-1] = (
                pressure[1:-1, 2:] + pressure[1:-1, :-2] + pressure[2:, 1:-1] + pressure[:-2, 1:-1]
                - divergence[1:-1, 1:-1]
            ) * .25
            pressure[0] = pressure[1]
            pressure[-1] = pressure[-2]
            pressure[:, 0] = pressure[:, 1]
            pressure[:, -1] = pressure[:, -2]
        u -= (np.roll(pressure, -1, 1) - np.roll(pressure, 1, 1)) * .5
        v -= (np.roll(pressure, -1, 0) - np.roll(pressure, 1, 0)) * .5
        u[:, [0, -1]] = 0.0
        v[[0, -1], :] = 0.0
        self.density = self._scalar(self.density, u, v, dt) * math.exp(-dt * self.density_decay)
        self.temperature = self._scalar(self.temperature, u, v, dt) * math.exp(-dt * .70)
        self.u = u * math.exp(-dt * .12)
        self.v = v * math.exp(-dt * .12)
        # Art-directed unresolved planar mixing: 32 world units squared/second.
        for field in (self.density, self.temperature):
            laplacian = (
                np.roll(field, 1, 0) + np.roll(field, -1, 0)
                + np.roll(field, 1, 1) + np.roll(field, -1, 1) - 4 * field
            )
            field += 8 * dt * laplacian
            field[:2] = 0.0
            field[-2:] = 0.0
            field[:, :2] = 0.0
            field[:, -2:] = 0.0
        self.version += 1


class SmokeSimulation:
    def __init__(self) -> None:
        self.fields: dict[int, SmokeField] = {}
        self.claims: dict[tuple[str, int], tuple[int, int]] = {}
        self.pending: list[tuple[float, SmokeEmission]] = []
        self._next_identity = 0

    def reset(self) -> None:
        self.fields.clear()
        self.claims.clear()
        self.pending.clear()

    def claims_entry(self, source: str, slot: int, generation: int) -> bool:
        claim = self.claims.get((source, slot))
        return claim is not None and claim[0] == generation and any(
            field.identity == claim[1] for field in self.fields.values()
        )

    def consume(self, emissions: tuple[SmokeEmission, ...], dt_sim: float) -> None:
        if not math.isfinite(dt_sim) or dt_sim < 0.0:
            raise ValueError("smoke presentation delta must be finite and nonnegative")
        ready = []
        waiting = []
        for age, emission in self.pending:
            age = f32(f32(age) + f32(dt_sim))
            if age >= 0.0:
                ready.append(emission)
            else:
                waiting.append((age, emission))
        self.pending = waiting
        for emission in emissions:
            if emission.color.a <= 0.0 or not all(math.isfinite(v) for v in (
                emission.pos.x, emission.pos.y, emission.vel.x, emission.vel.y, emission.scale,
                emission.color.r, emission.color.g, emission.color.b, emission.color.a,
                emission.delay_seconds, emission.expansion, emission.retention_seconds,
            )):
                continue
            if emission.delay_seconds > 0.0:
                if len(self.pending) < MAX_PENDING_EMISSIONS:
                    self.pending.append((-emission.delay_seconds, emission))
            else:
                ready.append(emission)
        for emission in ready:
            size = max(emission.scale, emission.expansion * 2.0 * STEP_SECONDS)
            if size <= 0.0:
                continue
            # Keep most injected mass inside the field and outside its edge fade.
            margin = max(24.0, size * (1.85 if emission.vel.length_sq() > 1e-10 else 1.5)) + 18.0
            if margin >= FIELD_SIZE * .5:
                continue
            candidates = [field for field in self.fields.values() if field.accepts(emission.pos, margin)]
            if candidates:
                field = min(candidates, key=lambda f: (f.origin + Vec2(FIELD_SIZE / 2, FIELD_SIZE / 2) - emission.pos).length_sq())
            elif len(self.fields) < MAX_FIELDS:
                slot = next(i for i in range(MAX_FIELDS) if i not in self.fields)
                origin = Vec2(
                    math.floor(emission.pos.x / CELL_SIZE) * CELL_SIZE - FIELD_SIZE / 2,
                    math.floor(emission.pos.y / CELL_SIZE) * CELL_SIZE - FIELD_SIZE / 2,
                )
                field = SmokeField(origin, self._next_identity)
                self._next_identity += 1
                self.fields[slot] = field
            else:
                # Unclaimed native sprites keep their ordinary rendering/lifetime.
                continue
            field.inject(emission)
            self.claims[(emission.source, emission.slot)] = (emission.generation, field.identity)
        if dt_sim <= 0.0:
            return
        for slot, field in tuple(self.fields.items()):
            field.advance(dt_sim)
            if field.fade <= 0.0 or (field.idle_seconds > .5 and float(field.density.max()) < .001):
                del self.fields[slot]
