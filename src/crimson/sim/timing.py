from __future__ import annotations

import math

import msgspec

from ..math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub


def reflex_boost_time_scale_factor(*, reflex_boost_timer: float, time_scale_active: bool) -> float:
    """Return the native Reflex Boost scale with x87 PC=24 operation boundaries."""

    if not time_scale_active:
        return 1.0

    reflex_f32 = f32(float(reflex_boost_timer))
    if reflex_f32 >= 1.0:
        return f32(0.3)

    return x87_pc24_add(
        x87_pc24_mul(
            x87_pc24_sub(f32(1.0), reflex_f32),
            f32(0.7),
        ),
        f32(0.3),
    )


def ftol_ms_i32(dt_seconds: float) -> int:
    """Convert seconds -> integer milliseconds via float32 scale + truncation."""

    dt_f32 = f32(float(dt_seconds))
    scaled_ms_f32 = f32(float(dt_f32) * 1000.0)
    return int(math.trunc(float(scaled_ms_f32)))


def nearest_ms_i32(seconds: float) -> int:
    """Encode canonical f32 seconds using Frida's nearest-millisecond rule."""

    seconds_f32 = f32(float(seconds))
    return int(math.floor(float(seconds_f32) * 1000.0 + 0.5))


class FrameTiming(msgspec.Struct, frozen=True):
    dt: float
    time_scale_active_entry: bool
    time_scale_factor: float
    zero_gate_active: bool
    dt_sim: float

    @property
    def dt_ms_i32(self) -> int:
        return int(ftol_ms_i32(self.dt))

    @property
    def dt_sim_ms_i32(self) -> int:
        return int(ftol_ms_i32(self.dt_sim))

    @staticmethod
    def compute(
        dt: float,
        *,
        world_dt: float | None = None,
        time_scale_active_entry: bool,
        time_scale_factor: float,
        zero_gate_active: bool,
    ) -> FrameTiming:
        dt_f32 = float(f32(float(dt)))
        if not math.isfinite(dt_f32):
            raise ValueError(f"dt must be finite, got {dt!r}")
        world_dt_f32 = dt_f32 if world_dt is None else float(f32(float(world_dt)))
        if not math.isfinite(world_dt_f32):
            raise ValueError(f"world_dt must be finite, got {world_dt!r}")

        active = bool(time_scale_active_entry)
        factor = float(f32(float(time_scale_factor)))
        if active and (not math.isfinite(factor) or float(factor) <= 0.0):
            raise ValueError(f"time_scale_factor must be finite and > 0 when active, got {time_scale_factor!r}")

        dt_sim = float(world_dt_f32)
        if active:
            dt_sim = float(x87_pc24_mul(world_dt_f32, factor))
        if bool(zero_gate_active):
            dt_sim = 0.0

        return FrameTiming(
            dt=float(dt_f32),
            time_scale_active_entry=active,
            time_scale_factor=float(factor),
            zero_gate_active=bool(zero_gate_active),
            dt_sim=float(dt_sim),
        )
