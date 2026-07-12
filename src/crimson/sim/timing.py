from __future__ import annotations

import math

import msgspec

from ..math_parity import f32


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

    @property
    def dt_player_local(self) -> float:
        if not self.time_scale_active_entry:
            return float(self.dt_sim)
        return float(f32((0.600000024 / float(self.time_scale_factor)) * float(self.dt_sim)))

    @staticmethod
    def compute(
        dt: float,
        *,
        time_scale_active_entry: bool,
        time_scale_factor: float,
        zero_gate_active: bool,
    ) -> FrameTiming:
        dt_f32 = float(f32(float(dt)))
        if not math.isfinite(dt_f32):
            raise ValueError(f"dt must be finite, got {dt!r}")

        active = bool(time_scale_active_entry)
        factor = float(f32(float(time_scale_factor)))
        if active and (not math.isfinite(factor) or float(factor) <= 0.0):
            raise ValueError(f"time_scale_factor must be finite and > 0 when active, got {time_scale_factor!r}")

        dt_sim = float(dt_f32)
        if active:
            dt_sim = float(f32(float(dt_f32) * float(factor)))
        if bool(zero_gate_active):
            dt_sim = 0.0

        return FrameTiming(
            dt=float(dt_f32),
            time_scale_active_entry=active,
            time_scale_factor=float(factor),
            zero_gate_active=bool(zero_gate_active),
            dt_sim=float(dt_sim),
        )
