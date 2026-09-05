from __future__ import annotations

import struct
from functools import lru_cache

from .geom import Vec2

_F32 = struct.Struct("<f")


def _f32(value: float) -> float:
    return _F32.unpack(_F32.pack(value))[0]


def native_sound_pan(position: Vec2 | None, *, camera: Vec2, screen_width: float) -> int:
    """sfx_play_panned: horizontal position to DirectSound hundredths of dB."""
    if position is None:
        return 0
    screen_x = _f32(_f32(camera.x) + _f32(position.x))
    fraction = _f32(screen_x / _f32(screen_width))
    pan = int(_f32(_f32(fraction - 0.5) * 1700.0))
    return min(10_000, max(-10_000, pan))


def native_sound_gain(volume: float) -> float:
    """sfx_entry_set_volume maps the game scalar into DirectSound attenuation."""
    # Keep the port's explicit zero-volume mute. Native's positive-volume curve
    # otherwise leaves a small audible floor even when its scalar reaches zero.
    if volume <= 0.0:
        return 0.0
    # Native runs these operations at x87 PC=24 and __ftol truncates to zero.
    mapped = _f32(_f32(_f32(volume) + 2.0) * _f32(1.0 / 3.0))
    attenuation = int(_f32(_f32(1.0 - mapped) * -10_000.0))
    return 10.0 ** (min(0, max(-10_000, attenuation)) / 2000.0)


def _pan_level(value: float) -> float:
    # raylib 5.5 raudio.c, MixAudioFrames: its stereo pan law.
    return 0.5 * value * (3.0 - value * value)


@lru_cache(maxsize=512)
def raylib_pan(native_pan: int) -> tuple[float, float]:
    """Return raylib pan and gain compensation for native channel attenuation.

    DirectSound keeps the louder channel unchanged. Raylib attenuates both
    channels, with pan=1 meaning left. Invert its monotone channel ratio and
    compensate its overall gain, including the centered case.
    """
    if native_pan == 0:
        return 0.5, 1.0 / _pan_level(0.5)
    ratio = 10.0 ** (-abs(native_pan) / 2000.0)
    lo, hi = 0.0, 0.5
    for _ in range(24):
        mid = (lo + hi) * 0.5
        if _pan_level(mid) / _pan_level(1.0 - mid) < ratio:
            lo = mid
        else:
            hi = mid
    quiet = (lo + hi) * 0.5
    return (quiet if native_pan > 0 else 1.0 - quiet), 1.0 / _pan_level(1.0 - quiet)
