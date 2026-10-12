from __future__ import annotations

from functools import lru_cache

from .geom import Vec2
from .math import f32


def native_sound_pan(position: Vec2 | None, *, camera: Vec2, screen_width: float) -> int:
    """sfx_play_panned: horizontal position to DirectSound hundredths of dB."""
    if position is None:
        return 0
    screen_x = f32(f32(camera.x) + f32(position.x))
    fraction = f32(screen_x / f32(screen_width))
    pan = int(f32(f32(fraction - 0.5) * 1700.0))
    return min(10_000, max(-10_000, pan))


def native_sound_gain(volume: float) -> float:
    """sfx_entry_set_volume maps the game scalar into DirectSound attenuation."""
    # Keep the port's explicit zero-volume mute. Native's positive-volume curve
    # otherwise leaves a small audible floor even when its scalar reaches zero.
    if volume <= 0.0:
        return 0.0
    # Native runs these operations at x87 PC=24 and __ftol truncates to zero.
    mapped = f32(f32(f32(volume) + 2.0) * f32(1.0 / 3.0))
    attenuation = int(f32(f32(1.0 - mapped) * -10_000.0))
    return 10.0 ** (min(0, max(-10_000, attenuation)) / 2000.0)


def _pan_level(share: float) -> float:
    # raylib 6 raudio.c, MixAudioFrames: its stereo pan law over a channel's share.
    return 0.5 * share * (3.0 - share * share)


@lru_cache(maxsize=512)
def raylib_pan(native_pan: int) -> tuple[float, float]:
    """Return raylib pan and gain compensation for native channel attenuation.

    DirectSound keeps the louder channel unchanged. Raylib pan runs from -1
    (left) to 1 (right) and attenuates both channels, splitting a share
    ``(pan + 1) / 2`` to the right. Invert its monotone channel ratio and
    compensate its overall gain, including the centered case.
    """
    if native_pan == 0:
        return 0.0, 1.0 / _pan_level(0.5)
    ratio = 10.0 ** (-abs(native_pan) / 2000.0)
    lo, hi = 0.5, 1.0
    for _ in range(24):
        mid = (lo + hi) * 0.5
        if _pan_level(1.0 - mid) / _pan_level(mid) > ratio:
            lo = mid
        else:
            hi = mid
    loud = (lo + hi) * 0.5
    pan = 2.0 * loud - 1.0
    return (pan if native_pan > 0 else -pan), 1.0 / _pan_level(loud)
