from __future__ import annotations

from dataclasses import dataclass, field
import datetime as dt
import math
import os
import random

import pyray as rl

from grim.assets import PaqTextureCache


# Native v1.9.93 only preloads balloon.tga (no in-binary draw consumer).
# Native v1.9.8 also has a render/update path that draws balloons when the date flag is set.
_BALLOON_EASTER_DATES = frozenset(((9, 12), (11, 8), (12, 18)))

ENV_ENABLE_BALLOONS_198 = "CRIMSON_ENABLE_BALLOONS_198"
ENV_FORCE_BALLOONS_198 = "CRIMSON_FORCE_BALLOONS_198"


def _env_bool(name: str, *, default: str = "0") -> bool:
    return os.environ.get(name, default) not in ("", "0", "false", "False")


def is_balloon_easter_egg_day(today: dt.date) -> bool:
    return (int(today.month), int(today.day)) in _BALLOON_EASTER_DATES


def balloons_198_enabled() -> bool:
    return _env_bool(ENV_ENABLE_BALLOONS_198)


def balloons_198_forced() -> bool:
    return _env_bool(ENV_FORCE_BALLOONS_198)


def should_show_balloons_198(today: dt.date) -> bool:
    if balloons_198_forced():
        return True
    if not balloons_198_enabled():
        return False
    return is_balloon_easter_egg_day(today)


def _tint(r: float, g: float, b: float, a: float) -> rl.Color:
    return rl.Color(
        int(round(float(r) * 255.0)),
        int(round(float(g) * 255.0)),
        int(round(float(b) * 255.0)),
        int(round(float(a) * 255.0)),
    )


_BALLOON_TINTS: tuple[rl.Color, ...] = (
    _tint(0.2, 1.0, 0.2, 0.5),
    _tint(0.2, 0.2, 1.0, 0.8),
    _tint(0.7, 0.2, 1.0, 0.6),
    _tint(1.0, 0.2, 0.2, 0.7),
)

_BALLOON_SEED_COUNT = 0x20
_BALLOON_DRAW_COUNT = 0x10

_BALLOON_SPEED_PX_PER_S = 60.0
_BALLOON_WRAP_TOP_Y = -128.0
_BALLOON_WRAP_PAD_PX = 128.0

_BALLOON_WAVE_AMP_PX = 64.0
_BALLOON_WAVE_FREQ_PER_MS = 0.00031415926

_BALLOON_WOBBLE_AMP_RAD = 0.4
_BALLOON_WOBBLE_FREQ_PER_MS = 0.003

# v1.9.8 computes these via a slightly odd integer pipeline, but the result is constant:
#  w = 64 * 0.6 = 38.4, h = 128 * 0.6 = 76.8
_BALLOON_W = 38.4
_BALLOON_H = 76.8


@dataclass(slots=True)
class Balloons198:
    rng: random.Random = field(default_factory=random.Random)
    time_ms: int = 0
    _initialized: bool = False
    _types: list[int] = field(default_factory=list)
    _y: list[float] = field(default_factory=list)

    def update(self, dt_s: float, *, screen_h: float) -> None:
        frame_dt = min(0.1, max(0.0, float(dt_s)))
        dt_ms = int(frame_dt * 1000.0)
        self.time_ms += dt_ms
        if not self._initialized:
            self._seed(screen_h=float(screen_h))
        speed = frame_dt * _BALLOON_SPEED_PX_PER_S
        wrap_add = float(screen_h) + _BALLOON_WRAP_PAD_PX
        for i in range(min(_BALLOON_DRAW_COUNT, len(self._y))):
            y = self._y[i] - speed
            if y < _BALLOON_WRAP_TOP_Y:
                y += wrap_add
            self._y[i] = y

    def draw(self, cache: PaqTextureCache | None, *, screen_w: float) -> None:
        if cache is None:
            return
        try:
            tex = cache.get_or_load("balloon", "balloon.tga").texture
        except FileNotFoundError:
            return
        if tex is None:
            return
        if not self._initialized:
            # Seed on first draw if update() hasn't run yet.
            self._seed(screen_h=float(rl.get_screen_height()))

        src = rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height))
        t = float(self.time_ms)
        screen_w_int = max(1, int(screen_w))
        for i in range(min(_BALLOON_DRAW_COUNT, len(self._y))):
            tint = _BALLOON_TINTS[int(self._types[i]) & 3]
            phase = float(i)
            x_base = (screen_w_int * int(i)) >> 4
            x = float(x_base) + math.cos(t * _BALLOON_WAVE_FREQ_PER_MS + phase) * _BALLOON_WAVE_AMP_PX
            y = float(self._y[i])
            # Native uses grim_set_rotation(sin(t*0.003 + i)*0.4 - pi/4), but grim's
            # rotation matrix is built from (radians + pi/4), so the visual rotation is
            # centered around 0: sin(t*0.003 + i)*0.4.
            angle_rad = math.sin(t * _BALLOON_WOBBLE_FREQ_PER_MS + phase) * _BALLOON_WOBBLE_AMP_RAD
            dst = rl.Rectangle(x, y, _BALLOON_W, _BALLOON_H)
            origin = rl.Vector2(_BALLOON_W * 0.5, _BALLOON_H * 0.5)
            rl.draw_texture_pro(tex, src, dst, origin, math.degrees(angle_rad), tint)

    def _seed(self, *, screen_h: float) -> None:
        self._types = [int(self.rng.randrange(4)) for _ in range(_BALLOON_SEED_COUNT)]
        h = max(1, int(screen_h))
        # v1.9.8 seeds y in [screen_h .. 2*screen_h).
        self._y = [float(self.rng.randrange(h) + h) for _ in range(_BALLOON_SEED_COUNT)]
        self._initialized = True
