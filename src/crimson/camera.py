from __future__ import annotations

"""Camera helpers recovered from the original crimsonland.exe.

This module currently models the `camera_update` screen shake logic, which is
global state in the original game.
"""

from grim.geom import Vec2

from .gameplay import GameplayState


def camera_shake_start(state: GameplayState, *, pulses: int, timer: float) -> None:
    """Start a camera shake sequence.

    Mirrors the nuke path in `bonus_apply`, which sets:
      - `camera_shake_pulses = 0x14`
      - `camera_shake_timer = 0.2`
    """

    state.camera_shake_pulses = int(pulses)
    state.camera_shake_timer = float(timer)


def camera_shake_update(state: GameplayState, dt: float) -> None:
    """Update camera shake offsets and timers.

    Port of `camera_update` (crimsonland.exe @ 0x00409500):
      - timer decays at `dt * 3.0`
      - when timer drops below 0, a "pulse" happens:
        - pulses--
        - timer resets to 0.1 (or 0.06 when time scaling is active)
        - offsets jump to new RNG-derived values
    """

    if state.camera_shake_timer <= 0.0:
        state.camera_shake_offset = Vec2()
        return

    state.camera_shake_timer -= float(dt) * 3.0
    if state.camera_shake_timer >= 0.0:
        return

    state.camera_shake_pulses -= 1
    if state.camera_shake_pulses < 1:
        state.camera_shake_timer = 0.0
        return

    time_scale_active = state.bonuses.reflex_boost > 0.0
    state.camera_shake_timer = 0.06 if time_scale_active else 0.1

    # Decompiled logic:
    #   iVar4 = camera_shake_pulses * 0x3c;
    #   iVar1 = rand() % (iVar4 / 0x14) + rand() % 10;
    # ... where (pulses * 0x3c) / 0x14 == pulses * 3.
    max_amp = int(state.camera_shake_pulses) * 3
    if max_amp <= 0:
        state.camera_shake_offset = Vec2()
        state.camera_shake_timer = 0.0
        state.camera_shake_pulses = 0
        return

    rand = state.rng.rand

    mag_x = (int(rand()) % max_amp) + (int(rand()) % 10)
    if (int(rand()) & 1) == 0:
        mag_x = -mag_x
    offset_x = float(mag_x)

    mag_y = (int(rand()) % max_amp) + (int(rand()) % 10)
    if (int(rand()) & 1) == 0:
        mag_y = -mag_y
    offset_y = float(mag_y)
    state.camera_shake_offset = Vec2(offset_x, offset_y)
