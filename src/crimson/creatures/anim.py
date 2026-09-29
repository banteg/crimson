from __future__ import annotations

import msgspec

from grim.math import f32, i32

from ..math_parity import x87_pc24_div, x87_pc24_mul_chain
from .spawn import CreatureAiMode, CreatureFlags, CreatureTypeId

_FLAG_ANIM_PING_PONG = int(CreatureFlags.ANIM_PING_PONG)
_FLAG_ANIM_LONG_STRIP = int(CreatureFlags.ANIM_LONG_STRIP)
_FLAG_RANGED_ATTACK_SHOCK = int(CreatureFlags.RANGED_ATTACK_SHOCK)


class CreatureAnimInfo(msgspec.Struct, frozen=True):
    base: int
    anim_rate: float
    mirror: bool


CREATURE_ANIM: dict[CreatureTypeId, CreatureAnimInfo] = {
    CreatureTypeId.ZOMBIE: CreatureAnimInfo(base=0x20, anim_rate=1.2, mirror=False),
    CreatureTypeId.LIZARD: CreatureAnimInfo(base=0x10, anim_rate=1.6, mirror=True),
    CreatureTypeId.ALIEN: CreatureAnimInfo(base=0x20, anim_rate=1.35, mirror=False),
    CreatureTypeId.SPIDER_SP1: CreatureAnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.SPIDER_SP2: CreatureAnimInfo(base=0x10, anim_rate=1.5, mirror=True),
    CreatureTypeId.TROOPER: CreatureAnimInfo(base=0x00, anim_rate=1.0, mirror=False),
}


_CREATURE_CORPSE_FRAMES: dict[int, int] = {
    0: 0,  # zombie
    1: 3,  # lizard
    2: 4,  # alien
    3: 1,  # spider sp1
    4: 2,  # spider sp2
    5: 7,  # trooper
    7: 6,  # ping-pong strip corpse fallback
}


def creature_corpse_frame_for_type(type_id: int) -> int:
    """Resolve the bodyset frame index used for corpse decals (`fx_queue_render`)."""

    return _CREATURE_CORPSE_FRAMES.get(int(type_id), int(type_id) & 0xF)


def creature_anim_is_long_strip(flags: CreatureFlags) -> bool:
    # From creature_update_all / creature_render_type:
    # long strip when (flags & 4) == 0 OR (flags & 0x40) != 0
    flags_bits = int(flags)
    return (flags_bits & _FLAG_ANIM_PING_PONG) == 0 or (flags_bits & _FLAG_ANIM_LONG_STRIP) != 0


def creature_anim_phase_step(
    *,
    anim_rate: float,
    move_speed: float,
    dt: float,
    size: float,
    local_scale: float = 1.0,
    flags: CreatureFlags = CreatureFlags(0),
    ai_mode: int = CreatureAiMode.ORBIT_PLAYER,
) -> float:
    """Compute the per-frame animation phase increment (creature_update_all)."""
    if size == 0.0:
        return 0.0

    anim_rate = f32(anim_rate)
    move_speed = f32(move_speed)
    dt = f32(dt)
    size = f32(size)
    local_scale = f32(local_scale)

    flags_bits = int(flags)
    is_long_strip = (flags_bits & _FLAG_ANIM_PING_PONG) == 0 or (flags_bits & _FLAG_ANIM_LONG_STRIP) != 0
    strip_mul = 25.0
    if not is_long_strip:
        strip_mul = 22.0
    elif ai_mode == CreatureAiMode.HOLD_TIMER:
        # Long-strip creatures stop advancing animation phase in ai_mode == 7.
        return 0.0

    # creature_update_all 0x00426e57/0x00426ed5: `30.0f / size` stays on the
    # x87 stack, then rate * speed * dt * scale * move_scale * strip, each
    # multiply rounding at PC24.
    speed_scale = x87_pc24_div(30.0, size)
    return x87_pc24_mul_chain(anim_rate, move_speed, dt, speed_scale, local_scale, strip_mul)


def creature_anim_advance_phase(
    phase: float,
    *,
    anim_rate: float,
    move_speed: float,
    dt: float,
    size: float,
    local_scale: float = 1.0,
    flags: CreatureFlags = CreatureFlags(0),
    ai_mode: int = CreatureAiMode.ORBIT_PLAYER,
) -> tuple[float, float]:
    """Advance anim_phase and wrap it the same way as creature_update_all.

    Returns (new_phase, applied_step).
    """
    phase = f32(phase)

    step = creature_anim_phase_step(
        anim_rate=anim_rate,
        move_speed=move_speed,
        dt=dt,
        size=size,
        local_scale=local_scale,
        flags=flags,
        ai_mode=ai_mode,
    )
    if step == 0.0:
        return phase, 0.0

    phase = f32(phase + step)

    flags_bits = int(flags)
    is_long_strip = (flags_bits & _FLAG_ANIM_PING_PONG) == 0 or (flags_bits & _FLAG_ANIM_LONG_STRIP) != 0
    if is_long_strip:
        while phase > 31.0:
            phase = f32(phase - 31.0)
    else:
        while phase > 15.0:
            phase = f32(phase - 15.0)

    return phase, step


def creature_anim_select_frame(
    phase: float,
    *,
    base_frame: int,
    mirror_long: bool,
    flags: CreatureFlags = CreatureFlags(0),
    lifecycle_stage: float = 16.0,
) -> tuple[int, bool, str]:
    """Select the shadow/body atlas frame from lifecycle and animation state.

    Returns (frame_index, mirror_applied, mode).
    The default lifecycle is alive; death staging uses its own truncation path.
    Arithmetic before integer conversion follows native gameplay PC24 rounding.

    Note: mirror_applied refers to the long-strip ping-pong index mirroring
    (frame = 0x1f - frame) when the per-type mirror flag is set, not a texture flip.
    """
    phase = f32(phase)
    lifecycle_stage = f32(lifecycle_stage)
    flags_bits = int(flags)
    is_long_strip = (flags_bits & _FLAG_ANIM_PING_PONG) == 0 or (flags_bits & _FLAG_ANIM_LONG_STRIP) != 0
    if is_long_strip:
        if lifecycle_stage < 16.0:
            # Native branches on lifecycle, not on a synthetic animation phase.
            # Subtraction rounds at PC24 before __ftol truncates toward zero.
            frame = (
                base_frame + 0x0F if lifecycle_stage < 0.0 else int(f32(float(base_frame + 0x0F) - lifecycle_stage))
            )
            mirrored = False
        else:
            frame = int(f32(phase + 0.5))
            mirrored = False
            if mirror_long and frame > 0x0F:
                frame = 0x1F - frame
                mirrored = True
        if (flags_bits & _FLAG_RANGED_ATTACK_SHOCK) != 0:
            frame += 0x20
        return frame, mirrored, "long"

    # Ping-pong strip:
    #   idx = (__ftol(phase + 0.5f) & 0x8000000f); then normalize negatives; then mirror >7.
    raw = int(f32(phase + 0.5))
    idx = i32(raw & 0x8000000F)
    if idx < 0:
        idx = i32(((idx - 1) | 0xFFFFFFF0) + 1)
    if idx > 7:
        idx = 0x0F - idx
    frame = base_frame + 0x10 + idx
    return frame, False, "ping-pong"


def creature_anim_select_flash_frame(
    phase: float,
    *,
    base_frame: int,
    mirror_long: bool,
    flags: CreatureFlags = CreatureFlags(0),
    lifecycle_stage: float = 16.0,
) -> tuple[int, bool, str]:
    """Select the hit-flash frame; dying long strips omit the shock offset."""
    if f32(lifecycle_stage) < 16.0:
        flags &= ~CreatureFlags.RANGED_ATTACK_SHOCK
    return creature_anim_select_frame(
        phase,
        base_frame=base_frame,
        mirror_long=mirror_long,
        flags=flags,
        lifecycle_stage=lifecycle_stage,
    )
