from __future__ import annotations

import struct

from .spawn import CreatureFlags


def _f32(value: float) -> float:
    """Round-trip through float32 to match the game's stored float behavior."""
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _i32(value: int) -> int:
    value &= 0xFFFFFFFF
    if value & 0x80000000:
        return value - 0x100000000
    return value


def creature_anim_is_long_strip(flags: CreatureFlags) -> bool:
    # From creature_update_all / creature_render_type:
    # long strip when (flags & 4) == 0 OR (flags & 0x40) != 0
    return (flags & CreatureFlags.ANIM_PING_PONG) == 0 or (flags & CreatureFlags.ANIM_LONG_STRIP) != 0


def creature_anim_phase_step(
    *,
    anim_rate: float,
    move_speed: float,
    dt: float,
    size: float,
    local_scale: float = 1.0,
    flags: CreatureFlags = CreatureFlags(0),
    ai_mode: int = 0,
    quantize_f32: bool = True,
) -> float:
    """Compute the per-frame animation phase increment (creature_update_all)."""
    if size == 0.0:
        return 0.0

    if quantize_f32:
        anim_rate = _f32(anim_rate)
        move_speed = _f32(move_speed)
        dt = _f32(dt)
        size = _f32(size)
        local_scale = _f32(local_scale)

    speed_scale = (_f32(30.0) if quantize_f32 else 30.0) / size
    strip_mul = _f32(25.0) if quantize_f32 else 25.0
    if not creature_anim_is_long_strip(flags):
        strip_mul = _f32(22.0) if quantize_f32 else 22.0
    elif ai_mode == 7:
        # Long-strip creatures stop advancing animation phase in ai_mode == 7.
        return 0.0

    step = anim_rate * move_speed * dt * speed_scale * local_scale * strip_mul
    return _f32(step) if quantize_f32 else step


def creature_anim_advance_phase(
    phase: float,
    *,
    anim_rate: float,
    move_speed: float,
    dt: float,
    size: float,
    local_scale: float = 1.0,
    flags: CreatureFlags = CreatureFlags(0),
    ai_mode: int = 0,
    quantize_f32: bool = True,
) -> tuple[float, float]:
    """Advance anim_phase and wrap it the same way as creature_update_all.

    Returns (new_phase, applied_step).
    """
    if quantize_f32:
        phase = _f32(phase)

    step = creature_anim_phase_step(
        anim_rate=anim_rate,
        move_speed=move_speed,
        dt=dt,
        size=size,
        local_scale=local_scale,
        flags=flags,
        ai_mode=ai_mode,
        quantize_f32=quantize_f32,
    )
    if step == 0.0:
        return phase, 0.0

    phase = phase + step
    if quantize_f32:
        phase = _f32(phase)

    if creature_anim_is_long_strip(flags):
        limit = _f32(31.0) if quantize_f32 else 31.0
        while phase > limit:
            phase = phase - limit
            if quantize_f32:
                phase = _f32(phase)
    else:
        limit = _f32(15.0) if quantize_f32 else 15.0
        if phase > limit:
            while phase > limit:
                phase = phase - limit
                if quantize_f32:
                    phase = _f32(phase)

    return phase, step


def creature_anim_select_frame(
    phase: float,
    *,
    base_frame: int,
    mirror_long: bool,
    flags: CreatureFlags = CreatureFlags(0),
) -> tuple[int, bool, str]:
    """Select an 8x8 atlas frame index (creature_render_type).

    Returns (frame_index, mirror_applied, mode).

    Note: mirror_applied refers to the long-strip ping-pong index mirroring
    (frame = 0x1f - frame) when the per-type mirror flag is set, not a texture flip.
    """
    if creature_anim_is_long_strip(flags):
        if phase < 0.0:
            # Negative anim_phase is used as a special render state in the game; keep the
            # same fallback frame selection.
            frame = base_frame + 0x0F
            mirrored = False
        else:
            # Matches __ftol(phase + 0.5f) used by the original binary.
            frame = int(phase + 0.5)
            mirrored = False
            if mirror_long and frame > 0x0F:
                frame = 0x1F - frame
                mirrored = True
        if flags & CreatureFlags.RANGED_ATTACK_SHOCK:
            frame += 0x20
        return frame, mirrored, "long"

    # Ping-pong strip:
    #   idx = (__ftol(phase + 0.5f) & 0x8000000f); then normalize negatives; then mirror >7.
    raw = int(phase + 0.5)
    idx = _i32(_u32(raw) & 0x8000000F)
    if idx < 0:
        idx = _i32(_u32(((idx - 1) | 0xFFFFFFF0) + 1))
    if idx > 7:
        idx = 0x0F - idx
    frame = base_frame + 0x10 + idx
    return frame, False, "ping-pong"
