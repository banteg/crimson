from __future__ import annotations

from crimson.creatures.anim import (
    CREATURE_ANIM,
    creature_anim_advance_phase,
    creature_anim_select_frame,
    creature_corpse_frame_for_type,
)
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.math_parity import f32, x87_pc24_div, x87_pc24_mul_chain
from crimson.owner_ref import OwnerRef
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def _expected_f32_step(*, strip_mul: float) -> float:
    # creature_update_all 0x00426e57: each x87 multiply rounds at PC24.
    speed_scale = x87_pc24_div(30.0, f32(50.0))
    return x87_pc24_mul_chain(f32(1.2), f32(2.0), f32(1.0 / 60.0), speed_scale, 1.0, strip_mul)


def test_creature_anim_advance_phase_long_strip_matches_formula() -> None:
    # rate=1.2, move_speed=2.0, dt=1/60, size=50:
    # step = 1.2 * 2.0 * (1/60) * (30/50) * 1.0 * 25 = 0.6
    phase, step = creature_anim_advance_phase(
        0.0,
        anim_rate=1.2,
        move_speed=2.0,
        dt=1.0 / 60.0,
        size=50.0,
        local_scale=1.0,
        flags=CreatureFlags(0),
        ai_mode=0,
    )
    expected = _expected_f32_step(strip_mul=25.0)
    assert_float_close(step, expected)
    assert_float_close(phase, expected)


def test_creature_anim_advance_phase_ping_pong_uses_22_multiplier() -> None:
    # Same inputs as above, but ping-pong uses 22 instead of 25:
    # step = 1.2 * 2.0 * (1/60) * (30/50) * 1.0 * 22 = 0.528
    phase, step = creature_anim_advance_phase(
        0.0,
        anim_rate=1.2,
        move_speed=2.0,
        dt=1.0 / 60.0,
        size=50.0,
        local_scale=1.0,
        flags=CreatureFlags.ANIM_PING_PONG,
        ai_mode=0,
    )
    expected = _expected_f32_step(strip_mul=22.0)
    assert_float_close(step, expected)
    assert_float_close(phase, expected)


def test_creature_anim_select_frame_ping_pong_basic() -> None:
    flags = CreatureFlags.ANIM_PING_PONG
    base = 0x20
    # idx=0 -> base+0x10+0 = 0x30
    frame, mirror_applied, mode = creature_anim_select_frame(0.0, base_frame=base, mirror_long=False, flags=flags)
    assert (frame, mirror_applied, mode) == (0x30, False, "ping-pong")

    # idx=7 -> base+0x10+7 = 0x37
    frame, mirror_applied, mode = creature_anim_select_frame(7.0, base_frame=base, mirror_long=False, flags=flags)
    assert (frame, mirror_applied, mode) == (0x37, False, "ping-pong")

    # idx=8 -> mirrored to 7 -> 0x37
    frame, mirror_applied, mode = creature_anim_select_frame(8.0, base_frame=base, mirror_long=False, flags=flags)
    assert (frame, mirror_applied, mode) == (0x37, False, "ping-pong")

    # idx=15 -> mirrored to 0 -> 0x30
    frame, mirror_applied, mode = creature_anim_select_frame(15.0, base_frame=base, mirror_long=False, flags=flags)
    assert (frame, mirror_applied, mode) == (0x30, False, "ping-pong")


def test_creature_anim_select_frame_long_strip_mirror_flag_is_index_mirror() -> None:
    # When the per-type mirror flag is set, long strip turns into a ping-pong of 16 frames:
    # phase 16 -> ftol(16.0 + 0.5) == 16, then mirrored to 31 - 16 == 15.
    frame, mirror_applied, mode = creature_anim_select_frame(
        16.0, base_frame=0x10, mirror_long=True, flags=CreatureFlags(0),
    )
    assert (frame, mirror_applied, mode) == (15, True, "long")


def test_creature_corpse_frame_ping_pong_fallback_uses_native_special_entry() -> None:
    # Native uses a special creature_type_table entry (effect id 7) for ping-pong strip corpses.
    assert creature_corpse_frame_for_type(7) == 6


def test_creature_killed_by_a_projectile_still_advances_its_walk_cycle_that_tick() -> None:
    # Native advances anim_phase inside `creature_update_all`, which runs before
    # `projectile_update`; a creature shot dead later in the tick keeps that step.
    world = WorldState.build(hardcore=False, quest_fail_retry_count=0)
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))
    creature = world.creatures.entries[0]
    creature.active = True
    creature.type_id = CreatureTypeId.ALIEN
    creature.flags = CreatureFlags(0)
    creature.pos = Vec2(256.0, 256.0)
    creature.hp = 1.0
    creature.max_hp = 1.0
    creature.size = 50.0
    creature.move_speed = 2.0
    creature.lifecycle_stage = 16.0
    world.state.projectiles.spawn(
        pos=creature.pos,
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_player(0),
    )
    dt = 1.0 / 60.0

    events = world.step(
        dt,
        inputs=None,
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        mode_update=None,
        violence_disabled=0,
        game_tune_started=False,
        perk_progression_enabled=False,
    )

    assert [death.index for death in events.deaths] == [0]
    expected_phase, _step = creature_anim_advance_phase(
        0.0,
        anim_rate=CREATURE_ANIM[CreatureTypeId.ALIEN].anim_rate,
        move_speed=2.0,
        dt=dt,
        size=50.0,
    )
    assert expected_phase > 0.0
    assert creature.anim_phase == expected_phase
