from __future__ import annotations

import struct
from collections.abc import Sequence

from grim.color import RGBA
from grim.geom import Vec2

from ..creatures.runtime import CreatureAiMode, CreatureState, CreatureTypeId
from ..creatures.spawn_ids import CreatureFlags
from ..math_parity import f32
from ..weapon_runtime import init_default_alt_weapon
from ..weapons import WeaponId
from .gameplay_state import GameplayState
from .run_spec import CreatureSlotResidue
from .state_types import PlayerState


def apply_creature_pool_residue(
    creatures: list[CreatureState],
    residue: Sequence[CreatureSlotResidue],
) -> None:
    """Seed the fresh pool with the run-start residue captured natively.

    `creature_reset_all` (0x4281e0) clears `active` and detaches linked
    spawn-slot owners, but leaves the other creature fields intact. Spawn
    paths overwrite only the fields they write, so stale reads (link_index,
    target_heading, AI7 timers, ...) must see the previous occupant's values."""

    for slot in residue:
        idx = int(slot.index)
        if not (0 <= idx < len(creatures)):
            continue
        entry = creatures[idx]
        entry.active = False
        entry.phase_seed = int(slot.phase_seed)
        entry.plague_infected = bool(slot.collision_flag)
        entry.collision_timer = float(slot.collision_timer)
        entry.lifecycle_stage = float(slot.lifecycle_stage)
        entry.pos = Vec2(float(slot.pos.x), float(slot.pos.y))
        entry.vel = Vec2(float(slot.vel.x), float(slot.vel.y))
        entry.hp = float(slot.hp)
        entry.max_hp = float(slot.max_hp)
        entry.heading = float(slot.heading)
        entry.target_heading = float(slot.target_heading)
        entry.size = float(slot.size)
        entry.hit_flash_timer = float(slot.hit_flash_timer)
        entry.tint = RGBA(float(slot.tint_r), float(slot.tint_g), float(slot.tint_b), float(slot.tint_a))
        entry.force_target = int(slot.force_target)
        entry.target = Vec2(float(slot.target.x), float(slot.target.y))
        entry.contact_damage = float(slot.contact_damage)
        entry.move_speed = float(slot.move_speed)
        entry.attack_cooldown = float(slot.attack_cooldown)
        entry.reward_value = float(slot.reward_value)
        entry.type_id = CreatureTypeId(int(slot.type_id))
        entry.target_player = int(slot.target_player)
        entry.link_index = int(slot.link_index)
        entry.target_offset = Vec2(float(slot.target_offset.x), float(slot.target_offset.y))
        entry.orbit_angle = float(slot.orbit_angle)
        entry.orbit_radius = _f32_from_bits(int(slot.orbit_radius_u32))
        entry.flags = CreatureFlags(int(slot.flags))
        entry.ai_mode = CreatureAiMode(int(slot.ai_mode))
        entry.anim_phase = float(slot.anim_phase)


def _f32_from_bits(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", int(bits) & 0xFFFFFFFF))[0]


def _reset_player_weapon_native(player: PlayerState) -> None:
    """Port of the weapon block in `player_reset_all` (0x41fc80).

    Native resets every run to a hardcoded 10-round pistol with a primed
    1.0s reload duration and a decaying 0.8s shot cooldown; it does not go
    through `weapon_assign_player` (no table stats, no usage count, no
    reload sfx), and it leaves the primary reload-active byte untouched.
    Quest setup assigns the start weapon on top of this."""

    weapon = player.weapon
    weapon.weapon_id = WeaponId.PISTOL
    weapon.clip_size = 10
    weapon.ammo = 10.0
    weapon.reload_timer = 0.0
    weapon.reload_timer_max = 1.0
    weapon.shot_cooldown = 0.8


def reset_world_players(
    players: list[PlayerState],
    *,
    state: GameplayState,
    world_size: float,
    player_count: int,
    spawn_pos: Vec2 | None = None,
) -> None:
    previous_players = tuple(players)
    players.clear()

    if spawn_pos is None:
        center = f32(float(world_size) * 0.5)
        base = Vec2(center, center)
    else:
        base = Vec2(f32(spawn_pos.x), f32(spawn_pos.y))
    count = max(1, int(player_count))

    for idx in range(count):
        offset = f32(float(idx * 0x50))
        if idx % 2:
            pos = Vec2(f32(base.x - offset), f32(base.y - offset))
        else:
            pos = Vec2(f32(base.x + offset), f32(base.y + offset))
        if idx < len(previous_players):
            player = previous_players[idx]
            player.index = idx
        else:
            player = PlayerState(index=idx, pos=pos)

        # `player_reset_all` mutates selected fields in the two static native
        # records; it does not reconstruct the player object. Keep the same
        # contract here so run-transition residue remains observable.
        player.pos = pos
        player.health = 100.0
        player.size = 48.0
        player.speed_multiplier = 2.0
        player.move_speed = 0.0
        player.heading = 0.0
        player.death_timer = 16.0
        player.experience = 0
        player.level = 1
        player.spread_heat = 0.0
        player.perk_counts = [0] * len(player.perk_counts)
        player.plaguebearer_active = False
        player.speed_bonus_timer = 0.0
        player.shield_timer = 0.0
        _reset_player_weapon_native(player)
        init_default_alt_weapon(player)

        # `gameplay_reset_state` immediately follows `player_reset_all` with
        # these represented per-player writes. The native move target is held
        # by the input runtime rather than PlayerState in this port.
        player.low_health_timer = 100.0
        player.auto_target = 0
        player.aux_timer = 0.0
        players.append(player)


