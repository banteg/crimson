from __future__ import annotations

import hashlib
import struct

from ..gameplay import GameplayState, PlayerState
from .world_state import WorldState

_U8 = struct.Struct("<B")
_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")
_I32 = struct.Struct("<i")
_F32 = struct.Struct("<f")


def _h_u8(h: "hashlib._Hash", value: int) -> None:
    h.update(_U8.pack(int(value) & 0xFF))


def _h_u16(h: "hashlib._Hash", value: int) -> None:
    h.update(_U16.pack(int(value) & 0xFFFF))


def _h_u32(h: "hashlib._Hash", value: int) -> None:
    h.update(_U32.pack(int(value) & 0xFFFF_FFFF))


def _h_i32(h: "hashlib._Hash", value: int) -> None:
    raw = int(value) & 0xFFFF_FFFF
    if raw & 0x8000_0000:
        raw -= 0x1_0000_0000
    h.update(_I32.pack(int(raw)))


def _h_f32(h: "hashlib._Hash", value: float) -> None:
    h.update(_F32.pack(float(value)))


def _hash_gameplay_globals(h: "hashlib._Hash", state: GameplayState) -> None:
    _h_u32(h, state.rng.state)
    _h_u8(h, int(state.game_mode))
    _h_u8(h, 1 if state.demo_mode_active else 0)
    _h_u8(h, 1 if state.hardcore else 0)
    _h_u8(h, 1 if state.preserve_bugs else 0)

    bonuses = state.bonuses
    _h_f32(h, float(bonuses.weapon_power_up))
    _h_f32(h, float(bonuses.reflex_boost))
    _h_f32(h, float(bonuses.energizer))
    _h_f32(h, float(bonuses.double_experience))
    _h_f32(h, float(bonuses.freeze))

    perk_state = state.perk_selection
    _h_u16(h, int(perk_state.pending_count))
    _h_u8(h, 1 if perk_state.choices_dirty else 0)
    _h_u8(h, len(perk_state.choices))
    for value in perk_state.choices[:16]:
        _h_u16(h, int(value))

    _h_f32(h, float(state.lean_mean_exp_timer))
    _h_f32(h, float(state.jinxed_timer))
    _h_u16(h, int(state.plaguebearer_infection_count))
    _h_u8(h, 1 if state.friendly_fire_enabled else 0)


def _hash_players(h: "hashlib._Hash", players: list[PlayerState]) -> None:
    _h_u8(h, len(players))
    for player in players:
        _h_u8(h, int(player.index))
        _h_f32(h, float(player.pos_x))
        _h_f32(h, float(player.pos_y))
        _h_f32(h, float(player.health))
        _h_f32(h, float(player.size))
        _h_u16(h, int(player.weapon_id))
        _h_u16(h, int(player.clip_size))
        _h_f32(h, float(player.ammo))
        _h_u8(h, 1 if player.reload_active else 0)
        _h_f32(h, float(player.reload_timer))
        _h_f32(h, float(player.shot_cooldown))
        _h_u16(h, int(player.shot_seq))
        _h_u32(h, int(player.experience))
        _h_u16(h, int(player.level))


def fingerprint_world_state(
    world: WorldState,
    *,
    max_creatures: int | None = None,
    max_projectiles: int | None = None,
    max_bonuses: int | None = None,
) -> int:
    """Return a stable 64-bit digest of key simulation state.

    Notes:
    - Uses float32 packing for determinism and to reduce noise from float64 drift.
    - Iterates pools in their index order to match exe scan/alloc behavior.
    """

    h = hashlib.blake2b(digest_size=8)
    state = world.state

    _hash_gameplay_globals(h, state)
    _hash_players(h, world.players)

    creatures = world.creatures.entries
    limit = len(creatures) if max_creatures is None else max(0, min(int(max_creatures), len(creatures)))
    _h_u16(h, int(world.creatures.kill_count))
    _h_u16(h, int(world.creatures.spawned_count))
    _h_u16(h, limit)
    for idx in range(limit):
        creature = creatures[idx]
        active = bool(getattr(creature, "active", False))
        _h_u8(h, 1 if active else 0)
        if not active:
            continue
        _h_u16(h, int(getattr(creature, "type_id", 0)))
        _h_f32(h, float(getattr(creature, "x", 0.0)))
        _h_f32(h, float(getattr(creature, "y", 0.0)))
        _h_f32(h, float(getattr(creature, "hp", 0.0)))
        _h_f32(h, float(getattr(creature, "hitbox_size", 0.0)))
        _h_u32(h, int(getattr(creature, "flags", 0)))
        _h_u16(h, int(getattr(creature, "ai_mode", 0)))
        _h_i32(h, int(getattr(creature, "link_index", 0)))
        _h_i32(h, int(getattr(creature, "spawn_slot_index", -1)))

    projectiles = state.projectiles.entries
    proj_limit = len(projectiles) if max_projectiles is None else max(0, min(int(max_projectiles), len(projectiles)))
    _h_u16(h, proj_limit)
    for idx in range(proj_limit):
        proj = projectiles[idx]
        active = bool(getattr(proj, "active", False))
        _h_u8(h, 1 if active else 0)
        if not active:
            continue
        _h_u16(h, int(getattr(proj, "type_id", 0)))
        _h_f32(h, float(getattr(proj, "pos_x", 0.0)))
        _h_f32(h, float(getattr(proj, "pos_y", 0.0)))
        _h_f32(h, float(getattr(proj, "vel_x", 0.0)))
        _h_f32(h, float(getattr(proj, "vel_y", 0.0)))
        _h_f32(h, float(getattr(proj, "life_timer", 0.0)))
        _h_i32(h, int(getattr(proj, "owner_id", 0)))

    bonuses = state.bonus_pool.entries
    bonus_limit = len(bonuses) if max_bonuses is None else max(0, min(int(max_bonuses), len(bonuses)))
    _h_u8(h, bonus_limit)
    for idx in range(bonus_limit):
        entry = bonuses[idx]
        active = int(getattr(entry, "bonus_id", 0)) != 0 and not bool(getattr(entry, "picked", False))
        _h_u8(h, 1 if active else 0)
        if not active:
            continue
        _h_u16(h, int(getattr(entry, "bonus_id", 0)))
        _h_f32(h, float(getattr(entry, "pos_x", 0.0)))
        _h_f32(h, float(getattr(entry, "pos_y", 0.0)))
        _h_f32(h, float(getattr(entry, "time_left", 0.0)))

    return int.from_bytes(h.digest(), "little")
