from __future__ import annotations

from .assign import (
    init_default_alt_weapon,
    most_used_weapon_id_for_player,
    player_start_reload,
    player_swap_alt_weapon,
    weapon_assign_player,
    weapon_entry,
)
from .availability import prepare_weapon_availability, weapon_pick_random_available
from .fire import WeaponFireCtx, WeaponFireResult, capture_fire_gate, fire_weapon
from .spawn import projectile_spawn, spawn_projectile_ring

__all__ = [
    "WeaponFireCtx",
    "WeaponFireResult",
    "capture_fire_gate",
    "fire_weapon",
    "init_default_alt_weapon",
    "most_used_weapon_id_for_player",
    "player_start_reload",
    "player_swap_alt_weapon",
    "prepare_weapon_availability",
    "projectile_spawn",
    "spawn_projectile_ring",
    "weapon_assign_player",
    "weapon_entry",
    "weapon_pick_random_available",
]
