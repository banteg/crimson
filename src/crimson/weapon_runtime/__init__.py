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
from .fire import WeaponFireCtx, WeaponFireResult, fire_weapon
from .spawn import (
    owner_ref_for_player,
    owner_ref_for_player_projectiles,
    projectile_spawn,
    spawn_projectile_ring,
    travel_budget_for_type_id,
)

__all__ = [
    "WeaponFireCtx",
    "WeaponFireResult",
    "fire_weapon",
    "init_default_alt_weapon",
    "most_used_weapon_id_for_player",
    "owner_ref_for_player",
    "owner_ref_for_player_projectiles",
    "player_start_reload",
    "player_swap_alt_weapon",
    "prepare_weapon_availability",
    "projectile_spawn",
    "spawn_projectile_ring",
    "travel_budget_for_type_id",
    "weapon_assign_player",
    "weapon_entry",
    "weapon_pick_random_available",
]
