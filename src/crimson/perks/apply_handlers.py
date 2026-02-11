from __future__ import annotations

from .ammo_maniac import apply_ammo_maniac
from .apply_context import PerkApplyHandler
from .bandage import apply_bandage
from .breathing_room import apply_breathing_room
from .death_clock import apply_death_clock
from .fatal_lottery import apply_fatal_lottery
from .grim_deal import apply_grim_deal
from .ids import PerkId
from .infernal_contract import apply_infernal_contract
from .instant_winner import apply_instant_winner
from .lifeline_50_50 import apply_lifeline_50_50
from .my_favourite_weapon import apply_my_favourite_weapon
from .plaguebearer import apply_plaguebearer
from .random_weapon import apply_random_weapon
from .thick_skinned import apply_thick_skinned


PERK_APPLY_HANDLERS: dict[PerkId, PerkApplyHandler] = {
    PerkId.INSTANT_WINNER: apply_instant_winner,
    PerkId.FATAL_LOTTERY: apply_fatal_lottery,
    PerkId.RANDOM_WEAPON: apply_random_weapon,
    PerkId.LIFELINE_50_50: apply_lifeline_50_50,
    PerkId.THICK_SKINNED: apply_thick_skinned,
    PerkId.BREATHING_ROOM: apply_breathing_room,
    PerkId.INFERNAL_CONTRACT: apply_infernal_contract,
    PerkId.GRIM_DEAL: apply_grim_deal,
    PerkId.AMMO_MANIAC: apply_ammo_maniac,
    PerkId.DEATH_CLOCK: apply_death_clock,
    PerkId.BANDAGE: apply_bandage,
    PerkId.MY_FAVOURITE_WEAPON: apply_my_favourite_weapon,
    PerkId.PLAGUEBEARER: apply_plaguebearer,
}
