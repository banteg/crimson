from __future__ import annotations

from crimson.perks.impl.ammo_maniac import apply_ammo_maniac
from crimson.perks.impl.bandage import apply_bandage
from crimson.perks.impl.breathing_room import apply_breathing_room
from crimson.perks.impl.death_clock import apply_death_clock
from crimson.perks.impl.fatal_lottery import apply_fatal_lottery
from crimson.perks.impl.grim_deal import apply_grim_deal
from crimson.perks.impl.infernal_contract import apply_infernal_contract
from crimson.perks.impl.instant_winner import apply_instant_winner
from crimson.perks.impl.lifeline_50_50 import apply_lifeline_50_50
from crimson.perks.impl.my_favourite_weapon import apply_my_favourite_weapon
from crimson.perks.impl.plaguebearer import apply_plaguebearer
from crimson.perks.impl.random_weapon import apply_random_weapon
from crimson.perks.impl.thick_skinned import apply_thick_skinned

from ..ids import PerkId
from .apply_context import PerkApplyHandler

PERK_APPLY_HANDLERS: dict[PerkId, PerkApplyHandler] = {
    PerkId.DEATH_CLOCK: apply_death_clock,
    PerkId.INSTANT_WINNER: apply_instant_winner,
    PerkId.FATAL_LOTTERY: apply_fatal_lottery,
    PerkId.RANDOM_WEAPON: apply_random_weapon,
    PerkId.LIFELINE_50_50: apply_lifeline_50_50,
    PerkId.THICK_SKINNED: apply_thick_skinned,
    PerkId.BREATHING_ROOM: apply_breathing_room,
    PerkId.INFERNAL_CONTRACT: apply_infernal_contract,
    PerkId.GRIM_DEAL: apply_grim_deal,
    PerkId.AMMO_MANIAC: apply_ammo_maniac,
    PerkId.BANDAGE: apply_bandage,
    PerkId.MY_FAVOURITE_WEAPON: apply_my_favourite_weapon,
    PerkId.PLAGUEBEARER: apply_plaguebearer,
}
