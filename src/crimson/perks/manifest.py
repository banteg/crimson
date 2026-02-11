from __future__ import annotations

"""Single source of truth for perk hook ownership and dispatch ordering."""

from .ammo_maniac import HOOKS as AMMO_MANIAC_HOOKS
from .apply_context import PerkApplyHandler
from .bandage import HOOKS as BANDAGE_HOOKS
from .breathing_room import HOOKS as BREATHING_ROOM_HOOKS
from .death_clock import HOOKS as DEATH_CLOCK_HOOKS
from .evil_eyes_effect import HOOKS as EVIL_EYES_HOOKS
from .fatal_lottery import HOOKS as FATAL_LOTTERY_HOOKS
from .final_revenge import HOOKS as FINAL_REVENGE_HOOKS
from .fire_cough import HOOKS as FIRE_COUGH_HOOKS
from .grim_deal import HOOKS as GRIM_DEAL_HOOKS
from .hook_types import PerkHooks, PerksUpdateEffectsStep, PlayerDeathHook, PlayerPerkTickStep, WorldDtStep
from .hot_tempered import HOOKS as HOT_TEMPERED_HOOKS
from .ids import PerkId
from .infernal_contract import HOOKS as INFERNAL_CONTRACT_HOOKS
from .instant_winner import HOOKS as INSTANT_WINNER_HOOKS
from .jinxed_effect import HOOKS as JINXED_HOOKS
from .lean_mean_exp_machine_effect import HOOKS as LEAN_MEAN_EXP_MACHINE_HOOKS
from .lifeline_50_50 import HOOKS as LIFELINE_50_50_HOOKS
from .living_fortress import HOOKS as LIVING_FORTRESS_HOOKS
from .man_bomb import HOOKS as MAN_BOMB_HOOKS
from .my_favourite_weapon import HOOKS as MY_FAVOURITE_WEAPON_HOOKS
from .plaguebearer import HOOKS as PLAGUEBEARER_HOOKS
from .player_bonus_timers_effect import update_player_bonus_timers
from .pyrokinetic_effect import HOOKS as PYROKINETIC_HOOKS
from .random_weapon import HOOKS as RANDOM_WEAPON_HOOKS
from .reflex_boosted import HOOKS as REFLEX_BOOSTED_HOOKS
from .regeneration_effect import HOOKS as REGENERATION_HOOKS
from .thick_skinned import HOOKS as THICK_SKINNED_HOOKS

# Order is parity-critical for runtime dispatch.
PERK_HOOKS_IN_ORDER: tuple[PerkHooks, ...] = (
    REFLEX_BOOSTED_HOOKS,
    MAN_BOMB_HOOKS,
    LIVING_FORTRESS_HOOKS,
    FIRE_COUGH_HOOKS,
    HOT_TEMPERED_HOOKS,
    REGENERATION_HOOKS,
    LEAN_MEAN_EXP_MACHINE_HOOKS,
    DEATH_CLOCK_HOOKS,
    EVIL_EYES_HOOKS,
    PYROKINETIC_HOOKS,
    JINXED_HOOKS,
    FINAL_REVENGE_HOOKS,
    INSTANT_WINNER_HOOKS,
    FATAL_LOTTERY_HOOKS,
    RANDOM_WEAPON_HOOKS,
    LIFELINE_50_50_HOOKS,
    THICK_SKINNED_HOOKS,
    BREATHING_ROOM_HOOKS,
    INFERNAL_CONTRACT_HOOKS,
    GRIM_DEAL_HOOKS,
    AMMO_MANIAC_HOOKS,
    BANDAGE_HOOKS,
    MY_FAVOURITE_WEAPON_HOOKS,
    PLAGUEBEARER_HOOKS,
)


PERK_APPLY_HANDLERS: dict[PerkId, PerkApplyHandler] = {
    hook.perk_id: hook.apply_handler
    for hook in PERK_HOOKS_IN_ORDER
    if hook.apply_handler is not None
}


WORLD_DT_STEPS: tuple[WorldDtStep, ...] = tuple(
    hook.world_dt_step for hook in PERK_HOOKS_IN_ORDER if hook.world_dt_step is not None
)


PLAYER_DEATH_HOOKS: tuple[PlayerDeathHook, ...] = tuple(
    hook.player_death_hook for hook in PERK_HOOKS_IN_ORDER if hook.player_death_hook is not None
)


PLAYER_PERK_TICK_STEPS: tuple[PlayerPerkTickStep, ...] = tuple(
    step for hook in PERK_HOOKS_IN_ORDER for step in hook.player_tick_steps
)


PERKS_UPDATE_EFFECT_STEPS: tuple[PerksUpdateEffectsStep, ...] = (update_player_bonus_timers,) + tuple(
    step for hook in PERK_HOOKS_IN_ORDER for step in hook.effects_steps
)
