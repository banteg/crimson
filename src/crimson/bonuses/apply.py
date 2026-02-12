from __future__ import annotations

from typing import Sequence

from ..perks import PerkId
from ..perks.helpers import perk_count_get
from ..projectiles import CreatureDamageApplier, Damageable
from ..sim.state_types import GameplayState, PlayerState
from .apply_context import BonusApplyCtx, BonusApplyHandler, HasPos
from .double_experience import apply_double_experience
from .energizer import apply_energizer
from .fire_bullets import apply_fire_bullets
from .fireblast import apply_fireblast
from .freeze import apply_freeze
from .ids import BONUS_BY_ID, BonusId
from .medikit import apply_medikit
from .nuke import apply_nuke
from .points import apply_points
from .reflex_boost import apply_reflex_boost
from .shield import apply_shield
from .shock_chain import apply_shock_chain
from .speed import apply_speed
from .weapon import apply_weapon
from .weapon_power_up import apply_weapon_power_up


_BONUS_APPLY_HANDLERS: dict[BonusId, BonusApplyHandler] = {
    BonusId.POINTS: apply_points,
    BonusId.ENERGIZER: apply_energizer,
    BonusId.WEAPON_POWER_UP: apply_weapon_power_up,
    BonusId.DOUBLE_EXPERIENCE: apply_double_experience,
    BonusId.REFLEX_BOOST: apply_reflex_boost,
    BonusId.FREEZE: apply_freeze,
    BonusId.SHIELD: apply_shield,
    BonusId.MEDIKIT: apply_medikit,
    BonusId.SPEED: apply_speed,
    BonusId.FIRE_BULLETS: apply_fire_bullets,
    BonusId.SHOCK_CHAIN: apply_shock_chain,
    BonusId.WEAPON: apply_weapon,
    BonusId.FIREBLAST: apply_fireblast,
    BonusId.NUKE: apply_nuke,
}


def bonus_apply(
    state: GameplayState,
    player: PlayerState,
    bonus_id: BonusId,
    *,
    amount: int | None = None,
    origin: HasPos | None = None,
    creatures: Sequence[Damageable] | None = None,
    players: list[PlayerState] | None = None,
    apply_creature_damage: CreatureDamageApplier | None = None,
    detail_preset: int = 5,
    defer_freeze_corpse_fx: bool = False,
    freeze_corpse_indices: set[int] | None = None,
) -> None:
    """Apply a bonus to player + global timers (subset of `bonus_apply`)."""

    meta = BONUS_BY_ID.get(int(bonus_id))
    if meta is None:
        return
    if amount is None:
        amount = int(meta.default_amount or 0)

    economist_multiplier = 1.5 if perk_count_get(player, PerkId.BONUS_ECONOMIST) != 0 else 1.0
    icon_id = int(meta.icon_id) if meta.icon_id is not None else -1
    label = meta.name
    ctx = BonusApplyCtx(
        state=state,
        player=player,
        bonus_id=bonus_id,
        amount=int(amount),
        origin=origin,
        creatures=creatures,
        players=players,
        apply_creature_damage=apply_creature_damage,
        detail_preset=int(detail_preset),
        economist_multiplier=float(economist_multiplier),
        label=str(label),
        icon_id=int(icon_id),
        defer_freeze_corpse_fx=bool(defer_freeze_corpse_fx),
        freeze_corpse_indices=freeze_corpse_indices,
    )
    handler = _BONUS_APPLY_HANDLERS.get(bonus_id)
    if handler is not None:
        handler(ctx)

    # Bonus types not modeled yet.
    return
