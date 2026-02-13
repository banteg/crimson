from __future__ import annotations

from typing import Sequence

from ..math_parity import f32
from ..perks.helpers import perk_active
from ..projectiles import CreatureDamageApplier, Damageable
from ..sim.state_types import BonusPickupEvent, GameplayState, PlayerState
from .apply import bonus_apply
from .hud import bonus_hud_update
from .ids import BonusId
from .pool import BONUS_PICKUP_LINGER, BONUS_TELEKINETIC_PICKUP_MS, bonus_find_aim_hover_entry

_REFLEX_TIMER_SUBTRACT_BIAS = 4e-9


def bonus_telekinetic_update(
    state: GameplayState,
    players: list[PlayerState],
    dt: float,
    *,
    creatures: Sequence[Damageable] | None = None,
    apply_creature_damage: CreatureDamageApplier | None = None,
    detail_preset: int = 5,
    defer_freeze_corpse_fx: bool = False,
    freeze_corpse_indices: set[int] | None = None,
) -> list[BonusPickupEvent]:
    """Allow Telekinetic perk owners to pick up bonuses by aiming at them."""
    from ..perks import PerkId

    if dt <= 0.0:
        return []

    pickups: list[BonusPickupEvent] = []
    dt_ms = float(dt) * 1000.0

    for player in players:
        if player.health <= 0.0:
            continue

        hovered = bonus_find_aim_hover_entry(player, state.bonus_pool)
        if hovered is None:
            player.bonus_aim_hover_index = -1
            player.bonus_aim_hover_timer_ms = 0.0
            continue

        idx, entry = hovered
        player.bonus_aim_hover_index = int(idx)
        player.bonus_aim_hover_timer_ms += dt_ms

        if player.bonus_aim_hover_timer_ms <= BONUS_TELEKINETIC_PICKUP_MS:
            continue
        if not perk_active(player, PerkId.TELEKINETIC):
            continue
        if entry.picked or entry.bonus_id == 0:
            continue

        bonus_apply(
            state,
            player,
            BonusId(int(entry.bonus_id)),
            amount=int(entry.amount),
            origin=entry,
            creatures=creatures,
            players=players,
            apply_creature_damage=apply_creature_damage,
            detail_preset=int(detail_preset),
            defer_freeze_corpse_fx=bool(defer_freeze_corpse_fx),
            freeze_corpse_indices=freeze_corpse_indices,
        )
        entry.picked = True
        entry.time_left = BONUS_PICKUP_LINGER
        pickups.append(
            BonusPickupEvent(
                player_index=int(player.index),
                bonus_id=int(entry.bonus_id),
                amount=int(entry.amount),
                pos=entry.pos,
            )
        )

        # Match the exe: after a telekinetic pickup, reset the hover accumulator.
        player.bonus_aim_hover_index = -1
        player.bonus_aim_hover_timer_ms = 0.0
        break

    return pickups


def bonus_update(
    state: GameplayState,
    players: list[PlayerState],
    dt: float,
    *,
    creatures: Sequence[Damageable] | None = None,
    update_hud: bool = True,
    apply_creature_damage: CreatureDamageApplier | None = None,
    detail_preset: int = 5,
    defer_freeze_corpse_fx: bool = False,
    freeze_corpse_indices: set[int] | None = None,
) -> list[BonusPickupEvent]:
    """Advance world bonuses and global timers (subset of `bonus_update`)."""

    pickups = bonus_telekinetic_update(
        state,
        players,
        dt,
        creatures=creatures,
        apply_creature_damage=apply_creature_damage,
        detail_preset=int(detail_preset),
        defer_freeze_corpse_fx=bool(defer_freeze_corpse_fx),
        freeze_corpse_indices=freeze_corpse_indices,
    )
    pickups.extend(
        state.bonus_pool.update(
            dt,
            state=state,
            players=players,
            creatures=creatures,
            apply_creature_damage=apply_creature_damage,
            detail_preset=int(detail_preset),
            defer_freeze_corpse_fx=bool(defer_freeze_corpse_fx),
            freeze_corpse_indices=freeze_corpse_indices,
        )
    )

    if dt > 0.0:
        # Native `bonus_update` decrements Freeze + Double XP here; other global
        # timers are advanced earlier in the gameplay loop.
        double_xp = float(state.bonuses.double_experience)
        if double_xp <= 0.0:
            state.bonuses.double_experience = 0.0
        else:
            state.bonuses.double_experience = float(f32(float(double_xp) - float(dt)))

        freeze = float(state.bonuses.freeze)
        if freeze <= 0.0:
            state.bonuses.freeze = 0.0
        else:
            state.bonuses.freeze = float(f32(float(freeze) - float(dt)))

    if update_hud:
        bonus_hud_update(state, players, dt=dt)

    return pickups


def bonus_update_pre_pickup_timers(state: GameplayState, dt: float) -> None:
    """Advance global timers that native decrements before `bonus_update`."""

    if dt <= 0.0:
        return
    if float(state.bonuses.weapon_power_up) > 0.0:
        state.bonuses.weapon_power_up = float(f32(float(state.bonuses.weapon_power_up) - float(dt)))
    if float(state.bonuses.energizer) > 0.0:
        state.bonuses.energizer = float(f32(float(state.bonuses.energizer) - float(dt)))
    if float(state.bonuses.reflex_boost) > 0.0:
        reflex_before = float(state.bonuses.reflex_boost)
        subtract = float(dt)
        if 0.0 < reflex_before < 1.0:
            # Native x87 timer math trends slightly lower than straight f32 subtraction in this window.
            subtract += float(_REFLEX_TIMER_SUBTRACT_BIAS)
        state.bonuses.reflex_boost = float(f32(float(reflex_before) - float(subtract)))
