from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from ..sim.state_types import GameplayState, PlayerState
from ..weapons import WeaponId
from .helpers import perk_count_get
from .ids import PerkId
from .state import CreatureForPerks, PerkSelectionState


def _increment_perk_count(player: PlayerState, perk_id: PerkId, *, amount: int = 1) -> None:
    idx = int(perk_id)
    if 0 <= idx < len(player.perk_counts):
        player.perk_counts[idx] += int(amount)


@dataclass(slots=True)
class _PerkApplyCtx:
    state: GameplayState
    players: list[PlayerState]
    owner: PlayerState
    perk_id: PerkId
    perk_state: PerkSelectionState | None
    dt: float | None
    creatures: Sequence[CreatureForPerks] | None

    def frame_dt(self) -> float:
        return float(self.dt) if self.dt is not None else 0.0


_PerkApplyHandler = Callable[[_PerkApplyCtx], None]


def _perk_apply_instant_winner(ctx: _PerkApplyCtx) -> None:
    ctx.owner.experience += 2500


def _perk_apply_fatal_lottery(ctx: _PerkApplyCtx) -> None:
    if ctx.state.rng.rand() & 1:
        ctx.owner.health = -1.0
    else:
        ctx.owner.experience += 10000


def _perk_apply_random_weapon(ctx: _PerkApplyCtx) -> None:
    from ..gameplay import weapon_assign_player, weapon_pick_random_available

    current = int(ctx.owner.weapon_id)
    weapon_id = int(current)
    for _ in range(100):
        candidate = int(weapon_pick_random_available(ctx.state))
        weapon_id = candidate
        if candidate != int(WeaponId.PISTOL) and candidate != current:
            break
    weapon_assign_player(ctx.owner, weapon_id, state=ctx.state)


def _perk_apply_lifeline_50_50(ctx: _PerkApplyCtx) -> None:
    creatures = ctx.creatures
    if creatures is None:
        return

    kill_toggle = False
    for creature in creatures:
        if kill_toggle and creature.active and float(creature.hp) <= 500.0 and (int(creature.flags) & 0x04) == 0:
            creature.active = False
            ctx.state.effects.spawn_burst(
                pos=creature.pos,
                count=4,
                rand=ctx.state.rng.rand,
                detail_preset=5,
            )
        kill_toggle = not kill_toggle


def _perk_apply_thick_skinned(ctx: _PerkApplyCtx) -> None:
    for player in ctx.players:
        if player.health > 0.0:
            player.health = max(1.0, player.health * (2.0 / 3.0))


def _perk_apply_breathing_room(ctx: _PerkApplyCtx) -> None:
    for player in ctx.players:
        player.health -= player.health * (2.0 / 3.0)

    frame_dt = ctx.frame_dt()
    creatures = ctx.creatures
    if creatures is not None:
        for creature in creatures:
            if creature.active:
                creature.hitbox_size = float(creature.hitbox_size) - frame_dt

    ctx.state.bonus_spawn_guard = False


def _perk_apply_infernal_contract(ctx: _PerkApplyCtx) -> None:
    ctx.owner.level += 3
    if ctx.perk_state is not None:
        ctx.perk_state.pending_count += 3
        ctx.perk_state.choices_dirty = True
    for player in ctx.players:
        if player.health > 0.0:
            player.health = 0.1


def _perk_apply_grim_deal(ctx: _PerkApplyCtx) -> None:
    ctx.owner.health = -1.0
    ctx.owner.experience += int(ctx.owner.experience * 0.18)


def _perk_apply_ammo_maniac(ctx: _PerkApplyCtx) -> None:
    from ..gameplay import weapon_assign_player

    if len(ctx.players) > 1:
        for player in ctx.players[1:]:
            player.perk_counts[:] = ctx.owner.perk_counts
    for player in ctx.players:
        weapon_assign_player(player, int(player.weapon_id), state=ctx.state)


def _perk_apply_death_clock(ctx: _PerkApplyCtx) -> None:
    _increment_perk_count(
        ctx.owner,
        PerkId.REGENERATION,
        amount=-perk_count_get(ctx.owner, PerkId.REGENERATION),
    )
    _increment_perk_count(
        ctx.owner,
        PerkId.GREATER_REGENERATION,
        amount=-perk_count_get(ctx.owner, PerkId.GREATER_REGENERATION),
    )
    for player in ctx.players:
        if player.health > 0.0:
            player.health = 100.0


def _perk_apply_bandage(ctx: _PerkApplyCtx) -> None:
    for player in ctx.players:
        if player.health > 0.0:
            scale = float(ctx.state.rng.rand() % 50 + 1)
            player.health = min(100.0, player.health * scale)
            ctx.state.effects.spawn_burst(
                pos=player.pos,
                count=8,
                rand=ctx.state.rng.rand,
                detail_preset=5,
            )


def _perk_apply_my_favourite_weapon(ctx: _PerkApplyCtx) -> None:
    for player in ctx.players:
        player.clip_size += 2


def _perk_apply_plaguebearer(ctx: _PerkApplyCtx) -> None:
    for player in ctx.players:
        player.plaguebearer_active = True


_PERK_APPLY_HANDLERS: dict[PerkId, _PerkApplyHandler] = {
    PerkId.INSTANT_WINNER: _perk_apply_instant_winner,
    PerkId.FATAL_LOTTERY: _perk_apply_fatal_lottery,
    PerkId.RANDOM_WEAPON: _perk_apply_random_weapon,
    PerkId.LIFELINE_50_50: _perk_apply_lifeline_50_50,
    PerkId.THICK_SKINNED: _perk_apply_thick_skinned,
    PerkId.BREATHING_ROOM: _perk_apply_breathing_room,
    PerkId.INFERNAL_CONTRACT: _perk_apply_infernal_contract,
    PerkId.GRIM_DEAL: _perk_apply_grim_deal,
    PerkId.AMMO_MANIAC: _perk_apply_ammo_maniac,
    PerkId.DEATH_CLOCK: _perk_apply_death_clock,
    PerkId.BANDAGE: _perk_apply_bandage,
    PerkId.MY_FAVOURITE_WEAPON: _perk_apply_my_favourite_weapon,
    PerkId.PLAGUEBEARER: _perk_apply_plaguebearer,
}


def perk_apply(
    state: GameplayState,
    players: list[PlayerState],
    perk_id: PerkId,
    *,
    perk_state: PerkSelectionState | None = None,
    dt: float | None = None,
    creatures: Sequence[CreatureForPerks] | None = None,
) -> None:
    """Apply immediate perk effects and increment the perk counter."""

    if not players:
        return
    owner = players[0]
    try:
        _increment_perk_count(owner, perk_id)
        handler = _PERK_APPLY_HANDLERS.get(perk_id)
        if handler is not None:
            handler(
                _PerkApplyCtx(
                    state=state,
                    players=players,
                    owner=owner,
                    perk_id=perk_id,
                    perk_state=perk_state,
                    dt=dt,
                    creatures=creatures,
                )
            )
    finally:
        if len(players) > 1:
            for player in players[1:]:
                player.perk_counts[:] = owner.perk_counts
