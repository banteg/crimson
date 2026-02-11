from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from grim.geom import Vec2

from ..effects import FxQueue
from ..sim.state_types import GameplayState, PlayerState
from .helpers import perk_active, perk_count_get
from .ids import PerkId


class _CreatureForPerks(Protocol):
    active: bool
    pos: Vec2
    hp: float
    hitbox_size: float
    collision_timer: float
    reward_value: float
    size: float


def _creature_find_in_radius(creatures: Sequence[_CreatureForPerks], *, pos: Vec2, radius: float, start_index: int) -> int:
    """Port of `creature_find_in_radius` (0x004206a0)."""

    start_index = max(0, int(start_index))
    max_index = min(len(creatures), 0x180)
    if start_index >= max_index:
        return -1

    radius = float(radius)

    for idx in range(start_index, max_index):
        creature = creatures[idx]
        if not creature.active:
            continue

        dist = (creature.pos - pos).length() - radius
        threshold = float(creature.size) * 0.14285715 + 3.0
        if threshold < dist:
            continue
        if float(creature.hitbox_size) < 5.0:
            continue
        return idx
    return -1


@dataclass(slots=True)
class _PerksUpdateEffectsCtx:
    state: GameplayState
    players: list[PlayerState]
    dt: float
    creatures: Sequence[_CreatureForPerks] | None
    fx_queue: FxQueue | None
    _aim_target: int | None = None

    def aim_target(self) -> int:
        if self._aim_target is not None:
            return int(self._aim_target)

        target = -1
        if (
            self.players
            and self.creatures is not None
            and (perk_active(self.players[0], PerkId.PYROKINETIC) or perk_active(self.players[0], PerkId.EVIL_EYES))
        ):
            target = _creature_find_in_radius(
                self.creatures,
                pos=self.players[0].aim,
                radius=12.0,
                start_index=0,
            )
        self._aim_target = int(target)
        return int(target)


_PerksUpdateEffectsStep = Callable[[_PerksUpdateEffectsCtx], None]


def _perks_update_regeneration(ctx: _PerksUpdateEffectsCtx) -> None:
    if ctx.players and perk_active(ctx.players[0], PerkId.REGENERATION) and (ctx.state.rng.rand() & 1):
        for player in ctx.players:
            if not (0.0 < float(player.health) < 100.0):
                continue
            player.health = float(player.health) + ctx.dt
            if player.health > 100.0:
                player.health = 100.0


def _perks_update_lean_mean_exp_machine(ctx: _PerksUpdateEffectsCtx) -> None:
    ctx.state.lean_mean_exp_timer -= ctx.dt
    if ctx.state.lean_mean_exp_timer < 0.0:
        ctx.state.lean_mean_exp_timer = 0.25
        if not ctx.players:
            return

        # Native `perks_update_effects` uses global `perk_count_get` and awards the
        # periodic XP tick only to player 0 (`player_experience[0]`).
        player0 = ctx.players[0]
        perk_count = perk_count_get(player0, PerkId.LEAN_MEAN_EXP_MACHINE)
        if perk_count > 0:
            player0.experience += perk_count * 10


def _perks_update_death_clock(ctx: _PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return
    if not perk_active(ctx.players[0], PerkId.DEATH_CLOCK):
        return

    # Native gates this effect on shared/player-0 perk state, then applies health
    # drain to every active local player.
    for player in ctx.players:
        if float(player.health) <= 0.0:
            player.health = 0.0
        else:
            player.health = float(player.health) - ctx.dt * 3.3333333


def _perks_update_evil_eyes_target(ctx: _PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return

    target = ctx.aim_target()
    player0 = ctx.players[0]
    player0.evil_eyes_target_creature = target if perk_active(player0, PerkId.EVIL_EYES) else -1


def _perks_update_pyrokinetic(ctx: _PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return
    if ctx.creatures is None:
        return
    if not perk_active(ctx.players[0], PerkId.PYROKINETIC):
        return

    target = ctx.aim_target()
    if target == -1:
        return
    creature = ctx.creatures[target]
    creature.collision_timer = float(creature.collision_timer) - float(ctx.dt)
    if creature.collision_timer < 0.0:
        creature.collision_timer = 0.5
        for intensity in (0.8, 0.6, 0.4, 0.3, 0.2):
            angle = float(int(ctx.state.rng.rand()) % 0x274) * 0.01
            ctx.state.particles.spawn_particle(pos=creature.pos, angle=angle, intensity=float(intensity))
        if ctx.fx_queue is not None:
            ctx.fx_queue.add_random(pos=creature.pos, rand=ctx.state.rng.rand)


def _perks_update_jinxed_timer(ctx: _PerksUpdateEffectsCtx) -> None:
    if ctx.state.jinxed_timer >= 0.0:
        ctx.state.jinxed_timer -= ctx.dt


def _perks_update_jinxed(ctx: _PerksUpdateEffectsCtx) -> None:
    if ctx.state.jinxed_timer >= 0.0:
        return
    if not ctx.players:
        return
    if not perk_active(ctx.players[0], PerkId.JINXED):
        return

    player = ctx.players[0]
    if int(ctx.state.rng.rand()) % 10 == 3:
        player.health = float(player.health) - 5.0
        if ctx.fx_queue is not None:
            ctx.fx_queue.add_random(pos=player.pos, rand=ctx.state.rng.rand)
            ctx.fx_queue.add_random(pos=player.pos, rand=ctx.state.rng.rand)

    ctx.state.jinxed_timer = float(int(ctx.state.rng.rand()) % 0x14) * 0.1 + float(ctx.state.jinxed_timer) + 2.0

    if float(ctx.state.bonuses.freeze) <= 0.0 and ctx.creatures is not None:
        pool_mod = min(0x17F, len(ctx.creatures))
        if pool_mod <= 0:
            return

        idx = int(ctx.state.rng.rand()) % pool_mod
        attempts = 0
        while attempts < 10 and not ctx.creatures[idx].active:
            idx = int(ctx.state.rng.rand()) % pool_mod
            attempts += 1
        if not ctx.creatures[idx].active:
            return

        creature = ctx.creatures[idx]
        creature.hp = -1.0
        creature.hitbox_size = float(creature.hitbox_size) - ctx.dt * 20.0
        player.experience = int(float(player.experience) + float(creature.reward_value))
        ctx.state.sfx_queue.append("sfx_trooper_inpain_01")


def _perks_update_player_bonus_timers(ctx: _PerksUpdateEffectsCtx) -> None:
    # Native `perks_update_effects` decrements per-player shield/fire-bullets/speed
    # timers before `player_update` reads them for this frame.
    for player in ctx.players:
        if player.shield_timer <= 0.0:
            player.shield_timer = 0.0
        else:
            player.shield_timer = float(player.shield_timer) - float(ctx.dt)

        if player.fire_bullets_timer <= 0.0:
            player.fire_bullets_timer = 0.0
        else:
            player.fire_bullets_timer = float(player.fire_bullets_timer) - float(ctx.dt)

        if player.speed_bonus_timer <= 0.0:
            player.speed_bonus_timer = 0.0
        else:
            player.speed_bonus_timer = float(player.speed_bonus_timer) - float(ctx.dt)


_PERKS_UPDATE_EFFECT_STEPS: tuple[_PerksUpdateEffectsStep, ...] = (
    _perks_update_player_bonus_timers,
    _perks_update_regeneration,
    _perks_update_lean_mean_exp_machine,
    _perks_update_death_clock,
    _perks_update_evil_eyes_target,
    _perks_update_pyrokinetic,
    _perks_update_jinxed_timer,
    _perks_update_jinxed,
)


def perks_update_effects(
    state: GameplayState,
    players: list[PlayerState],
    dt: float,
    *,
    creatures: Sequence[_CreatureForPerks] | None = None,
    fx_queue: FxQueue | None = None,
) -> None:
    """Port subset of `perks_update_effects` (0x00406b40)."""

    dt = float(dt)
    if dt <= 0.0:
        return
    ctx = _PerksUpdateEffectsCtx(
        state=state,
        players=players,
        dt=dt,
        creatures=creatures,
        fx_queue=fx_queue,
    )
    for step in _PERKS_UPDATE_EFFECT_STEPS:
        step(ctx)
