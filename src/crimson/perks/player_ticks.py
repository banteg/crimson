from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable

from grim.color import RGBA
from grim.geom import Vec2

from ..projectiles import ProjectileTypeId
from ..sim.state_types import GameplayState, PlayerState
from .helpers import perk_active
from .ids import PerkId

_ProjectileSpawnFn = Callable[..., int]
_OwnerIdForPlayerFn = Callable[[int], int]
_OwnerIdForPlayerProjectilesFn = Callable[[GameplayState, int], int]


def _perk_update_man_bomb(
    player: PlayerState,
    dt: float,
    state: GameplayState,
    *,
    players: list[PlayerState] | None,
    owner_id_for_player_projectiles: _OwnerIdForPlayerProjectilesFn,
    projectile_spawn: _ProjectileSpawnFn,
) -> None:
    player.man_bomb_timer += dt
    if player.man_bomb_timer <= state.perk_intervals.man_bomb:
        return

    owner_id = owner_id_for_player_projectiles(state, player.index)
    for idx in range(8):
        type_id = ProjectileTypeId.ION_MINIGUN if ((idx & 1) == 0) else ProjectileTypeId.ION_RIFLE
        angle = (float(state.rng.rand() % 50) * 0.01) + float(idx) * (math.pi / 4.0) - 0.25
        projectile_spawn(
            state,
            players=players,
            pos=player.pos,
            angle=angle,
            type_id=type_id,
            owner_id=owner_id,
        )
    state.sfx_queue.append("sfx_explosion_small")

    player.man_bomb_timer -= state.perk_intervals.man_bomb
    state.perk_intervals.man_bomb = 4.0


def _perk_update_hot_tempered(
    player: PlayerState,
    dt: float,
    state: GameplayState,
    *,
    players: list[PlayerState] | None,
    owner_id_for_player: _OwnerIdForPlayerFn,
    projectile_spawn: _ProjectileSpawnFn,
) -> None:
    player.hot_tempered_timer += dt
    if player.hot_tempered_timer <= state.perk_intervals.hot_tempered:
        return

    owner_id = owner_id_for_player(player.index) if state.friendly_fire_enabled else -100
    for idx in range(8):
        type_id = ProjectileTypeId.PLASMA_MINIGUN if ((idx & 1) == 0) else ProjectileTypeId.PLASMA_RIFLE
        angle = float(idx) * (math.pi / 4.0)
        projectile_spawn(
            state,
            players=players,
            pos=player.pos,
            angle=angle,
            type_id=type_id,
            owner_id=owner_id,
        )
    state.sfx_queue.append("sfx_explosion_small")

    player.hot_tempered_timer -= state.perk_intervals.hot_tempered
    state.perk_intervals.hot_tempered = float(state.rng.rand() % 8) + 2.0


def _perk_update_fire_cough(
    player: PlayerState,
    dt: float,
    state: GameplayState,
    *,
    owner_id_for_player_projectiles: _OwnerIdForPlayerProjectilesFn,
    projectile_spawn: _ProjectileSpawnFn,
) -> None:
    player.fire_cough_timer += dt
    if player.fire_cough_timer <= state.perk_intervals.fire_cough:
        return

    owner_id = owner_id_for_player_projectiles(state, player.index)
    state.sfx_queue.append("sfx_autorifle_fire")
    state.sfx_queue.append("sfx_plasmaminigun_fire")

    aim_heading = float(player.aim_heading)
    muzzle = player.pos + Vec2.from_heading(aim_heading).rotated(-0.150915) * 16.0

    aim = player.aim
    dist = (aim - player.pos).length()
    max_offset = dist * float(player.spread_heat) * 0.5
    dir_angle = float(int(state.rng.rand()) & 0x1FF) * (math.tau / 512.0)
    mag = float(int(state.rng.rand()) & 0x1FF) * (1.0 / 512.0)
    offset = max_offset * mag
    jitter = aim + Vec2.from_angle(dir_angle) * offset
    angle = (jitter - player.pos).to_heading()
    projectile_spawn(
        state,
        players=[player],
        pos=muzzle,
        angle=angle,
        type_id=ProjectileTypeId.FIRE_BULLETS,
        owner_id=owner_id,
    )

    vel = Vec2.from_angle(aim_heading) * 25.0
    state.sprite_effects.spawn(pos=muzzle, vel=vel, scale=1.0, color=RGBA(0.5, 0.5, 0.5, 0.413))

    player.fire_cough_timer -= state.perk_intervals.fire_cough
    state.perk_intervals.fire_cough = float(state.rng.rand() % 4) + 2.0


@dataclass(slots=True)
class _PlayerPerkTickCtx:
    state: GameplayState
    player: PlayerState
    players: list[PlayerState] | None
    dt: float
    stationary: bool
    owner_id_for_player: _OwnerIdForPlayerFn
    owner_id_for_player_projectiles: _OwnerIdForPlayerProjectilesFn
    projectile_spawn: _ProjectileSpawnFn


_PlayerPerkTickStep = Callable[[_PlayerPerkTickCtx], None]


def _player_perk_tick_man_bomb(ctx: _PlayerPerkTickCtx) -> None:
    if ctx.stationary and perk_active(ctx.player, PerkId.MAN_BOMB):
        _perk_update_man_bomb(
            ctx.player,
            ctx.dt,
            ctx.state,
            players=ctx.players,
            owner_id_for_player_projectiles=ctx.owner_id_for_player_projectiles,
            projectile_spawn=ctx.projectile_spawn,
        )
    else:
        ctx.player.man_bomb_timer = 0.0


def _player_perk_tick_living_fortress(ctx: _PlayerPerkTickCtx) -> None:
    if ctx.stationary and perk_active(ctx.player, PerkId.LIVING_FORTRESS):
        ctx.player.living_fortress_timer = min(30.0, ctx.player.living_fortress_timer + ctx.dt)
    else:
        ctx.player.living_fortress_timer = 0.0


def _player_perk_tick_fire_cough(ctx: _PlayerPerkTickCtx) -> None:
    if perk_active(ctx.player, PerkId.FIRE_CAUGH):
        _perk_update_fire_cough(
            ctx.player,
            ctx.dt,
            ctx.state,
            owner_id_for_player_projectiles=ctx.owner_id_for_player_projectiles,
            projectile_spawn=ctx.projectile_spawn,
        )
    else:
        ctx.player.fire_cough_timer = 0.0


def _player_perk_tick_hot_tempered(ctx: _PlayerPerkTickCtx) -> None:
    if perk_active(ctx.player, PerkId.HOT_TEMPERED):
        _perk_update_hot_tempered(
            ctx.player,
            ctx.dt,
            ctx.state,
            players=ctx.players,
            owner_id_for_player=ctx.owner_id_for_player,
            projectile_spawn=ctx.projectile_spawn,
        )
    else:
        ctx.player.hot_tempered_timer = 0.0


_PLAYER_PERK_TICK_STEPS: tuple[_PlayerPerkTickStep, ...] = (
    _player_perk_tick_man_bomb,
    _player_perk_tick_living_fortress,
    _player_perk_tick_fire_cough,
    _player_perk_tick_hot_tempered,
)


def apply_player_perk_ticks(
    *,
    player: PlayerState,
    dt: float,
    state: GameplayState,
    players: list[PlayerState] | None,
    stationary: bool,
    owner_id_for_player: _OwnerIdForPlayerFn,
    owner_id_for_player_projectiles: _OwnerIdForPlayerProjectilesFn,
    projectile_spawn: _ProjectileSpawnFn,
) -> None:
    ctx = _PlayerPerkTickCtx(
        state=state,
        player=player,
        players=players,
        dt=dt,
        stationary=stationary,
        owner_id_for_player=owner_id_for_player,
        owner_id_for_player_projectiles=owner_id_for_player_projectiles,
        projectile_spawn=projectile_spawn,
    )
    for step in _PLAYER_PERK_TICK_STEPS:
        step(ctx)
