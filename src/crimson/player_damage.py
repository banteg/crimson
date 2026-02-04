from __future__ import annotations

"""Player damage intake helpers.

This is a minimal, rewrite-focused port of `player_take_damage` (0x00425e50).
See: `docs/crimsonland-exe/player-damage.md`.
"""

from dataclasses import dataclass
from typing import Callable

from .gameplay import GameplayState, PlayerState, perk_active
from .perks import PerkId

__all__ = ["player_take_damage", "player_take_projectile_damage"]


@dataclass(slots=True)
class _PlayerDamageCtx:
    state: GameplayState
    player: PlayerState
    dmg: float
    dt: float | None
    rng: Callable[[], int]


_PlayerDamagePreStep = Callable[[_PlayerDamageCtx], bool]


def _player_damage_gate_death_clock(ctx: _PlayerDamageCtx) -> bool:
    return perk_active(ctx.player, PerkId.DEATH_CLOCK)


def _player_damage_scale_tough_reloader(ctx: _PlayerDamageCtx) -> bool:
    if perk_active(ctx.player, PerkId.TOUGH_RELOADER) and bool(ctx.player.reload_active):
        ctx.dmg *= 0.5
    return False


def _player_damage_gate_shield(ctx: _PlayerDamageCtx) -> bool:
    return float(ctx.player.shield_timer) > 0.0


def _player_damage_scale_thick_skinned(ctx: _PlayerDamageCtx) -> bool:
    if perk_active(ctx.player, PerkId.THICK_SKINNED):
        ctx.dmg *= 2.0 / 3.0
    return False


def _player_damage_gate_dodge(ctx: _PlayerDamageCtx) -> bool:
    if perk_active(ctx.player, PerkId.NINJA):
        return (ctx.rng() % 3) == 0
    if perk_active(ctx.player, PerkId.DODGER):
        return (ctx.rng() % 5) == 0
    return False


_PLAYER_DAMAGE_PRE_STEPS: tuple[_PlayerDamagePreStep, ...] = (
    _player_damage_gate_death_clock,
    _player_damage_scale_tough_reloader,
    _player_damage_gate_shield,
    _player_damage_scale_thick_skinned,
    _player_damage_gate_dodge,
)


def _player_damage_apply_health(ctx: _PlayerDamageCtx) -> None:
    if perk_active(ctx.player, PerkId.HIGHLANDER):
        if (ctx.rng() % 10) == 0:
            ctx.player.health = 0.0
    else:
        ctx.player.health -= ctx.dmg
        if ctx.player.health < 0.0 and ctx.dt is not None and float(ctx.dt) > 0.0:
            ctx.player.death_timer -= float(ctx.dt) * 28.0


_PlayerDamagePostStep = Callable[[_PlayerDamageCtx], None]


def _player_damage_post_hit_disruption(ctx: _PlayerDamageCtx) -> None:
    if perk_active(ctx.player, PerkId.UNSTOPPABLE):
        return
    # player_take_damage @ 0x00425e50: on-hit camera/spread disruption.
    ctx.player.heading += float((ctx.rng() % 100) - 50) * 0.04
    ctx.player.spread_heat = min(0.48, float(ctx.player.spread_heat) + ctx.dmg * 0.01)


def _player_damage_post_low_health_warning(ctx: _PlayerDamageCtx) -> None:
    if ctx.player.health <= 20.0 and (ctx.rng() & 7) == 3:
        ctx.player.low_health_timer = 0.0


_PLAYER_DAMAGE_POST_STEPS: tuple[_PlayerDamagePostStep, ...] = (
    _player_damage_post_hit_disruption,
    _player_damage_post_low_health_warning,
)


def player_take_damage(
    state: GameplayState,
    player: PlayerState,
    damage: float,
    *,
    dt: float | None = None,
    rand: Callable[[], int] | None = None,
) -> float:
    """Apply damage to a player, returning the actual damage applied.

    Notes:
    - This models only the must-have gates used by creature contact damage.
    - Low-health warning timers are not yet ported.
    """

    dmg = float(damage)
    if dmg <= 0.0:
        return 0.0
    if state.debug_god_mode:
        return 0.0

    ctx = _PlayerDamageCtx(
        state=state,
        player=player,
        dmg=dmg,
        dt=dt,
        rng=rand or state.rng.rand,
    )
    for step in _PLAYER_DAMAGE_PRE_STEPS:
        if step(ctx):
            return 0.0

    health_before = float(player.health)

    _player_damage_apply_health(ctx)
    for step in _PLAYER_DAMAGE_POST_STEPS:
        step(ctx)
    return max(0.0, health_before - float(player.health))


def player_take_projectile_damage(state: GameplayState, player: PlayerState, damage: float) -> float:
    """Apply projectile damage to a player (modeled after `projectile_update` player-hit logic).

    Native `projectile_update` does not call `player_take_damage` for projectile hits: it sets
    `projectile.life_timer = 0.25` and subtracts a fixed amount (usually 10.0) if shield is down.
    """

    dmg = float(damage)
    if dmg <= 0.0:
        return 0.0
    if state.debug_god_mode:
        return 0.0
    if float(player.shield_timer) > 0.0:
        return 0.0

    player.health -= dmg
    return dmg
