from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from grim.geom import Vec2
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ...creatures.damage_types import CreatureDamageType
from ...effects import FxQueue
from ...math_parity import x87_pc24_hypot, x87_pc24_mul, x87_pc24_sub
from ...owner_ref import OwnerRef
from ...sim.state_types import PlayerState
from ..ids import PerkId

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ...creatures.runtime import CreatureDeath, CreaturePool


def apply_final_revenge_on_player_death(
    *,
    state: GameplayState,
    creatures: CreaturePool,
    players: list[PlayerState],
    player: PlayerState,
    dt: float,
    detail_preset: int,
    fx_queue: FxQueue | None,
    deaths: list[CreatureDeath],
) -> None:
    """Apply Final Revenge perk behavior when a player dies."""
    from ...creatures.damage import creature_apply_damage_with_lethal_followup

    if PerkId.FINAL_REVENGE not in state.perks:
        return

    player_pos = player.pos
    state.effects.spawn_explosion_burst(
        pos=player_pos,
        scale=1.8,
        rng=state.rng,
        detail_preset=int(detail_preset),
    )

    state.bonus_spawn_guard = True
    on_lethal = partial(
        creatures.record_death,
        state=state,
        players=players,
        rng=state.rng,
        dt=float(dt),
        detail_preset=int(detail_preset),
        fx_queue=fx_queue,
        deaths=deaths,
        sfx=state.sfx_queue,
    )
    for creature_idx, creature in enumerate(creatures.entries):
        if not creature.active:
            continue

        dx = x87_pc24_sub(creature.pos.x, player_pos.x)
        dy = x87_pc24_sub(creature.pos.y, player_pos.y)
        if abs(dx) > 512.0 or abs(dy) > 512.0:
            continue

        remaining = x87_pc24_sub(512.0, x87_pc24_hypot(dx, dy))
        if remaining <= 0.0:
            continue

        damage = x87_pc24_mul(remaining, 5.0)
        creature_apply_damage_with_lethal_followup(
            creature,
            creature_index=int(creature_idx),
            damage_amount=damage,
            damage_type=CreatureDamageType.EXPLOSION,
            impulse=Vec2(),
            owner=OwnerRef.from_player(int(player.index)),
            dt=float(dt),
            players=players,
            perks=state.perks,
            rng=state.rng,
            preserve_bugs=bool(state.preserve_bugs),
            effects=state.effects,
            detail_preset=int(detail_preset),
            on_lethal=on_lethal,
        )

    state.bonus_spawn_guard = False
    state.sfx_queue.append(SfxRequest(SfxId.EXPLOSION_LARGE, player.pos))
    state.sfx_queue.append(SfxRequest(SfxId.SHOCKWAVE, player.pos))
