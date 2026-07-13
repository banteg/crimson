from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from grim.geom import Vec2
from grim.sfx_map import SfxId

from ...creatures.damage_runtime import CreatureDamageRuntime
from ...creatures.damage_types import CreatureDamageType
from ...effects import FxQueue
from ...math_parity import x87_pc24_hypot, x87_pc24_mul, x87_pc24_sub
from ...owner_ref import OwnerRef
from ...sim.state_types import GameplayState, PlayerState
from ..helpers import perk_active
from ..ids import PerkId
from ..runtime.hook_types import PerkHooks

if TYPE_CHECKING:
    from ...creatures.runtime import CreatureDeath, CreaturePool


class _FinalRevengeCreatureDamageRuntime(CreatureDamageRuntime):
    state: GameplayState
    creatures: CreaturePool
    players: list[PlayerState]
    dt: float
    world_size: float
    detail_preset: int
    fx_queue: FxQueue | None
    deaths: list[CreatureDeath]

    def on_creature_lethal(
        self,
        creature_index: int,
        resolve_death_sfx: Callable[[], tuple[SfxId, ...]],
    ) -> None:
        self.deaths.append(
            self.creatures.handle_death(
                int(creature_index),
                state=self.state,
                players=self.players,
                rng=self.state.rng,
                dt=float(self.dt),
                detail_preset=int(self.detail_preset),
                world_width=float(self.world_size),
                world_height=float(self.world_size),
                fx_queue=self.fx_queue,
            ),
        )
        self.state.sfx_queue.extend(resolve_death_sfx())


def apply_final_revenge_on_player_death(
    *,
    state: GameplayState,
    creatures: CreaturePool,
    players: list[PlayerState],
    player: PlayerState,
    dt: float,
    world_size: float,
    detail_preset: int,
    fx_queue: FxQueue | None,
    deaths: list[CreatureDeath],
) -> None:
    """Apply Final Revenge perk behavior when a player dies."""
    from ...creatures.damage import creature_apply_damage_with_lethal_followup

    if not perk_active(player, PerkId.FINAL_REVENGE):
        return

    player_pos = player.pos
    state.effects.spawn_explosion_burst(
        pos=player_pos,
        scale=1.8,
        rng=state.rng,
        detail_preset=int(detail_preset),
    )

    prev_guard = bool(state.bonus_spawn_guard)
    state.bonus_spawn_guard = True
    creature_damage_runtime = _FinalRevengeCreatureDamageRuntime(
        state=state,
        creatures=creatures,
        players=players,
        dt=float(dt),
        world_size=float(world_size),
        detail_preset=int(detail_preset),
        fx_queue=fx_queue,
        deaths=deaths,
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
            rng=state.rng,
            preserve_bugs=bool(state.preserve_bugs),
            effects=state.effects,
            detail_preset=int(detail_preset),
            creature_damage_runtime=creature_damage_runtime,
        )

    state.bonus_spawn_guard = prev_guard
    state.sfx_queue.append(SfxId.EXPLOSION_LARGE)
    state.sfx_queue.append(SfxId.SHOCKWAVE)


HOOKS = PerkHooks(
    perk_id=PerkId.FINAL_REVENGE,
    player_death_hook=apply_final_revenge_on_player_death,
)
