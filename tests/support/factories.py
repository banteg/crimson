from __future__ import annotations

from collections.abc import Sequence

import msgspec

from crimson.creatures.damage_runtime import CreatureDamageRuntime, DirectCreatureDamageRuntime
from crimson.creatures.runtime import CreatureState, CreatureUpdateOptions
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId, SpawnEnv
from crimson.effects import FxQueue, FxQueueRotated
from crimson.owner_ref import OwnerRef
from crimson.projectiles.runtime import ProjectileHitRuntime, ProjectileUpdateOptions
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.rand import CrandLike


def make_creature_state(
    *,
    pos: Vec2,
    hp: float = 100.0,
    active: bool = True,
    lifecycle_stage: float = 16.0,
    size: float = 50.0,
    flags: CreatureFlags = CreatureFlags(0),
    plague_infected: bool = False,
    max_hp: float | None = None,
    type_id: CreatureTypeId = CreatureTypeId.ZOMBIE,
) -> CreatureState:
    hp_value = float(hp)
    return CreatureState(
        active=bool(active),
        type_id=type_id,
        pos=pos,
        hp=hp_value,
        max_hp=hp_value if max_hp is None else float(max_hp),
        lifecycle_stage=float(lifecycle_stage),
        size=float(size),
        flags=flags,
        plague_infected=bool(plague_infected),
    )


def make_creature_update_options(
    *,
    state: GameplayState,
    players: list[PlayerState],
    rng: CrandLike | None = None,
    detail_preset: int = 5,
    violence_disabled: int = 0,
    env: SpawnEnv | None = None,
    world_width: float = 1024.0,
    world_height: float = 1024.0,
    fx_queue: FxQueue | None = None,
    fx_queue_rotated: FxQueueRotated | None = None,
    quest_fail_retry_count: int = 0,
) -> CreatureUpdateOptions:
    width = float(world_width)
    height = float(world_height)
    default_env = SpawnEnv(
        terrain_width=width,
        terrain_height=height,
        demo_mode_active=bool(state.demo_mode_active),
        hardcore=bool(state.hardcore),
        quest_fail_retry_count=int(quest_fail_retry_count),
    )
    return CreatureUpdateOptions(
        state=state,
        players=players,
        rng=state.rng if rng is None else rng,
        env=default_env if env is None else env,
        world_width=width,
        world_height=height,
        fx_queue=FxQueue() if fx_queue is None else fx_queue,
        fx_queue_rotated=FxQueueRotated() if fx_queue_rotated is None else fx_queue_rotated,
        detail_preset=int(detail_preset),
        violence_disabled=int(violence_disabled),
    )


class RecordingProjectileHitRuntime(ProjectileHitRuntime):
    players: Sequence[PlayerState] = ()
    player_damage_calls: list[tuple[int, float]] = msgspec.field(default_factory=list)

    def apply_player_damage(self, player_index: int, damage: float) -> None:
        idx = int(player_index)
        damage_value = float(damage)
        self.player_damage_calls.append((idx, damage_value))
        if not (0 <= idx < len(self.players)):
            return
        player = self.players[idx]
        if float(player.shield_timer) <= 0.0:
            player.health -= damage_value


class RecordingCreatureDamageRuntime(DirectCreatureDamageRuntime):
    calls: list[tuple[int, float, int, Vec2, OwnerRef]] = msgspec.field(default_factory=list)
    kills: list[tuple[int, OwnerRef]] = msgspec.field(default_factory=list)
    detonation_kills: list[int] = msgspec.field(default_factory=list)
    apply_damage: bool = True

    def apply_creature_damage(
        self,
        creature_index: int,
        damage: float,
        damage_type: int,
        impulse: Vec2,
        owner: OwnerRef,
    ) -> None:
        _ = owner
        idx = int(creature_index)
        damage_value = float(damage)
        self.calls.append((idx, damage_value, int(damage_type), impulse, owner))
        if not bool(self.apply_damage):
            return
        super().apply_creature_damage(
            idx,
            damage_value,
            int(damage_type),
            impulse,
            owner,
        )

    def kill_creature_no_corpse(self, creature_index: int, owner: OwnerRef) -> None:
        self.kills.append((int(creature_index), owner))
        super().kill_creature_no_corpse(creature_index, owner)

    def on_secondary_detonation_kill(self, creature_index: int) -> None:
        self.detonation_kills.append(int(creature_index))


def make_projectile_update_options(
    *,
    world_size: float = 1024.0,
    damage_scale_by_type: dict[int, float] | None = None,
    ion_aoe_scale: float = 1.0,
    detail_preset: int = 5,
    rng: CrandLike | None = None,
    runtime_state: GameplayState | None = None,
    players: Sequence[PlayerState] | None = None,
    hit_runtime: ProjectileHitRuntime | None = None,
    creature_damage_runtime: CreatureDamageRuntime | None = None,
) -> ProjectileUpdateOptions:
    state = GameplayState() if runtime_state is None else runtime_state
    player_seq: Sequence[PlayerState] = () if players is None else players
    return ProjectileUpdateOptions(
        world_size=float(world_size),
        damage_scale_by_type={} if damage_scale_by_type is None else damage_scale_by_type,
        rng=state.rng if rng is None else rng,
        runtime_state=state,
        players=player_seq,
        hit_runtime=RecordingProjectileHitRuntime(players=player_seq) if hit_runtime is None else hit_runtime,
        creature_damage_runtime=creature_damage_runtime,
        ion_aoe_scale=float(ion_aoe_scale),
        detail_preset=int(detail_preset),
    )
