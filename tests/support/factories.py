from __future__ import annotations

from collections.abc import Callable, Sequence

from crimson.creatures.runtime import CreatureState, CreatureUpdateOptions
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId, SpawnEnv
from crimson.effects import FxQueue, FxQueueRotated
from crimson.gameplay import GameplayState
from crimson.projectiles.runtime import ProjectileUpdateOptions
from crimson.projectiles.types import CreatureDamageApplier, ProjectileHit
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


def _default_apply_player_damage(players: Sequence[PlayerState]) -> Callable[[int, float], None]:
    def _apply_player_damage(player_index: int, damage: float) -> None:
        idx = int(player_index)
        if not (0 <= idx < len(players)):
            return
        player = players[idx]
        if float(player.shield_timer) <= 0.0:
            player.health -= float(damage)

    return _apply_player_damage


def make_projectile_update_options(
    *,
    world_size: float = 1024.0,
    damage_scale_by_type: dict[int, float] | None = None,
    ion_aoe_scale: float = 1.0,
    detail_preset: int = 5,
    rng: CrandLike | None = None,
    runtime_state: GameplayState | None = None,
    players: Sequence[PlayerState] | None = None,
    apply_player_damage: Callable[[int, float], None] | None = None,
    apply_creature_damage: CreatureDamageApplier | None = None,
    begin_hit_presentation: Callable[[ProjectileHit], object] | None = None,
    finish_hit_presentation: Callable[[ProjectileHit, object], None] | None = None,
) -> ProjectileUpdateOptions:
    state = GameplayState() if runtime_state is None else runtime_state
    player_seq: Sequence[PlayerState] = () if players is None else players
    return ProjectileUpdateOptions(
        world_size=float(world_size),
        damage_scale_by_type={} if damage_scale_by_type is None else damage_scale_by_type,
        rng=state.rng if rng is None else rng,
        runtime_state=state,
        players=player_seq,
        apply_player_damage=(
            _default_apply_player_damage(player_seq) if apply_player_damage is None else apply_player_damage
        ),
        apply_creature_damage=apply_creature_damage,
        ion_aoe_scale=float(ion_aoe_scale),
        detail_preset=int(detail_preset),
        begin_hit_presentation=begin_hit_presentation,
        finish_hit_presentation=finish_hit_presentation,
    )
