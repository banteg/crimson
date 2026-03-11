from __future__ import annotations

import inspect
from collections.abc import Callable, Sequence
from typing import cast

from crimson.creatures.runtime import CreatureState, CreatureUpdateOptions
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId, SpawnEnv
from crimson.effects import FxQueue, FxQueueRotated
from crimson.gameplay import GameplayState
from crimson.projectiles.runtime import ProjectileUpdateOptions
from crimson.projectiles.types import ProjectileHit
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.rand import CallerStatic


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


class _NoopFxQueue(FxQueue):
    def __init__(self) -> None:
        super().__init__(capacity=0, max_count=0)

    def add(
        self,
        *,
        effect_id: int,
        pos: Vec2,
        width: float,
        height: float,
        rotation: float,
        rgba: object,
    ) -> bool:
        del effect_id, pos, width, height, rotation, rgba
        return False

    def add_random(self, *, pos: Vec2, rand: Callable[..., int]) -> bool:
        del pos, rand
        return False


class _NoopFxQueueRotated(FxQueueRotated):
    def __init__(self) -> None:
        super().__init__(capacity=0, max_count=0)

    def add(
        self,
        *,
        top_left: Vec2,
        rgba: object,
        rotation: float,
        scale: float,
        creature_type_id: int,
        terrain_bodies_transparency: float = 0.0,
        terrain_texture_failed: bool = False,
    ) -> bool:
        del (
            top_left,
            rgba,
            rotation,
            scale,
            creature_type_id,
            terrain_bodies_transparency,
            terrain_texture_failed,
        )
        return False


def _coerce_rand_draw(rand: Callable[..., int]) -> Callable[..., int]:
    try:
        params = inspect.signature(rand).parameters.values()
    except (TypeError, ValueError):
        params = ()

    for param in params:
        if param.kind == inspect.Parameter.VAR_KEYWORD:
            return rand
        if param.name == "caller":
            return rand

    def _draw(*, caller: CallerStatic = None) -> int:
        _ = caller
        return int(rand())

    return _draw


def make_creature_update_options(
    *,
    state: GameplayState,
    players: list[PlayerState],
    rand: Callable[..., int] | None = None,
    detail_preset: int = 5,
    gore_disabled: int = 0,
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
        rand=_coerce_rand_draw(state.rng.rand if rand is None else rand),
        env=default_env if env is None else env,
        world_width=width,
        world_height=height,
        fx_queue=cast(FxQueue, _NoopFxQueue()) if fx_queue is None else fx_queue,
        fx_queue_rotated=cast(FxQueueRotated, _NoopFxQueueRotated()) if fx_queue_rotated is None else fx_queue_rotated,
        detail_preset=int(detail_preset),
        gore_disabled=int(gore_disabled),
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
    rng: Callable[..., int] | None = None,
    runtime_state: GameplayState | None = None,
    players: Sequence[PlayerState] | None = None,
    apply_player_damage: Callable[[int, float], None] | None = None,
    on_hit: Callable[[ProjectileHit], object] | None = None,
    on_hit_post: Callable[[ProjectileHit, object], None] | None = None,
) -> ProjectileUpdateOptions:
    state = GameplayState() if runtime_state is None else runtime_state
    player_seq: Sequence[PlayerState] = () if players is None else players
    return ProjectileUpdateOptions(
        world_size=float(world_size),
        damage_scale_by_type={} if damage_scale_by_type is None else damage_scale_by_type,
        rng=_coerce_rand_draw((lambda *, caller=None: 0) if rng is None else rng),
        runtime_state=state,
        players=player_seq,
        apply_player_damage=(
            _default_apply_player_damage(player_seq) if apply_player_damage is None else apply_player_damage
        ),
        ion_aoe_scale=float(ion_aoe_scale),
        detail_preset=int(detail_preset),
        on_hit=on_hit,
        on_hit_post=on_hit_post,
    )
