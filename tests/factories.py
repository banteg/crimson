from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureFlags
from grim.geom import Vec2


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
    type_id: int = 0,
) -> CreatureState:
    hp_value = float(hp)
    return CreatureState(
        active=bool(active),
        type_id=int(type_id),
        pos=pos,
        hp=hp_value,
        max_hp=hp_value if max_hp is None else float(max_hp),
        lifecycle_stage=float(lifecycle_stage),
        size=float(size),
        flags=flags,
        plague_infected=bool(plague_infected),
    )
