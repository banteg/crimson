from __future__ import annotations

from collections.abc import Callable

from ..weapons import WeaponId
from .types import QuestBuilder, QuestDefinition, parse_level, terrain_ids_for

_QUESTS: dict[tuple[int, int], QuestDefinition] = {}


def register_quest(
    *,
    level: str,
    title: str,
    time_limit_ms: int,
    start_weapon_id: WeaponId,
    unlock_perk_id: int | None = None,
    unlock_weapon_id: WeaponId | None = None,
    terrain_ids: tuple[int, int, int] | None = None,
    builder_address: int | None = None,
) -> Callable[[QuestBuilder], QuestBuilder]:
    def _builder_name(builder_fn: QuestBuilder) -> str:
        return str(builder_fn.__name__)

    def decorator(builder: QuestBuilder) -> QuestBuilder:
        major, minor = parse_level(level)
        resolved_terrain_ids = terrain_ids if terrain_ids is not None else terrain_ids_for(major, minor)
        normalized_terrain_ids = (
            int(resolved_terrain_ids[0]),
            int(resolved_terrain_ids[1]),
            int(resolved_terrain_ids[2]),
        )
        normalized_unlock_weapon_id = WeaponId(unlock_weapon_id) if unlock_weapon_id is not None else None
        quest = QuestDefinition(
            major=major,
            minor=minor,
            title=title,
            builder=builder,
            time_limit_ms=time_limit_ms,
            start_weapon_id=WeaponId(start_weapon_id),
            unlock_perk_id=unlock_perk_id,
            unlock_weapon_id=normalized_unlock_weapon_id,
            terrain_ids=normalized_terrain_ids,
            builder_address=builder_address,
        )
        key = quest.level_key
        existing = _QUESTS.get(key)
        if existing is not None:
            raise ValueError(
                f"duplicate quest level {quest.level}: {_builder_name(existing.builder)} vs {_builder_name(builder)}",
            )
        _QUESTS[key] = quest
        return builder

    return decorator


def all_quests() -> list[QuestDefinition]:
    return sorted(_QUESTS.values(), key=lambda quest: quest.level_key)


def quest_by_stage(major: int, minor: int) -> QuestDefinition | None:
    return _QUESTS.get((int(major), int(minor)))


def quest_by_level(level: str) -> QuestDefinition | None:
    try:
        major, minor = parse_level(level)
    except ValueError:
        return None
    return quest_by_stage(major, minor)
