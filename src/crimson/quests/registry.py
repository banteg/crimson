from __future__ import annotations

from collections.abc import Callable

from ..terrain_slots import TerrainSlotTriplet, terrain_slots_for_quest
from ..weapons import WeaponId
from .level import QuestLevel
from .types import QuestBuilder, QuestDefinition

_QUESTS: dict[QuestLevel, QuestDefinition] = {}


def register_quest(
    *,
    level: str,
    title: str,
    time_limit_ms: int,
    start_weapon_id: WeaponId,
    unlock_perk_id: int | None = None,
    unlock_weapon_id: WeaponId | None = None,
    terrain_slots: TerrainSlotTriplet | None = None,
) -> Callable[[QuestBuilder], QuestBuilder]:
    def _builder_name(builder_fn: QuestBuilder) -> str:
        return str(getattr(builder_fn, "__name__", repr(builder_fn)))

    def decorator(builder: QuestBuilder) -> QuestBuilder:
        quest_level = QuestLevel.parse(level)
        resolved_terrain_slots = (
            terrain_slots if terrain_slots is not None else terrain_slots_for_quest(quest_level)
        )
        normalized_unlock_weapon_id = WeaponId(unlock_weapon_id) if unlock_weapon_id is not None else None
        quest = QuestDefinition(
            level=quest_level,
            title=title,
            builder=builder,
            time_limit_ms=time_limit_ms,
            start_weapon_id=WeaponId(start_weapon_id),
            unlock_perk_id=unlock_perk_id,
            unlock_weapon_id=normalized_unlock_weapon_id,
            terrain_slots=resolved_terrain_slots,
        )
        existing = _QUESTS.get(quest.level)
        if existing is not None:
            raise ValueError(
                f"duplicate quest level {quest.level.text}: {_builder_name(existing.builder)} vs {_builder_name(builder)}",
            )
        _QUESTS[quest.level] = quest
        return builder

    return decorator


def all_quests() -> list[QuestDefinition]:
    return sorted(_QUESTS.values(), key=lambda quest: quest.level.global_index)


def quest_by_level(level: QuestLevel) -> QuestDefinition | None:
    return _QUESTS.get(level)
