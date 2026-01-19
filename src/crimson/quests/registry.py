from __future__ import annotations

from typing import Callable

from .types import QuestBuilder, QuestDefinition

_QUESTS: dict[str, QuestDefinition] = {}


def register_quest(
    *,
    level: str,
    title: str,
    time_limit_ms: int,
    start_weapon_id: int,
    unlock_perk_id: int | None = None,
    unlock_weapon_id: int | None = None,
    terrain_id: int | None = None,
    terrain_ids: tuple[int, int, int] | None = None,
    builder_address: int | None = None,
) -> Callable[[QuestBuilder], QuestBuilder]:
    def decorator(builder: QuestBuilder) -> QuestBuilder:
        quest = QuestDefinition(
            level=level,
            title=title,
            builder=builder,
            time_limit_ms=time_limit_ms,
            start_weapon_id=start_weapon_id,
            unlock_perk_id=unlock_perk_id,
            unlock_weapon_id=unlock_weapon_id,
            terrain_id=terrain_id,
            terrain_ids=terrain_ids,
            builder_address=builder_address,
        )
        existing = _QUESTS.get(quest.level)
        if existing is not None:
            raise ValueError(
                "duplicate quest level "
                f"{quest.level}: {existing.builder.__name__} vs {builder.__name__}"
            )
        _QUESTS[quest.level] = quest
        return builder

    return decorator


def all_quests() -> list[QuestDefinition]:
    return sorted(_QUESTS.values(), key=lambda quest: quest.level_key)


def quest_by_level(level: str) -> QuestDefinition | None:
    return _QUESTS.get(level)
