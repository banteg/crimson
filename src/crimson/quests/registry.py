from __future__ import annotations

from typing import Callable

from .types import QuestBuilder, QuestDefinition, parse_level

_QUESTS: dict[tuple[int, int], QuestDefinition] = {}


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
    def _builder_name(builder_fn: QuestBuilder) -> str:
        return str(getattr(builder_fn, "__name__", type(builder_fn).__name__))

    def decorator(builder: QuestBuilder) -> QuestBuilder:
        major, minor = parse_level(level)
        quest = QuestDefinition(
            major=major,
            minor=minor,
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
        key = quest.level_key
        existing = _QUESTS.get(key)
        if existing is not None:
            raise ValueError(
                f"duplicate quest level {quest.level}: {_builder_name(existing.builder)} vs {_builder_name(builder)}"
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
