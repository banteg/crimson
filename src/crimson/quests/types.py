from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class QuestContext:
    width: int
    height: int
    player_count: int


@dataclass(frozen=True, slots=True)
class SpawnEntry:
    x: float
    y: float
    heading: float
    spawn_id: int
    trigger_ms: int
    count: int


QuestBuilder = Callable[..., list[SpawnEntry]]


@dataclass(frozen=True, slots=True)
class QuestDefinition:
    level: str
    title: str
    builder: QuestBuilder
