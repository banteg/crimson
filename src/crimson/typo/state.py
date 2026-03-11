from __future__ import annotations

from collections.abc import Sequence

import msgspec

from grim.geom import Vec2

from .names import CreatureNameTable
from .typing import TypingBuffer


class TypoState(msgspec.Struct):
    typing: TypingBuffer = msgspec.field(default_factory=TypingBuffer)
    names: CreatureNameTable = msgspec.field(default_factory=lambda: CreatureNameTable.sized(0))
    spawn_cooldown_ms: int = 0
    dictionary_words: tuple[str, ...] = ()
    highscore_names: tuple[str, ...] = ()
    pending_fire_target: Vec2 | None = None
    pending_reload: bool = False


def reset_typo_state(
    typo: TypoState,
    *,
    creature_capacity: int,
    dictionary_words: Sequence[str] = (),
    highscore_names: Sequence[str] = (),
) -> None:
    typo.typing = TypingBuffer()
    typo.names = CreatureNameTable.sized(int(creature_capacity))
    typo.spawn_cooldown_ms = 0
    typo.dictionary_words = tuple(str(word) for word in dictionary_words)
    typo.highscore_names = tuple(str(name) for name in highscore_names)
    typo.pending_fire_target = None
    typo.pending_reload = False


def typo_shot_counts(typo: TypoState) -> tuple[int, int]:
    return int(typo.typing.submit_count), int(typo.typing.match_count)
