from __future__ import annotations

from collections.abc import Sequence

import msgspec

from grim.geom import Vec2

from .names import CreatureNameTable, TypoHighscoreNames
from .typing import TypingBuffer


class TypoCarry(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Typ-o globals native keeps for the whole process, as the next Typ-o run starts with them."""

    # `typo_gameplay_update_and_render`'s static aim point, set on the process's first Typ-o frame.
    target_world: Vec2 | None = None
    # `typo_submit_count` / `typo_match_count`: nothing resets them.
    submit_count: int = 0
    match_count: int = 0
    # `typo_word_highscore_cache_ready`: the first highscore-name pick loads the score table.
    highscore_names_loaded: bool = False


class TypoState(msgspec.Struct):
    typing: TypingBuffer = msgspec.field(default_factory=TypingBuffer)
    names: CreatureNameTable = msgspec.field(default_factory=lambda: CreatureNameTable.sized(0))
    spawn_cooldown_ms: int = 0
    dictionary_words: tuple[str, ...] = ()
    highscore_names: TypoHighscoreNames = msgspec.field(default_factory=TypoHighscoreNames)
    # `typo_gameplay_update_and_render`'s static aim point, the last matched creature's position.
    target_world: Vec2 = Vec2()
    # The counters as the run started; the run's own shots are the difference.
    start_submit_count: int = 0
    start_match_count: int = 0

    def carry(self) -> TypoCarry:
        return TypoCarry(
            target_world=self.target_world,
            submit_count=self.typing.submit_count,
            match_count=self.typing.match_count,
            highscore_names_loaded=self.highscore_names.loaded,
        )


def reset_typo_state(
    typo: TypoState,
    *,
    creature_capacity: int,
    target_world: Vec2 = Vec2(),
    carry: TypoCarry | None = None,
    dictionary_words: Sequence[str] = (),
    highscore_names: Sequence[str] = (),
) -> None:
    carry = TypoCarry() if carry is None else carry
    typo.typing = TypingBuffer(submit_count=carry.submit_count, match_count=carry.match_count)
    # One more name than creatures: native names the phantom slot one past its table.
    typo.names = CreatureNameTable.sized(int(creature_capacity) + 1)
    typo.spawn_cooldown_ms = 0
    typo.dictionary_words = tuple(str(word) for word in dictionary_words)
    typo.highscore_names = TypoHighscoreNames(
        names=tuple(str(name) for name in highscore_names), loaded=carry.highscore_names_loaded,
    )
    typo.target_world = target_world
    typo.start_submit_count = carry.submit_count
    typo.start_match_count = carry.match_count


def typo_shot_counts(typo: TypoState, *, preserve_bugs: bool) -> tuple[int, int]:
    """`highscore_active_record.shots_fired` / `shots_hit`: native copies its never-reset counters.

    The fix counts only this run's words; `preserve_bugs` keeps the earlier runs' in."""

    submit_count, match_count = int(typo.typing.submit_count), int(typo.typing.match_count)
    if preserve_bugs:
        return submit_count, match_count
    return submit_count - typo.start_submit_count, match_count - typo.start_match_count


class TypoSession(msgspec.Struct):
    """What the game keeps for Typ-o between runs, as native keeps its globals for the process."""

    carry: TypoCarry = msgspec.field(default_factory=TypoCarry)
    # `typo_word_highscore_cache`, once `carry.highscore_names_loaded`.
    highscore_names: tuple[str, ...] = ()

    def keep(self, typo: TypoState) -> None:
        self.carry = typo.carry()
        if typo.highscore_names.loaded:
            self.highscore_names = typo.highscore_names.names
