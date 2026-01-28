from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from grim.rand import Crand


NAME_MAX_CHARS = 16  # creature_name_assign_random enforces strlen < 0x10.


_NAME_PARTS: tuple[str, ...] = (
    "lamb",
    "gun",
    "head",
    "tail",
    "leg",
    "nose",
    "road",
    "stab",
    "high",
    "low",
    "hat",
    "pie",
    "hand",
    "jack",
    "cube",
    "ice",
    "cow",
    "king",
    "lord",
    "mate",
    "mary",
    "dick",
    "bill",
    "cat",
    "harry",
    "tom",
    "fly",
    "call",
    "shot",
    "gate",
    "quick",
    "brown",
    "fox",
    "jumper",
    "over",
    "lazy",
    "dog",
    "zeta",
    "unique",
    "nerd",
    "earl",
    "sleep",
    "onyx",
    "mill",
    "blue",
    "below",
    "scape",
    "reap",
    "damo",
    "break",
    "boom",
    "the",
)


def typo_name_part(rng: Crand, *, allow_the: bool) -> str:
    mod = 52 if allow_the else 51
    idx = int(rng.rand() % mod)
    if idx == 39:
        return "nerd"
    return _NAME_PARTS[idx]


def typo_build_name(rng: Crand, *, score_xp: int, unique_words: Sequence[str] | None = None) -> str:
    score_xp = int(score_xp)
    if score_xp > 120:
        if int(rng.rand() % 100) < 10 and unique_words:
            return str(unique_words[int(rng.rand() % len(unique_words))])
        if int(rng.rand() % 100) < 80:
            return "".join(
                [
                    typo_name_part(rng, allow_the=True),
                    typo_name_part(rng, allow_the=False),
                    typo_name_part(rng, allow_the=False),
                    typo_name_part(rng, allow_the=False),
                ]
            )

    if (score_xp > 80 and int(rng.rand() % 100) < 80) or (score_xp > 60 and int(rng.rand() % 100) < 40):
        return "".join(
            [
                typo_name_part(rng, allow_the=True),
                typo_name_part(rng, allow_the=False),
                typo_name_part(rng, allow_the=False),
            ]
        )

    if (score_xp > 40 and int(rng.rand() % 100) < 80) or (score_xp > 20 and int(rng.rand() % 100) < 40):
        return "".join(
            [
                typo_name_part(rng, allow_the=True),
                typo_name_part(rng, allow_the=False),
            ]
        )

    return typo_name_part(rng, allow_the=False)


@dataclass(slots=True)
class CreatureNameTable:
    names: list[str]

    @classmethod
    def sized(cls, size: int) -> CreatureNameTable:
        return cls(names=[""] * int(size))

    def clear(self, idx: int) -> None:
        if 0 <= int(idx) < len(self.names):
            self.names[int(idx)] = ""

    def find_by_name(self, name: str, *, active_mask: Sequence[bool]) -> int | None:
        for idx, existing in enumerate(self.names):
            if not (0 <= idx < len(active_mask) and bool(active_mask[idx])):
                continue
            if existing == name:
                return idx
        return None

    def is_unique(self, name: str, *, exclude_idx: int, active_mask: Sequence[bool]) -> bool:
        exclude = int(exclude_idx)
        for idx, existing in enumerate(self.names):
            if idx == exclude:
                continue
            if not (0 <= idx < len(active_mask) and bool(active_mask[idx])):
                continue
            if existing == name:
                return False
        return True

    def assign_random(
        self,
        creature_idx: int,
        rng: Crand,
        *,
        score_xp: int,
        active_mask: Sequence[bool],
        unique_words: Sequence[str] | None = None,
    ) -> str:
        idx = int(creature_idx)
        if not (0 <= idx < len(self.names)):
            raise IndexError(f"creature_idx out of range: {idx}")

        too_long_attempts = 0
        while True:
            name = typo_build_name(rng, score_xp=score_xp, unique_words=unique_words)
            if not self.is_unique(name, exclude_idx=idx, active_mask=active_mask):
                continue

            if len(name) < NAME_MAX_CHARS:
                self.names[idx] = name
                return name

            too_long_attempts += 1
            if too_long_attempts > 99:
                self.names[idx] = name
                return name

