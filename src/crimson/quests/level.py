from __future__ import annotations

from typing import Annotated, TypeAlias

import msgspec

QUEST_STAGE_COUNT = 5
QUESTS_PER_STAGE = 10
QUEST_COUNT = QUEST_STAGE_COUNT * QUESTS_PER_STAGE

QuestStageMajor: TypeAlias = Annotated[int, msgspec.Meta(ge=1, le=QUEST_STAGE_COUNT)]
QuestStageMinor: TypeAlias = Annotated[int, msgspec.Meta(ge=1, le=QUESTS_PER_STAGE)]


class QuestLevel(msgspec.Struct, frozen=True):
    major: QuestStageMajor
    minor: QuestStageMinor

    @classmethod
    def parse(cls, value: str) -> QuestLevel:
        text = str(value).strip()
        major_text, sep, minor_text = text.partition(".")
        if sep != "." or not major_text or not minor_text:
            raise ValueError(f"invalid quest level: {value!r}")
        try:
            major = int(major_text)
            minor = int(minor_text)
        except ValueError as exc:
            raise ValueError(f"invalid quest level: {value!r}") from exc
        try:
            return msgspec.convert(
                {
                    "major": major,
                    "minor": minor,
                },
                type=cls,
            )
        except msgspec.ValidationError as exc:
            raise ValueError(f"invalid quest level: {value!r}") from exc

    @classmethod
    def try_parse(cls, value: str | None) -> QuestLevel | None:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            return cls.parse(text)
        except ValueError:
            return None

    @classmethod
    def from_global_index(cls, index: int) -> QuestLevel:
        idx = int(index)
        if not (0 <= idx < QUEST_COUNT):
            raise ValueError(f"quest global index out of range: {idx} (expected 0..{QUEST_COUNT - 1})")
        major, row_index = divmod(idx, QUESTS_PER_STAGE)
        return cls(major=major + 1, minor=row_index + 1)

    @property
    def text(self) -> str:
        return f"{self.major}.{self.minor}"

    @property
    def global_index(self) -> int:
        return (self.major - 1) * QUESTS_PER_STAGE + (self.minor - 1)

    @property
    def title(self) -> str:
        from .registry import quest_by_level

        quest = quest_by_level(self)
        if quest is None:
            raise KeyError(f"unknown quest level: {self.text}")
        return str(quest.title)

    def __str__(self) -> str:
        return self.text
