from __future__ import annotations

from dataclasses import dataclass

QUEST_STAGE_COUNT = 5
QUESTS_PER_STAGE = 10
QUEST_COUNT = QUEST_STAGE_COUNT * QUESTS_PER_STAGE

# `game.cfg` quest counters use staged offsets into `quest_play_counts`.
QUEST_STATUS_GAMES_OFFSET = 11
QUEST_STATUS_COMPLETED_OFFSET = 51
QUEST_STATUS_TRACKED_COUNT = 40


@dataclass(frozen=True, order=True, slots=True)
class QuestLevel:
    major: int
    minor: int

    def __post_init__(self) -> None:
        major = self.major
        minor = self.minor
        if isinstance(major, bool) or not isinstance(major, int):
            raise TypeError(f"quest stage must be int, got {type(major).__name__}")
        if isinstance(minor, bool) or not isinstance(minor, int):
            raise TypeError(f"quest row must be int, got {type(minor).__name__}")
        if not (1 <= major <= QUEST_STAGE_COUNT):
            raise ValueError(f"quest stage out of range: {major} (expected 1..{QUEST_STAGE_COUNT})")
        if not (1 <= minor <= QUESTS_PER_STAGE):
            raise ValueError(f"quest row out of range: {minor} (expected 1..{QUESTS_PER_STAGE})")

    @classmethod
    def from_parts(cls, major: int, minor: int) -> QuestLevel:
        return cls(major, minor)

    @classmethod
    def from_parts_or_none(cls, major: int, minor: int) -> QuestLevel | None:
        if major == 0 and minor == 0:
            return None
        try:
            return cls(major, minor)
        except (TypeError, ValueError):
            return None

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
        return cls(major=major, minor=minor)

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

    @classmethod
    def from_stage_row(cls, stage: int, row_index: int) -> QuestLevel:
        return cls(major=int(stage), minor=int(row_index) + 1)

    def to_string(self) -> str:
        return f"{self.major}.{self.minor}"

    @property
    def level(self) -> str:
        return self.to_string()

    def to_stage_pair(self) -> tuple[int, int]:
        return self.major, self.minor

    @property
    def stage_pair(self) -> tuple[int, int]:
        return self.to_stage_pair()

    def to_stage_row(self) -> tuple[int, int]:
        return self.major, self.minor - 1

    @property
    def stage_row(self) -> tuple[int, int]:
        return self.to_stage_row()

    def to_global_index(self) -> int:
        return (self.major - 1) * QUESTS_PER_STAGE + (self.minor - 1)

    @property
    def global_index(self) -> int:
        return self.to_global_index()

    def status_games_counter_index(self) -> int:
        return self.to_global_index() + QUEST_STATUS_GAMES_OFFSET

    @property
    def games_counter_index(self) -> int:
        return self.status_games_counter_index()

    def status_completed_counter_index(self) -> int:
        return self.to_global_index() + QUEST_STATUS_COMPLETED_OFFSET

    @property
    def completed_counter_index(self) -> int:
        return self.status_completed_counter_index()

    @property
    def tracked_in_status(self) -> bool:
        return self.to_global_index() < QUEST_STATUS_TRACKED_COUNT

    def tracked_status_games_counter_index(self) -> int | None:
        if not self.tracked_in_status:
            return None
        return self.status_games_counter_index()

    @property
    def tracked_games_counter_index(self) -> int | None:
        return self.tracked_status_games_counter_index()

    def tracked_status_completed_counter_index(self) -> int | None:
        if not self.tracked_in_status:
            return None
        return self.status_completed_counter_index()

    @property
    def tracked_completed_counter_index(self) -> int | None:
        return self.tracked_status_completed_counter_index()

    def __str__(self) -> str:
        return self.to_string()


def normalize_quest_level_text(value: str | None) -> str:
    level = QuestLevel.try_parse(value)
    if level is None:
        return ""
    return level.to_string()
