from __future__ import annotations

import msgspec

from ..game_modes import GameMode
from ..msgspec_types import NonNegativeInt, PlayerCount
from ..persistence.save_status import GameStatusData
from ..quests.level import QuestLevel
from ..weapon_usage import ZERO_WEAPON_USAGE_COUNTS, WeaponUsageCounts

# Native terrain and world bounds; every run uses the same arena.
WORLD_SIZE = 1024.0


class RunStatus(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Save-status fields that influence a run.

    Unlock indices gate weapons, perks and terrain; weapon usage counts steer
    native weapon-drop rerolls. Other save counters never reach the simulation.
    """

    quest_unlock_index: int = 0
    quest_unlock_index_full: int = 0
    weapon_usage_counts: WeaponUsageCounts = ZERO_WEAPON_USAGE_COUNTS

    @classmethod
    def from_status_data(cls, data: GameStatusData) -> RunStatus:
        return cls(
            quest_unlock_index=data.quest_unlock_index,
            quest_unlock_index_full=data.quest_unlock_index_full,
            weapon_usage_counts=tuple(data.weapon_usage_counts),
        )

    def as_status_data(self) -> GameStatusData:
        return GameStatusData(
            quest_unlock_index=self.quest_unlock_index,
            quest_unlock_index_full=self.quest_unlock_index_full,
            weapon_usage_counts=self.weapon_usage_counts,
        )


class RunSpec(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Inputs captured before any run-start mutation, shared by live and replay."""

    game_mode_id: GameMode
    seed: int
    quest_level: QuestLevel | None = None
    player_count: PlayerCount = 1
    hardcore: bool = False
    preserve_bugs: bool = False
    # Shareware demo build: changes quest spawns, input thresholds and usage tracking.
    demo: bool = False
    # Mirrors the native quest retry scaling counter (`quest_fail_retry_count`).
    quest_fail_retry_count: NonNegativeInt = 0
    detail_preset: NonNegativeInt = 5
    violence_disabled: NonNegativeInt = 0
    status: RunStatus = msgspec.field(default_factory=RunStatus)
    typo_dictionary_words: tuple[str, ...] = ()
    typo_highscore_names: tuple[str, ...] = ()
