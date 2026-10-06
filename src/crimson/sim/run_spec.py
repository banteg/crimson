from __future__ import annotations

import msgspec

from ..game_modes import GameMode
from ..msgspec_types import NonNegativeInt, PlayerCount
from ..persistence.save_status import GameStatusData
from ..quests.level import QuestLevel
from ..typo.state import TypoCarry
from ..weapon_usage import ZERO_WEAPON_USAGE_COUNTS, WeaponUsageCounts

# Native terrain and world bounds; every run uses the same arena.


class RunStatus(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Save-status fields that influence a run.

    Unlock indices gate weapons, perks and terrain; weapon usage counts steer
    native weapon-drop rerolls. Other save counters never reach the simulation.
    """

    quest_unlock_index: int = 0
    # Replay format 29 stores this under its earlier name.
    quest_unlock_index_hardcore: int = msgspec.field(default=0, name="quest_unlock_index_full")  # name-audit: keep
    weapon_usage_counts: WeaponUsageCounts = ZERO_WEAPON_USAGE_COUNTS

    @classmethod
    def from_status_data(cls, data: GameStatusData) -> RunStatus:
        return cls(**{name: getattr(data, name) for name in cls.__struct_fields__})

    def as_status_data(self) -> GameStatusData:
        return GameStatusData(**msgspec.structs.asdict(self))


class RunSpec(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Inputs captured before any run-start mutation, shared by live and replay."""

    game_mode_id: GameMode
    seed: int
    quest_level: QuestLevel | None = None
    player_count: PlayerCount = 1
    hardcore: bool = False
    preserve_bugs: bool = False
    # Mirrors the native quest retry scaling counter (`quest_fail_retry_count`).
    quest_fail_retry_count: NonNegativeInt = 0
    detail_preset: NonNegativeInt = 5
    violence_disabled: NonNegativeInt = 0
    # `cv_friendlyFire` at run start: player shots carry their own owner id and can hit other players.
    friendly_fire: bool = False
    status: RunStatus = msgspec.field(default_factory=RunStatus)
    typo_dictionary_words: tuple[str, ...] = ()
    # The score table's names as `typo_word_pick_highscore_name`'s cache holds them: loaded by an
    # earlier run of the process (see `typo_carry`), or the table as this run would load it.
    typo_highscore_names: tuple[str, ...] = ()
    typo_carry: TypoCarry = msgspec.field(default_factory=TypoCarry)
