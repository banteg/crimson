from __future__ import annotations

import msgspec

from .ids import PerkId


class PerkEffectIntervals(msgspec.Struct):
    """Global thresholds used by perk timers in `player_update`.

    These are global (not per-player) in crimsonland.exe: `perk_man_bomb_trigger_interval_s`,
    `perk_fire_cough_trigger_interval_s` and `perk_hot_tempered_trigger_interval_s`; Fire Cough
    and Hot Tempered re-roll theirs.
    """

    man_bomb: float = 4.0
    fire_cough: float = 1.399999976158142
    hot_tempered: float = 1.399999976158142


class PerkSelectionState(msgspec.Struct):
    pending_count: int = 0
    choices: list[PerkId] = msgspec.field(default_factory=list)
    choices_dirty: bool = True
