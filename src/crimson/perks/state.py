from __future__ import annotations

import msgspec

from .ids import PerkId


class PerkEffectIntervals(msgspec.Struct):
    """Global thresholds used by perk timers in `player_update`.

    These are global (not per-player) in crimsonland.exe: `flt_473310`,
    `flt_473314`, and `flt_473318`.
    """

    man_bomb: float = 4.0
    fire_cough: float = 1.399999976158142
    hot_tempered: float = 1.399999976158142


class PerkSelectionState(msgspec.Struct):
    pending_count: int = 0
    choices: list[PerkId] = msgspec.field(default_factory=list)
    choices_dirty: bool = True
    capture_player_perk_counts_known: bool = True
