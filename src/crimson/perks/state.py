from __future__ import annotations

import msgspec

from .ids import PerkId


class PerkEffectIntervals(msgspec.Struct):
    """Global thresholds used by perk timers in `player_update`.

    These are global (not per-player) in crimsonland.exe: `perk_man_bomb_trigger_interval_s`,
    `perk_fire_cough_trigger_interval_s` and `perk_hot_tempered_trigger_interval_s`; Fire Cough
    and Hot Tempered re-roll theirs. Default rules keep those two thresholds on
    PlayerState instead; these fields retain the original preserve-bugs path.
    """

    man_bomb: float = 4.0
    fire_cough: float = 1.399999976158142
    hot_tempered: float = 1.399999976158142


class PerkOffer(msgspec.Struct, frozen=True):
    """The visible choices the next simulation tick may pick from."""

    choices: tuple[PerkId, ...]


class PerkSelectionState(msgspec.Struct):
    pending_count: int = 0
    choices: list[PerkId] = msgspec.field(default_factory=list)
    choices_dirty: bool = True
    open_offer: PerkOffer | None = None

    def close_offer(self) -> PerkOffer | None:
        """Take the one-tick offer. Canceling leaves the cached roll intact."""
        offer, self.open_offer = self.open_offer, None
        return offer
