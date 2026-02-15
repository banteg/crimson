from __future__ import annotations

from pathlib import Path
import tempfile

from ..persistence.save_status import (
    QUEST_PLAY_COUNT,
    UNKNOWN_TAIL_SIZE,
    WEAPON_USAGE_COUNT,
    GameStatus,
)

# LAN lockstep must not depend on local save progress; different machines often have
# different unlock indices / usage counts, which impacts RNG consumption and can
# desync simulation (e.g., weapon/bonus spawning).
LAN_DETERMINISTIC_QUEST_UNLOCK_INDEX = 0x28


def build_lan_deterministic_status(*, base: GameStatus | None = None) -> GameStatus:
    """Return a session-local `GameStatus` for deterministic LAN simulation.

    - Quest unlock indices are forced to a stable value (>= 0x28 so all terrain tiers
      are eligible and Splitter Gun availability matches across peers).
    - Weapon usage counts start at zero and evolve only within the current session.
      This preserves the native "used weapon" bias while removing dependency on
      preexisting save data.
    """

    # This status object should never overwrite the on-disk save. Give it a
    # safe temp path so accidental `save_if_dirty()` calls don't clobber
    # `game.cfg`.
    path = Path(tempfile.gettempdir()) / "crimson-lan-sim-game.cfg"
    data = {
        "quest_unlock_index": int(LAN_DETERMINISTIC_QUEST_UNLOCK_INDEX),
        "quest_unlock_index_full": int(LAN_DETERMINISTIC_QUEST_UNLOCK_INDEX),
        "weapon_usage_counts": [0] * int(WEAPON_USAGE_COUNT),
        "quest_play_counts": [0] * int(QUEST_PLAY_COUNT),
        "mode_play_survival": 0,
        "mode_play_rush": 0,
        "mode_play_typo": 0,
        "mode_play_other": 0,
        "game_sequence_id": 0,
        "unknown_tail": b"\x00" * int(UNKNOWN_TAIL_SIZE),
    }
    return GameStatus(path=path, data=data, dirty=False)
