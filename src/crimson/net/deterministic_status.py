from __future__ import annotations

import tempfile
from pathlib import Path

from ..persistence.save_status import GameStatus, GameStatusData, default_status_data, hash_status_data


def status_data_from_status(status: GameStatus | None) -> GameStatusData:
    if status is None:
        return default_status_data()
    return status.as_data()


def build_lan_deterministic_status(*, status: GameStatusData | None = None) -> GameStatus:
    """Return a session-local `GameStatus` for deterministic LAN simulation.

    The host sends its save status in `MatchStart`, and all peers use it as the
    simulation status. This avoids split brain where local save progress impacts
    deterministic simulation (weapon availability / RNG consumption).
    """

    # This status object should never overwrite the on-disk save. Give it a
    # safe temp path so accidental `save_if_dirty()` calls don't clobber
    # `game.cfg`.
    path = Path(tempfile.gettempdir()) / "crimson-lan-sim-game.cfg"
    data = default_status_data() if status is None else status
    return GameStatus.from_data(path=path, data=data, dirty=False)


__all__ = [
    "build_lan_deterministic_status",
    "hash_status_data",
    "status_data_from_status",
]
