from __future__ import annotations

import tempfile
from pathlib import Path

from ..persistence.save_status import GameStatus
from ..status_snapshot import (
    game_status_from_progress_status,
    hash_progress_status,
    lockstep_status_from_progress,
    progress_status_from_game_status,
    progress_status_from_lockstep,
)
from .lockstep_protocol import StatusSnapshot


def status_snapshot_from_status(status: GameStatus | None) -> StatusSnapshot:
    return lockstep_status_from_progress(progress_status_from_game_status(status))


def hash_status_snapshot(snapshot: StatusSnapshot) -> str:
    """Stable hash for sanity-checking host/client status snapshots."""
    return hash_progress_status(progress_status_from_lockstep(snapshot))


def build_lan_deterministic_status(*, snapshot: StatusSnapshot | None = None) -> GameStatus:
    """Return a session-local `GameStatus` for deterministic LAN simulation.

    The host sends its save snapshot in `MatchStart`, and all peers use it as the
    simulation status. This avoids split brain where local save progress impacts
    deterministic simulation (weapon availability / RNG consumption).
    """

    # This status object should never overwrite the on-disk save. Give it a
    # safe temp path so accidental `save_if_dirty()` calls don't clobber
    # `game.cfg`.
    path = Path(tempfile.gettempdir()) / "crimson-lan-sim-game.cfg"
    progress = progress_status_from_lockstep(snapshot)
    return game_status_from_progress_status(progress, path=path)
