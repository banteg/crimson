from __future__ import annotations

import warnings

from .types import Replay, current_replay_game_version


class ReplayGameVersionWarning(UserWarning):
    """Warnings related to the replay's recorded `game_version`."""


def warn_on_game_version_mismatch(
    replay: Replay,
    *,
    action: str = "playback",
    current_version: str | None = None,
) -> bool:
    """Warn if `replay.header.game_version` doesn't match the current runtime version.

    Returns True if a warning was emitted.

    Intended call sites:
      - replay playback
      - replay verification / server-side validation
    """

    expected = str(current_version) if current_version is not None else str(current_replay_game_version())
    got = str(replay.header.game_version)

    if not got:
        warnings.warn(
            f"Replay is missing game_version; {action} may diverge (current={expected!r}).",
            category=ReplayGameVersionWarning,
            stacklevel=2,
        )
        return True

    if got != expected:
        warnings.warn(
            f"Replay game_version mismatch; {action} may diverge (replay={got!r}, current={expected!r}).",
            category=ReplayGameVersionWarning,
            stacklevel=2,
        )
        return True

    return False
