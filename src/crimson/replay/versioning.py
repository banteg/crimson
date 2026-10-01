from __future__ import annotations

import warnings

from .types import Replay, current_replay_game_version


class ReplayGameVersionWarning(UserWarning):
    """Warned when a replay was recorded by another game version or build."""


def warn_on_game_version_mismatch(
    replay: Replay,
    *,
    action: str = "playback",
    current_version: str | None = None,
) -> None:
    """Warn when the recording build differs.

    The replay format version already gates decoding, and verification re-simulates every tick, so a rules change
    between versions shows up as a mismatch; the version alone does not reject a replay.
    """

    expected = current_version if current_version is not None else current_replay_game_version()
    if replay.game_version != expected:
        warnings.warn(
            f"Replay was recorded by another game version; continuing {action} "
            f"(replay={replay.game_version!r}, current={expected!r}).",
            ReplayGameVersionWarning,
            stacklevel=2,
        )
