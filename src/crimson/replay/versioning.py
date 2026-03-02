from __future__ import annotations

from .types import Replay, current_replay_game_version


class ReplayGameVersionError(ValueError):
    """Raised when replay `game_version` does not exactly match runtime version."""


def warn_on_game_version_mismatch(
    replay: Replay,
    *,
    action: str = "playback",
    current_version: str | None = None,
) -> None:
    """Require `replay.header.game_version` to match the current runtime version."""

    expected = str(current_version) if current_version is not None else str(current_replay_game_version())
    got = str(replay.header.game_version)

    if not got:
        raise ReplayGameVersionError(
            f"Replay is missing game_version; {action} requires an exact match (current={expected!r}).",
        )

    if got != expected:
        raise ReplayGameVersionError(
            f"Replay game_version mismatch; {action} requires an exact match "
            f"(replay={got!r}, current={expected!r}).",
        )
