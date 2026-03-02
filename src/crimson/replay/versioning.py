from __future__ import annotations

import warnings

from .types import Replay, current_replay_game_version


class ReplayGameVersionError(ValueError):
    """Raised when replay `game_version` is incompatible with runtime version."""


class ReplayGameVersionWarning(UserWarning):
    """Warned when replay and runtime build metadata differ while game version matches."""


def _split_game_version(value: str) -> tuple[str, str]:
    game_version, sep, build_metadata = str(value).partition("+")
    if not sep:
        return game_version.strip(), ""
    return game_version.strip(), build_metadata.strip()


def warn_on_game_version_mismatch(
    replay: Replay,
    *,
    action: str = "playback",
    current_version: str | None = None,
) -> None:
    """Require matching game version; warn when only build metadata differs."""

    expected = str(current_version).strip() if current_version is not None else str(current_replay_game_version()).strip()
    got = str(replay.header.game_version).strip()

    if not got:
        raise ReplayGameVersionError(
            f"Replay is missing game_version; {action} requires a matching game version (current={expected!r}).",
        )

    expected_game_version, _ = _split_game_version(expected)
    replay_game_version, _ = _split_game_version(got)
    if replay_game_version != expected_game_version:
        raise ReplayGameVersionError(
            f"Replay game_version mismatch; {action} requires a matching game version "
            f"(replay={got!r}, current={expected!r}).",
        )

    if got != expected:
        warnings.warn(
            "Replay game_version build metadata differs (git tag/hash mismatch); "
            "continuing because base game version matches "
            f"(replay={got!r}, current={expected!r}).",
            ReplayGameVersionWarning,
            stacklevel=2,
        )
