from __future__ import annotations

import warnings

from ..game_version import REPLAY_RULES, current_replay_game_version
from .codec import ReplayCodecError
from .types import Replay


class ReplayRulesError(ReplayCodecError):
    """A replay recorded under rules this build does not play."""


def require_playable_rules(replay: Replay) -> None:
    """Refuse a replay recorded under other rules: this build simulates only its own (REPLAY_RULES)."""

    if replay.rules != REPLAY_RULES:
        raise ReplayRulesError(f"replay was recorded under rules {replay.rules}; this build plays rules {REPLAY_RULES}")


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
