from __future__ import annotations

import re
import warnings

from ..game_version import REPLAY_RULES, current_replay_game_version
from .codec import ReplayCodecError
from .types import Replay


class ReplayRulesError(ReplayCodecError):
    """A replay recorded under rules this build does not play."""


def require_playable_rules(replay: Replay) -> None:
    """Accept the supported historical and current simulation profiles."""

    if replay.rules not in (1, REPLAY_RULES):
        raise ReplayRulesError(f"replay was recorded under rules {replay.rules}; this build plays rules 1 and {REPLAY_RULES}")


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


def legacy_coop_reload(replay: Replay) -> bool:
    """Resolve the unversioned co-op reload fix from verified release history.

    It landed during 0.18.0 development, before 0.19.0. Builds naming 0.18.0
    with a source suffix are ambiguous and need an explicit provenance mapping.
    """
    if replay.rules != 1 or replay.run.player_count == 1 or replay.run.preserve_bugs:
        return False
    # Service vectors introduced by bde24bef7, after reload fix 99cc34261.
    if replay.game_version == "0.18.0+build.64a9589f5fbefdc036f0559b":
        return False
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(.*)", replay.game_version)
    if match:
        version = tuple(int(match[i]) for i in (1, 2, 3))
        if version >= (0, 19, 0):
            return False
        if version < (0, 18, 0) or (version == (0, 18, 0) and not match[4]):
            return True
    raise ReplayRulesError("rules-1 co-op reload behavior requires known recording-build provenance")
