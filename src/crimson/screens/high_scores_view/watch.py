"""What a high score row can be watched as: its replay, or why it does not play (docs/rewrite/watch-replays.md)."""

from __future__ import annotations

from pathlib import Path

import msgspec

from ...game_version import REPLAY_RULES, current_replay_game_version
from ...persistence.highscores import HighScoreRecord
from ...replay import ReplayCodecError, load_replay_file
from ...replay.library import numbered_replay
from ...replay.types import Replay


class WatchTarget(msgspec.Struct, frozen=True):
    """A row's replay when it plays, and the line its card shows: the build it came from, or why it does not play."""

    replay: Replay | None
    note: str


def local_watch_target(replay_dir: Path, record: HighScoreRecord) -> WatchTarget | None:
    """A local record's replay, by the number it names; None for a record without one."""

    if record.replay_number == 0:
        return None
    path = numbered_replay(replay_dir, record.replay_number)
    if path is None:
        return WatchTarget(None, "Its replay was not saved")
    return replay_watch_target(path)


def replay_watch_target(path: Path) -> WatchTarget:
    """A replay file as a row's Watch: it plays, or the reason it does not."""

    try:
        replay = load_replay_file(path)
    except ReplayCodecError:
        return WatchTarget(None, "This version cannot read its replay")
    # The release a build came from, without its commit.
    release = replay.game_version.split("+")[0]
    if replay.rules != REPLAY_RULES:
        return WatchTarget(None, f"Recorded under other rules ({release})")
    if replay.game_version != current_replay_game_version():
        return WatchTarget(replay, f"Recorded with {release}")
    return WatchTarget(replay, "")
