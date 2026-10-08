"""Where a client keeps its replays: one numbered file per run, `replays/<n>-<mode>.crd`, which a high score record
names by its number (docs/rewrite/watch-replays.md)."""

from __future__ import annotations

import re
from pathlib import Path

from ..game_modes import GameMode

REPLAY_MODE_NAMES = {
    GameMode.SURVIVAL: "survival",
    GameMode.RUSH: "rush",
    GameMode.QUESTS: "quest",
    GameMode.TYPO: "typo",
    GameMode.TUTORIAL: "tutorial",
}
_NUMBERED = re.compile(r"(\d+)-([a-z]+)\.crd")


def replay_file_name(number: int, game_mode: GameMode) -> str:
    return f"{number}-{REPLAY_MODE_NAMES[game_mode]}.crd"


def next_replay_number(replay_dir: Path, *, after: int = 0) -> int:
    """One more than the highest number in `replay_dir`, or than `after` (a number taken but not yet written)."""

    taken = [int(match[1]) for path in replay_dir.glob("*.crd") if (match := _NUMBERED.fullmatch(path.name))]
    return max([after, *taken]) + 1


def numbered_replay(replay_dir: Path, number: int) -> Path | None:
    """The replay numbered `number`, if it is written."""

    for path in replay_dir.glob(f"{number}-*.crd"):
        if (match := _NUMBERED.fullmatch(path.name)) and int(match[1]) == number:
            return path
    return None
