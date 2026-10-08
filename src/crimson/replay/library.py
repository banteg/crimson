"""Where a client keeps its replays: one numbered file per run, `replays/<n>-<mode>.crd`, which a high score record
names by its number (docs/rewrite/watch-replays.md).

A number is never handed out twice: `.last-number` keeps the last one, written when it is reserved, so a replay still
being written or since deleted keeps its number. A run whose replay failed to save names a file that never appears.
"""

from __future__ import annotations

import re
from pathlib import Path

from grim.atomic_write import atomic_write_bytes

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


_LAST_NUMBER = ".last-number"


def reserve_replay_number(replay_dir: Path) -> int:
    """The next replay number in `replay_dir`, reserved: one more than the last handed out or written."""

    replay_dir.mkdir(parents=True, exist_ok=True)
    last_path = replay_dir / _LAST_NUMBER
    last = int(last_path.read_text()) if last_path.exists() else 0
    taken = [int(match[1]) for path in replay_dir.glob("*.crd") if (match := _NUMBERED.fullmatch(path.name))]
    number = max([last, *taken]) + 1
    atomic_write_bytes(last_path, str(number).encode())
    return number


def numbered_replay(replay_dir: Path, number: int) -> Path | None:
    """The replay numbered `number`, if it is written."""

    for path in replay_dir.glob(f"{number}-*.crd"):
        if (match := _NUMBERED.fullmatch(path.name)) and int(match[1]) == number:
            return path
    return None
