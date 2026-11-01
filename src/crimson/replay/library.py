"""Where a client keeps its replays: one numbered file per run, `replays/<n>-<mode>.crd`, which a high score record
names by its number (docs/formats/replay.md).

A number is never handed out twice: `.last-number` keeps the last one, written when it is reserved, so a replay still
being written or since deleted keeps its number. A run whose replay failed to save names a file that never appears.
"""

from __future__ import annotations

import re
from pathlib import Path

from grim.atomic_write import atomic_write_bytes, locked_file

from ..game_modes import GameMode

REPLAY_MODE_NAMES = {
    GameMode.SURVIVAL: "survival",
    GameMode.RUSH: "rush",
    GameMode.QUESTS: "quest",
    GameMode.TYPO: "typo",
    GameMode.TUTORIAL: "tutorial",
}
_NUMBERED = re.compile(r"([0-9]+)-([a-z]+)\.crd")


def replay_file_name(number: int, game_mode: GameMode) -> str:
    return f"{number}-{REPLAY_MODE_NAMES[game_mode]}.crd"


_LAST_NUMBER = ".last-number"


def reserve_replay_number(replay_dir: Path) -> int:
    """The next replay number in `replay_dir`, reserved: one more than the last handed out or written."""

    replay_dir.mkdir(parents=True, exist_ok=True)
    last_path = replay_dir / _LAST_NUMBER
    with locked_file(replay_dir / ".last-number.lock"):
        try:
            counter = last_path.read_bytes().strip()
        except FileNotFoundError:
            counter = b"0"
        if not counter.isdigit():
            raise ValueError(f"Invalid replay counter in {last_path}")
        taken = (int(match[1]) for path in replay_dir.iterdir() if (match := _NUMBERED.fullmatch(path.name)))
        number = max(int(counter), max(taken, default=0)) + 1
        if number > 0x7FFFFFFF:
            raise ValueError("Replay numbers are exhausted")
        atomic_write_bytes(last_path, str(number).encode())
        return number


def numbered_replay(replay_dir: Path, number: int) -> Path | None:
    """The replay numbered `number`, if it is written."""

    for path in replay_dir.glob(f"{number}-*.crd"):
        if (match := _NUMBERED.fullmatch(path.name)) and int(match[1]) == number:
            return path
    return None
