from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

CONSOLE_LOG_NAME = "console.log"
MAX_CONSOLE_LINES = 0x1000

CommandHandler = Callable[[list[str]], None]


def game_build_path(base_dir: Path, name: str) -> Path:
    return base_dir / name


@dataclass(slots=True)
class ConsoleLog:
    base_dir: Path
    lines: list[str] = field(default_factory=list)

    def log(self, message: str) -> None:
        self.lines.append(message)
        if len(self.lines) > MAX_CONSOLE_LINES:
            self.lines.pop(0)

    def flush(self) -> None:
        path = game_build_path(self.base_dir, CONSOLE_LOG_NAME)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            for line in self.lines:
                handle.write(line.rstrip() + "\n")
        self.lines.clear()


@dataclass(slots=True)
class ConsoleState:
    base_dir: Path
    log: ConsoleLog
    commands: dict[str, CommandHandler] = field(default_factory=dict)
    cvars: dict[str, str] = field(default_factory=dict)

    def register_command(self, name: str, handler: CommandHandler) -> None:
        self.commands[name] = handler

    def register_cvar(self, name: str, value: str) -> None:
        self.cvars[name] = value


def create_console(base_dir: Path) -> ConsoleState:
    return ConsoleState(base_dir=base_dir, log=ConsoleLog(base_dir=base_dir))
