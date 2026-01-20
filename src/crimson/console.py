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

    def exec_line(self, line: str) -> None:
        tokens = line.strip().split()
        if not tokens:
            return
        name, args = tokens[0], tokens[1:]
        handler = self.commands.get(name)
        if handler is not None:
            handler(args)
            return
        if name in self.cvars:
            if args:
                self.cvars[name] = " ".join(args)
                self.log.log(f"cvar {name} set to {self.cvars[name]}")
            else:
                self.log.log(f"cvar {name} = {self.cvars[name]}")
            return
        self.log.log(f"unknown command: {name}")


def create_console(base_dir: Path) -> ConsoleState:
    return ConsoleState(base_dir=base_dir, log=ConsoleLog(base_dir=base_dir))


def _make_noop_command(console: ConsoleState, name: str) -> CommandHandler:
    def _handler(args: list[str]) -> None:
        console.log.log(f"command {name} called with {len(args)} args")

    return _handler


def register_boot_commands(console: ConsoleState) -> None:
    commands = (
        "setGammaRamp",
        "snd_addGameTune",
        "generateterrain",
        "telltimesurvived",
        "setresourcepaq",
        "loadtexture",
        "openurl",
        "sndfreqadjustment",
    )
    for name in commands:
        console.register_command(name, _make_noop_command(console, name))


def register_core_cvars(console: ConsoleState, width: int, height: int) -> None:
    console.register_cvar("v_width", str(width))
    console.register_cvar("v_height", str(height))
