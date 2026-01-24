from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

import pyray as rl

from grim.fonts.grim_mono import (
    GRIM_MONO_LINE_HEIGHT,
    GrimMonoFont,
    draw_grim_mono_text,
    load_grim_mono_font,
)

CONSOLE_LOG_NAME = "console.log"
MAX_CONSOLE_LINES = 0x1000
MAX_CONSOLE_INPUT = 0x3FF
DEFAULT_CONSOLE_HEIGHT = 300
EXTENDED_CONSOLE_HEIGHT = 480

CONSOLE_TEXT_SCALE = 0.7
CONSOLE_PADDING_X = 12.0
CONSOLE_PADDING_Y = 8.0
CONSOLE_BG_COLOR = rl.Color(10, 10, 12, 200)
CONSOLE_TEXT_COLOR = rl.Color(230, 230, 230, 255)
CONSOLE_ACCENT_COLOR = rl.Color(200, 220, 160, 255)
CONSOLE_CARET_COLOR = rl.Color(255, 255, 255, 255)

CommandHandler = Callable[[list[str]], None]


def game_build_path(base_dir: Path, name: str) -> Path:
    return base_dir / name


def _parse_float(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return 0.0


def _normalize_script_path(name: str) -> Path:
    raw = name.strip().strip("\"'")
    normalized = raw.replace("\\", "/")
    return Path(normalized)


@dataclass(slots=True)
class ConsoleCvar:
    name: str
    value: str
    value_f: float

    @classmethod
    def from_value(cls, name: str, value: str) -> "ConsoleCvar":
        return cls(name=name, value=value, value_f=_parse_float(value))


@dataclass(slots=True)
class ConsoleLog:
    base_dir: Path
    lines: list[str] = field(default_factory=list)
    flushed_index: int = 0

    def log(self, message: str) -> None:
        self.lines.append(message)
        if len(self.lines) > MAX_CONSOLE_LINES:
            overflow = len(self.lines) - MAX_CONSOLE_LINES
            del self.lines[:overflow]
            self.flushed_index = max(0, self.flushed_index - overflow)

    def clear(self) -> None:
        self.lines.clear()
        self.flushed_index = 0

    def flush(self) -> None:
        if self.flushed_index >= len(self.lines):
            return
        path = game_build_path(self.base_dir, CONSOLE_LOG_NAME)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            for line in self.lines[self.flushed_index :]:
                handle.write(line.rstrip() + "\n")
        self.flushed_index = len(self.lines)


@dataclass(slots=True)
class ConsoleState:
    base_dir: Path
    log: ConsoleLog
    assets_dir: Path | None = None
    commands: dict[str, CommandHandler] = field(default_factory=dict)
    cvars: dict[str, ConsoleCvar] = field(default_factory=dict)
    open_flag: bool = False
    input_enabled: bool = False
    input_ready: bool = False
    input_buffer: str = ""
    input_caret: int = 0
    history: list[str] = field(default_factory=list)
    history_index: int | None = None
    history_pending: str = ""
    scroll_offset: int = 0
    height_px: int = DEFAULT_CONSOLE_HEIGHT
    echo_enabled: bool = True
    quit_requested: bool = False
    prompt_string: str = "> %s"
    _font: GrimMonoFont | None = field(default=None, init=False, repr=False)
    _font_error: str | None = field(default=None, init=False, repr=False)

    def register_command(self, name: str, handler: CommandHandler) -> None:
        self.commands[name] = handler

    def register_cvar(self, name: str, value: str) -> None:
        self.cvars[name] = ConsoleCvar.from_value(name, value)

    def set_open(self, open_flag: bool) -> None:
        self.open_flag = open_flag
        self.input_enabled = open_flag
        self.input_ready = False
        self.history_index = None
        self._flush_input_queue()

    def toggle_open(self) -> None:
        self.set_open(not self.open_flag)

    def handle_hotkey(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_GRAVE):
            self.toggle_open()

    def exec_line(self, line: str) -> None:
        tokens = self._tokenize_line(line)
        if not tokens:
            return
        name, args = tokens[0], tokens[1:]
        cvar = self.cvars.get(name)
        if cvar is not None:
            if args:
                value = " ".join(args)
                cvar.value = value
                cvar.value_f = _parse_float(value)
                self.log.log(f"\"{cvar.name}\" set to \"{cvar.value}\" ({cvar.value_f:.6f})")
            else:
                self.log.log(f"\"{cvar.name}\" is \"{cvar.value}\" ({cvar.value_f:.6f})")
            return
        handler = self.commands.get(name)
        if handler is not None:
            handler(args)
            return
        self.log.log(f"Unknown command \"{name}\"")

    def update(self) -> None:
        if not self.open_flag or not self.input_enabled:
            return
        ctrl_down = rl.is_key_down(rl.KeyboardKey.KEY_LEFT_CONTROL) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_CONTROL)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            if ctrl_down:
                self._scroll_lines(1)
            else:
                self._history_prev()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            if ctrl_down:
                self._scroll_lines(-1)
            else:
                self._history_next()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_UP):
            self._scroll_lines(self._visible_log_lines())
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN):
            self._scroll_lines(-self._visible_log_lines())
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
            self.input_caret = max(0, self.input_caret - 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self.input_caret = min(len(self.input_buffer), self.input_caret + 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_HOME):
            self.input_caret = 0
        if rl.is_key_pressed(rl.KeyboardKey.KEY_END):
            self.input_caret = len(self.input_buffer)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._autocomplete()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
            if self.input_caret > 0:
                self._exit_history_edit()
                self.input_buffer = (
                    self.input_buffer[: self.input_caret - 1] + self.input_buffer[self.input_caret :]
                )
                self.input_caret -= 1
        if rl.is_key_pressed(rl.KeyboardKey.KEY_DELETE):
            if self.input_caret < len(self.input_buffer):
                self._exit_history_edit()
                self.input_buffer = (
                    self.input_buffer[: self.input_caret] + self.input_buffer[self.input_caret + 1 :]
                )
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            self._submit_input()
        self._poll_text_input()

    def draw(self) -> None:
        if not self.open_flag:
            return
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        height = min(float(self.height_px), screen_h)
        if height <= 0.0:
            return
        rl.draw_rectangle(0, 0, int(screen_w), int(height), CONSOLE_BG_COLOR)
        line_height = self._line_height()
        if line_height <= 0.0:
            return
        pad_x = CONSOLE_PADDING_X
        pad_y = CONSOLE_PADDING_Y
        total_lines = max(int((height - pad_y * 2) // line_height), 1)
        log_lines = max(total_lines - 1, 1)
        visible = self._visible_log_slice(log_lines)
        y = pad_y
        for line in visible:
            self._draw_text(line, pad_x, y, CONSOLE_TEXT_SCALE, CONSOLE_TEXT_COLOR)
            y += line_height
        prompt = self._prompt_text()
        input_y = height - pad_y - line_height
        self._draw_text(prompt, pad_x, input_y, CONSOLE_TEXT_SCALE, CONSOLE_ACCENT_COLOR)
        caret_x = self._caret_x(prompt_prefix=self._prompt_prefix())
        rl.draw_rectangle(int(caret_x), int(input_y), 2, int(line_height), CONSOLE_CARET_COLOR)

    def close(self) -> None:
        if self._font is not None:
            rl.unload_texture(self._font.texture)
            self._font = None

    def _tokenize_line(self, line: str) -> list[str]:
        return line.strip().split()

    def _prompt_prefix(self) -> str:
        if "%s" in self.prompt_string:
            return self.prompt_string.split("%s", 1)[0]
        return self.prompt_string

    def _prompt_text(self) -> str:
        if "%s" in self.prompt_string:
            return self.prompt_string.replace("%s", self.input_buffer)
        return f"{self.prompt_string}{self.input_buffer}"

    def _history_prev(self) -> None:
        if not self.history:
            return
        if self.history_index is None:
            self.history_index = len(self.history) - 1
            self.history_pending = self.input_buffer
        elif self.history_index > 0:
            self.history_index -= 1
        self.input_buffer = self.history[self.history_index]
        self.input_caret = len(self.input_buffer)

    def _history_next(self) -> None:
        if self.history_index is None:
            return
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.input_buffer = self.history[self.history_index]
        else:
            self.history_index = None
            self.input_buffer = self.history_pending
        self.input_caret = len(self.input_buffer)

    def _exit_history_edit(self) -> None:
        if self.history_index is not None:
            self.history_index = None
            self.history_pending = self.input_buffer

    def _submit_input(self) -> None:
        line = self.input_buffer.strip()
        self.input_ready = True
        self.input_buffer = ""
        self.input_caret = 0
        self.history_index = None
        if not line:
            return
        if self.echo_enabled:
            if "%s" in self.prompt_string:
                self.log.log(self.prompt_string.replace("%s", line))
            else:
                self.log.log(f"{self.prompt_string}{line}")
        if not self.history or self.history[-1] != line:
            self.history.append(line)
        self.exec_line(line)
        self.scroll_offset = 0

    def _poll_text_input(self) -> None:
        while True:
            value = rl.get_char_pressed()
            if value == 0:
                break
            if value < 0x20 or value > 0xFF:
                continue
            if len(self.input_buffer) >= MAX_CONSOLE_INPUT:
                continue
            char = chr(value)
            self._exit_history_edit()
            self.input_buffer = (
                self.input_buffer[: self.input_caret] + char + self.input_buffer[self.input_caret :]
            )
            self.input_caret += 1

    def _autocomplete(self) -> None:
        if not self.input_buffer:
            return
        token_start = len(self.input_buffer) - len(self.input_buffer.lstrip())
        if token_start >= len(self.input_buffer):
            return
        token_end = self.input_buffer.find(" ", token_start)
        if token_end == -1:
            token_end = len(self.input_buffer)
        if self.input_caret > token_end:
            return
        prefix = self.input_buffer[token_start:self.input_caret]
        if not prefix:
            return
        match = self._autocomplete_name(prefix, self.cvars.keys())
        if match is None:
            match = self._autocomplete_name(prefix, self.commands.keys())
        if match is None:
            return
        self.input_buffer = self.input_buffer[:token_start] + match + self.input_buffer[token_end:]
        self.input_caret = token_start + len(match)

    def _autocomplete_name(self, prefix: str, names: Iterable[str]) -> str | None:
        for name in names:
            if name == prefix:
                return name
        for name in names:
            if name.startswith(prefix):
                return name
        return None

    def _scroll_lines(self, delta: int) -> None:
        visible = self._visible_log_lines()
        max_offset = max(0, len(self.log.lines) - visible)
        if max_offset <= 0:
            self.scroll_offset = 0
            return
        self.scroll_offset = max(0, min(max_offset, self.scroll_offset + int(delta)))

    def _visible_log_lines(self) -> int:
        height = min(float(self.height_px), float(rl.get_screen_height()))
        if height <= 0.0:
            return 1
        line_height = self._line_height()
        if line_height <= 0.0:
            return 1
        total_lines = max(int((height - CONSOLE_PADDING_Y * 2) // line_height), 1)
        return max(total_lines - 1, 1)

    def _visible_log_slice(self, log_lines: int) -> list[str]:
        if not self.log.lines:
            return []
        max_offset = max(0, len(self.log.lines) - log_lines)
        if self.scroll_offset > max_offset:
            self.scroll_offset = max_offset
        start = max(0, len(self.log.lines) - log_lines - self.scroll_offset)
        end = min(len(self.log.lines), start + log_lines)
        return self.log.lines[start:end]

    def _line_height(self) -> float:
        if self._ensure_font() is not None:
            return GRIM_MONO_LINE_HEIGHT * CONSOLE_TEXT_SCALE
        return float(20 * CONSOLE_TEXT_SCALE)

    def _ensure_font(self) -> GrimMonoFont | None:
        if self._font is not None:
            return self._font
        if self._font_error is not None:
            return None
        if self.assets_dir is None:
            self._font_error = "missing assets dir"
            return None
        missing_assets: list[str] = []
        try:
            self._font = load_grim_mono_font(self.assets_dir, missing_assets)
        except FileNotFoundError as exc:
            self._font_error = str(exc)
            self._font = None
        return self._font

    def _draw_text(self, text: str, x: float, y: float, scale: float, color: rl.Color) -> None:
        font = self._ensure_font()
        if font is None:
            rl.draw_text(text, int(x), int(y), int(20 * scale), color)
            return
        draw_grim_mono_text(font, text, x, y, scale, color)

    def _caret_x(self, prompt_prefix: str) -> float:
        font = self._ensure_font()
        advance = 16.0 * CONSOLE_TEXT_SCALE
        if font is not None:
            advance = font.advance * CONSOLE_TEXT_SCALE
        count = self._advance_count(prompt_prefix + self.input_buffer[: self.input_caret])
        return CONSOLE_PADDING_X + advance * float(count + 1)

    def _advance_count(self, text: str) -> int:
        count = 0
        skip_advance = False
        for value in text.encode("latin-1", errors="replace"):
            if value == 0x0A:
                continue
            if value == 0x0D:
                continue
            if value == 0xA7:
                skip_advance = True
                continue
            if skip_advance:
                skip_advance = False
                continue
            count += 1
        return count

    def _flush_input_queue(self) -> None:
        while rl.get_char_pressed():
            pass
        while rl.get_key_pressed():
            pass


def create_console(base_dir: Path, assets_dir: Path | None = None) -> ConsoleState:
    console = ConsoleState(base_dir=base_dir, log=ConsoleLog(base_dir=base_dir), assets_dir=assets_dir)
    register_core_commands(console)
    return console


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


def register_core_commands(console: ConsoleState) -> None:
    def cmdlist(_args: list[str]) -> None:
        for name in console.commands.keys():
            console.log.log(name)
        console.log.log(f"{len(console.commands)} commands")

    def vars_cmd(_args: list[str]) -> None:
        for name in console.cvars.keys():
            console.log.log(name)
        console.log.log(f"{len(console.cvars)} variables")

    def cmd_set(args: list[str]) -> None:
        if len(args) < 2:
            console.log.log("Usage: set <var> <value>")
            return
        name = args[0]
        value = " ".join(args[1:])
        console.register_cvar(name, value)
        console.log.log(f"'{name}' set to '{value}'")

    def cmd_echo(args: list[str]) -> None:
        if not args:
            console.log.log(f"echo is {'on' if console.echo_enabled else 'off'}")
            return
        mode = args[0].lower()
        if mode in {"on", "off"}:
            console.echo_enabled = mode == "on"
            console.log.log(f"echo {mode}")
            return
        console.log.log(" ".join(args))

    def cmd_quit(_args: list[str]) -> None:
        console.quit_requested = True

    def cmd_clear(_args: list[str]) -> None:
        console.log.clear()
        console.scroll_offset = 0

    def cmd_extend(_args: list[str]) -> None:
        console.height_px = EXTENDED_CONSOLE_HEIGHT

    def cmd_minimize(_args: list[str]) -> None:
        console.height_px = DEFAULT_CONSOLE_HEIGHT

    def cmd_exec(args: list[str]) -> None:
        if not args:
            console.log.log("Usage: exec <file>")
            return
        target = _normalize_script_path(args[0])
        path = target if target.is_absolute() else game_build_path(console.base_dir, str(target))
        if not path.is_file():
            console.log.log(f"Cannot open '{args[0]}'")
            return
        console.log.log(f"Executing '{args[0]}'")
        try:
            for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if line:
                    console.exec_line(line)
        except OSError:
            console.log.log(f"Cannot open '{args[0]}'")

    console.register_command("cmdlist", cmdlist)
    console.register_command("vars", vars_cmd)
    console.register_command("set", cmd_set)
    console.register_command("echo", cmd_echo)
    console.register_command("quit", cmd_quit)
    console.register_command("clear", cmd_clear)
    console.register_command("extendconsole", cmd_extend)
    console.register_command("minimizeconsole", cmd_minimize)
    console.register_command("exec", cmd_exec)
