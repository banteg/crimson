from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

import math
import pyray as rl

from grim.fonts.grim_mono import (
    GrimMonoFont,
    draw_grim_mono_text,
    load_grim_mono_font,
)
from grim.fonts.small import (
    SmallFontData,
    draw_small_text,
    load_small_font,
    measure_small_text_width,
)

CONSOLE_LOG_NAME = "console.log"
MAX_CONSOLE_LINES = 0x1000
MAX_CONSOLE_INPUT = 0x3FF
DEFAULT_CONSOLE_HEIGHT = 300
EXTENDED_CONSOLE_HEIGHT = 480
CONSOLE_VERSION_TEXT = "Crimsonland 1.9.93"
CONSOLE_ANIM_SPEED = 3.5
CONSOLE_BLINK_SPEED = 3.0
CONSOLE_LINE_HEIGHT = 16.0
CONSOLE_MONO_SCALE = 0.5
CONSOLE_SMALL_SCALE = 1.0
CONSOLE_TEXT_X = 10.0
CONSOLE_INPUT_X_MONO = 26.0
CONSOLE_VERSION_OFFSET_X = 210.0
CONSOLE_VERSION_OFFSET_Y = 18.0
CONSOLE_BORDER_HEIGHT = 4.0
CONSOLE_BG_COLOR = (0.140625, 0.1875, 0.2890625)
CONSOLE_BORDER_COLOR = (0.21875, 0.265625, 0.3671875)
CONSOLE_PROMPT_MONO = ">"
CONSOLE_PROMPT_SMALL_FMT = ">%s"
CONSOLE_CARET_TEXT = "_"

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


def _resolve_script_path(console: "ConsoleState", target: Path) -> Path | None:
    if target.is_absolute():
        return target if target.is_file() else None
    for base in console.script_dirs:
        candidate = base / target
        if candidate.is_file():
            return candidate
    return None


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _rgba(r: float, g: float, b: float, a: float) -> rl.Color:
    return rl.Color(
        int(_clamp(r, 0.0, 1.0) * 255),
        int(_clamp(g, 0.0, 1.0) * 255),
        int(_clamp(b, 0.0, 1.0) * 255),
        int(_clamp(a, 0.0, 1.0) * 255),
    )


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
    script_dirs: tuple[Path, ...] = field(default_factory=tuple)
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
    _mono_font: GrimMonoFont | None = field(default=None, init=False, repr=False)
    _mono_font_error: str | None = field(default=None, init=False, repr=False)
    _small_font: SmallFontData | None = field(default=None, init=False, repr=False)
    _small_font_error: str | None = field(default=None, init=False, repr=False)
    _slide_t: float = 1.0
    _offset_y: float = field(default=0.0, init=False)
    _blink_time: float = 0.0

    def register_command(self, name: str, handler: CommandHandler) -> None:
        self.commands[name] = handler

    def register_cvar(self, name: str, value: str) -> None:
        self.cvars[name] = ConsoleCvar.from_value(name, value)

    def add_script_dir(self, path: Path | None) -> None:
        if path is None:
            return
        if path in self.script_dirs:
            return
        self.script_dirs = (*self.script_dirs, path)

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

    def update(self, dt: float) -> None:
        frame_dt = min(dt, 0.1)
        self._blink_time += frame_dt
        self._update_slide(frame_dt)
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
            self._scroll_lines(2)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN):
            self._scroll_lines(-2)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
            self.input_caret = max(0, self.input_caret - 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self.input_caret = min(len(self.input_buffer), self.input_caret + 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_HOME):
            self._scroll_lines(0x14)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_END):
            self.scroll_offset = 0
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
        height = float(self.height_px)
        if height <= 0.0:
            return
        ratio = self._open_ratio(height)
        if ratio <= 0.0:
            return
        screen_w = float(rl.get_screen_width())
        offset_y = self._offset_y
        rl.draw_rectangle(
            0,
            int(offset_y),
            int(screen_w),
            int(height),
            _rgba(*CONSOLE_BG_COLOR, ratio),
        )
        border_y = int(offset_y + height - CONSOLE_BORDER_HEIGHT)
        rl.draw_rectangle(
            0,
            border_y,
            int(screen_w),
            int(CONSOLE_BORDER_HEIGHT),
            _rgba(*CONSOLE_BORDER_COLOR, ratio),
        )

        version_x = screen_w - CONSOLE_VERSION_OFFSET_X
        version_y = offset_y + height - CONSOLE_VERSION_OFFSET_Y
        self._draw_version_text(version_x, version_y, _rgba(1.0, 1.0, 1.0, ratio * 0.3))

        visible, visible_count = self._visible_log_block(height)
        input_y = offset_y + (visible_count + 1) * CONSOLE_LINE_HEIGHT
        text_color = _rgba(1.0, 1.0, 1.0, ratio)
        use_mono = self._use_mono_font()
        if use_mono:
            self._draw_mono_text(CONSOLE_PROMPT_MONO, CONSOLE_TEXT_X, input_y, text_color)
            self._draw_mono_text(self.input_buffer, CONSOLE_INPUT_X_MONO, input_y, text_color)
        else:
            prompt = CONSOLE_PROMPT_SMALL_FMT.replace("%s", self.input_buffer)
            self._draw_small_text(prompt, CONSOLE_TEXT_X, input_y, text_color)

        log_color = _rgba(0.6, 0.6, 0.7, ratio)
        y = offset_y + CONSOLE_LINE_HEIGHT
        for line in visible:
            if use_mono:
                self._draw_mono_text(line, CONSOLE_TEXT_X, y, log_color)
            else:
                self._draw_small_text(line, CONSOLE_TEXT_X, y, log_color)
            y += CONSOLE_LINE_HEIGHT

        caret_alpha = ratio * self._caret_blink_alpha()
        caret_color = _rgba(1.0, 1.0, 1.0, caret_alpha)
        caret_y = input_y + 2.0
        if use_mono:
            caret_x = CONSOLE_INPUT_X_MONO + float(self.input_caret) * 8.0
            self._draw_mono_text(CONSOLE_CARET_TEXT, caret_x, caret_y, caret_color)
        else:
            caret_x = self._small_caret_x()
            self._draw_small_text(CONSOLE_CARET_TEXT, caret_x, caret_y, caret_color)

    def close(self) -> None:
        if self._mono_font is not None:
            rl.unload_texture(self._mono_font.texture)
            self._mono_font = None
        if self._small_font is not None:
            rl.unload_texture(self._small_font.texture)
            self._small_font = None

    def _tokenize_line(self, line: str) -> list[str]:
        stripped = line.strip()
        if not stripped:
            return []
        if stripped.startswith("//"):
            return []
        return stripped.split()

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
        self.input_ready = False
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
        max_offset = self._max_scroll_offset()
        if max_offset <= 0:
            self.scroll_offset = 0
            return
        self.scroll_offset = max(0, min(max_offset, self.scroll_offset + int(delta)))

    def _max_visible_lines(self, height: float | None = None) -> int:
        use_height = height if height is not None else float(self.height_px)
        if use_height <= 0.0:
            return 0
        return max(int(use_height // CONSOLE_LINE_HEIGHT) - 2, 0)

    def _max_scroll_offset(self) -> int:
        max_lines = self._max_visible_lines()
        log_count = len(self.log.lines)
        visible = min(log_count, max_lines)
        return max(0, log_count - visible)

    def _visible_log_block(self, height: float) -> tuple[list[str], int]:
        max_lines = self._max_visible_lines(height)
        log_count = len(self.log.lines)
        visible_count = min(log_count, max_lines)
        if visible_count <= 0:
            return [], 0
        max_offset = max(0, log_count - visible_count)
        if self.scroll_offset > max_offset:
            self.scroll_offset = max_offset
        start = max(0, log_count - visible_count - self.scroll_offset)
        end = min(log_count, start + visible_count)
        return self.log.lines[start:end], visible_count

    def _update_slide(self, dt: float) -> None:
        if self.open_flag:
            self._slide_t = max(0.0, self._slide_t - dt * CONSOLE_ANIM_SPEED)
        else:
            self._slide_t = min(1.0, self._slide_t + dt * CONSOLE_ANIM_SPEED)
        height = float(self.height_px)
        if height <= 0.0:
            self._offset_y = -height
            return
        eased = math.sin((1.0 - self._slide_t) * math.pi / 2.0)
        self._offset_y = eased * height - height

    def _open_ratio(self, height: float) -> float:
        if height <= 0.0:
            return 0.0
        return _clamp((height + self._offset_y) / height, 0.0, 1.0)

    def _caret_blink_alpha(self) -> float:
        pulse = math.sin(self._blink_time * CONSOLE_BLINK_SPEED)
        value = max(0.2, abs(pulse) ** 2)
        return _clamp(value, 0.0, 1.0)

    def _use_mono_font(self) -> bool:
        cvar = self.cvars.get("con_monoFont")
        if cvar is None:
            return False
        return bool(cvar.value_f)

    def _ensure_mono_font(self) -> GrimMonoFont | None:
        if self._mono_font is not None:
            return self._mono_font
        if self._mono_font_error is not None:
            return None
        if self.assets_dir is None:
            self._mono_font_error = "missing assets dir"
            return None
        missing_assets: list[str] = []
        try:
            self._mono_font = load_grim_mono_font(self.assets_dir, missing_assets)
        except FileNotFoundError as exc:
            self._mono_font_error = str(exc)
            self._mono_font = None
        return self._mono_font

    def _ensure_small_font(self) -> SmallFontData | None:
        if self._small_font is not None:
            return self._small_font
        if self._small_font_error is not None:
            return None
        if self.assets_dir is None:
            self._small_font_error = "missing assets dir"
            return None
        missing_assets: list[str] = []
        try:
            self._small_font = load_small_font(self.assets_dir, missing_assets)
        except FileNotFoundError as exc:
            self._small_font_error = str(exc)
            self._small_font = None
        return self._small_font

    def _draw_mono_text(self, text: str, x: float, y: float, color: rl.Color) -> None:
        font = self._ensure_mono_font()
        if font is None:
            rl.draw_text(text, int(x), int(y), int(16 * CONSOLE_MONO_SCALE), color)
            return
        advance = font.advance * CONSOLE_FONT_SCALE
        draw_grim_mono_text(font, text, x - advance, y, CONSOLE_MONO_SCALE, color)

    def _draw_small_text(self, text: str, x: float, y: float, color: rl.Color) -> None:
        font = self._ensure_small_font()
        if font is None:
            rl.draw_text(text, int(x), int(y), int(16 * CONSOLE_SMALL_SCALE), color)
            return
        draw_small_text(font, text, x, y, CONSOLE_SMALL_SCALE, color)

    def _draw_version_text(self, x: float, y: float, color: rl.Color) -> None:
        font = self._ensure_small_font()
        if font is None:
            self._draw_mono_text(CONSOLE_VERSION_TEXT, x, y, color)
            return
        draw_small_text(font, CONSOLE_VERSION_TEXT, x, y, CONSOLE_SMALL_SCALE, color)

    def _small_caret_x(self) -> float:
        font = self._ensure_small_font()
        if font is None:
            return CONSOLE_TEXT_X + 16.0 + float(self.input_caret) * 8.0
        prompt_w = measure_small_text_width(font, CONSOLE_PROMPT_SMALL_FMT.replace("%s", ""), CONSOLE_SMALL_SCALE)
        input_w = measure_small_text_width(font, self.input_buffer[: self.input_caret], CONSOLE_SMALL_SCALE)
        return CONSOLE_TEXT_X + prompt_w + input_w

    def _flush_input_queue(self) -> None:
        while rl.get_char_pressed():
            pass
        while rl.get_key_pressed():
            pass


def create_console(base_dir: Path, assets_dir: Path | None = None) -> ConsoleState:
    script_dirs: tuple[Path, ...] = (base_dir,)
    if assets_dir is not None and assets_dir != base_dir:
        script_dirs = (*script_dirs, assets_dir)
    console = ConsoleState(
        base_dir=base_dir,
        log=ConsoleLog(base_dir=base_dir),
        assets_dir=assets_dir,
        script_dirs=script_dirs,
    )
    console.register_cvar("version", CONSOLE_VERSION_TEXT)
    console.register_cvar("con_monoFont", "1")
    if console.open_flag:
        console._slide_t = 0.0
        console._offset_y = 0.0
    else:
        console._slide_t = 1.0
        console._offset_y = -float(console.height_px)
    register_core_commands(console)
    return console


def _make_noop_command(console: ConsoleState, name: str) -> CommandHandler:
    def _handler(args: list[str]) -> None:
        console.log.log(f"command {name} called with {len(args)} args")

    return _handler


def register_boot_commands(
    console: ConsoleState, handlers: dict[str, CommandHandler] | None = None
) -> None:
    resolved = handlers or {}
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
        handler = resolved.get(name)
        if handler is None:
            handler = _make_noop_command(console, name)
        console.register_command(name, handler)


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
            console.log.log("exec <script>")
            return
        target = _normalize_script_path(args[0])
        path = _resolve_script_path(console, target)
        if path is None:
            console.log.log(f"Cannot open file '{args[0]}'")
            return
        console.log.log(f"Executing '{args[0]}'")
        try:
            for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if line:
                    console.exec_line(line)
        except OSError:
            console.log.log(f"Cannot open file '{args[0]}'")

    console.register_command("cmdlist", cmdlist)
    console.register_command("vars", vars_cmd)
    console.register_command("set", cmd_set)
    console.register_command("echo", cmd_echo)
    console.register_command("quit", cmd_quit)
    console.register_command("clear", cmd_clear)
    console.register_command("extendconsole", cmd_extend)
    console.register_command("minimizeconsole", cmd_minimize)
    console.register_command("exec", cmd_exec)
