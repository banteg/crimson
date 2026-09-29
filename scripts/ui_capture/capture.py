"""Drive the real game loop with scripted input at a fixed 60 Hz and screenshot named frames.

usage: uv run python scripts/ui_capture/capture.py <scenario.py> <out_dir> [--seed N] [--size WxH] [--assets DIR]

A scenario module defines STEPS, a list of ops:
  ("wait", frames)            advance frames with no new input
  ("key", "KEY_ENTER")        press and release a key over one frame
  ("hold", "KEY_W", frames)   hold a key down
  ("move", x, y)              put the mouse at canvas coords (sticky)
  ("click", x, y)             move and click the left button for one frame
  ("rclick",)                 right-click at the current mouse position for one frame
  ("fire", frames)            hold the left button (non-blocking; combine with move/wait)
  ("text", "abc")             one char per frame
  ("hook", fn)                call fn(GameState) on the live game (no frame consumed)
  ("shot", "name")            screenshot the frame drawn last
Optional STATUS(status) mutates the fresh game status before boot.
"""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

import pyray as rl

DT = 1.0 / 60.0


class Driver:
    def __init__(self, steps: list[tuple], out_dir: Path) -> None:
        self.steps = list(steps)
        self.out_dir = out_dir
        self.frame = 0
        self.pressed: set[int] = set()
        self.down: set[int] = set()
        self.held: dict[int, int] = {}
        self.mouse = rl.Vector2(0.0, 0.0)
        self.prev_mouse = rl.Vector2(0.0, 0.0)
        self.mouse_pressed: set[int] = set()
        self.mouse_held = 0
        self.chars: list[int] = []
        self.key_queue: list[int] = []
        self.pending_shot: str | None = None
        self.wait = 0
        self.game_state = None

    def _key(self, name: str) -> int:
        return int(getattr(rl.KeyboardKey, name))

    def advance(self) -> bool:
        """Called at the top of each loop iteration; returns True when the script is done."""
        if self.pending_shot is not None:
            path = self.out_dir / f"{self.pending_shot}.png"
            image = rl.load_image_from_screen()
            rl.export_image(image, str(path))
            rl.unload_image(image)
            print(f"shot {path.name} frame={self.frame}", flush=True)
            self.pending_shot = None
        self.frame += 1
        self.pressed.clear()
        self.mouse_pressed.clear()
        self.chars.clear()
        self.key_queue.clear()
        self.prev_mouse = rl.Vector2(self.mouse.x, self.mouse.y)
        for key in list(self.held):
            self.held[key] -= 1
            if self.held[key] <= 0:
                del self.held[key]
        self.down = set(self.held)
        if self.mouse_held > 0:
            self.mouse_held -= 1
        if self.wait > 0:
            self.wait -= 1
            return False
        while self.steps:
            op, *args = self.steps.pop(0)
            match op:
                case "wait":
                    self.wait = int(args[0]) - 1
                    return False
                case "key":
                    key = self._key(args[0])
                    self.pressed.add(key)
                    self.down.add(key)
                    self.key_queue.append(key)
                    return False
                case "hold":
                    key = self._key(args[0])
                    self.held[key] = int(args[1])
                    self.pressed.add(key)
                    self.down.add(key)
                    self.key_queue.append(key)
                    return False
                case "move":
                    self.mouse = rl.Vector2(float(args[0]), float(args[1]))
                case "click":
                    self.mouse = rl.Vector2(float(args[0]), float(args[1]))
                    self.mouse_pressed.add(int(rl.MouseButton.MOUSE_BUTTON_LEFT))
                    return False
                case "hook":
                    # Run fn(GameState) against the live game, e.g. to grant XP for a level-up.
                    args[0](self.game_state)
                case "rclick":
                    self.mouse_pressed.add(int(rl.MouseButton.MOUSE_BUTTON_RIGHT))
                    return False
                case "fire":
                    # Hold the left button for N frames while later moves still apply.
                    self.mouse_held = int(args[0])
                    self.mouse_pressed.add(int(rl.MouseButton.MOUSE_BUTTON_LEFT))
                case "text":
                    text = str(args[0])
                    self.chars.append(ord(text[0]))
                    if len(text) > 1:
                        self.steps.insert(0, ("text", text[1:]))
                    return False
                case "shot":
                    self.pending_shot = str(args[0])
                    return False
                case _:
                    raise ValueError(op)
        return self.pending_shot is None

    def install(self) -> None:
        real_flags = rl.set_config_flags
        # Native-size captures: hidden window, no HiDPI backbuffer.
        rl.set_config_flags = lambda flags: real_flags(
            (int(flags) & ~int(rl.ConfigFlags.FLAG_WINDOW_HIGHDPI)) | int(rl.ConfigFlags.FLAG_WINDOW_HIDDEN),
        )
        rl.set_target_fps = lambda _fps: None
        rl.window_should_close = self.advance
        rl.get_frame_time = lambda: DT
        # The hidden window never has focus; the game would suspend like native does when inactive.
        rl.is_window_focused = lambda: True
        rl.get_time = lambda: self.frame * DT
        rl.get_fps = lambda: 60
        rl.is_key_pressed = lambda key: int(key) in self.pressed
        rl.is_key_pressed_repeat = lambda _key: False
        rl.is_key_down = lambda key: int(key) in self.down
        rl.is_key_released = lambda _key: False
        rl.is_key_up = lambda key: int(key) not in self.down
        rl.get_key_pressed = lambda: self.key_queue.pop(0) if self.key_queue else 0
        rl.get_char_pressed = lambda: self.chars.pop(0) if self.chars else 0
        rl.get_mouse_position = lambda: rl.Vector2(self.mouse.x, self.mouse.y)
        rl.get_mouse_delta = lambda: rl.Vector2(self.mouse.x - self.prev_mouse.x, self.mouse.y - self.prev_mouse.y)
        rl.get_mouse_wheel_move = lambda: 0.0
        rl.is_mouse_button_pressed = lambda button: int(button) in self.mouse_pressed
        rl.is_mouse_button_down = lambda button: int(button) in self.mouse_pressed or (
            self.mouse_held > 0 and int(button) == int(rl.MouseButton.MOUSE_BUTTON_LEFT)
        )
        rl.is_mouse_button_released = lambda _button: False
        rl.set_mouse_position = lambda x, y: setattr(self, "mouse", rl.Vector2(float(x), float(y)))
        rl.is_gamepad_available = lambda _pad: False
        rl.is_gamepad_button_down = lambda _pad, _button: False
        rl.is_gamepad_button_pressed = lambda _pad, _button: False
        rl.get_gamepad_axis_movement = lambda _pad, _axis: 0.0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--seed", type=int, default=0x1234)
    parser.add_argument("--size", default="1024x768")
    parser.add_argument("--assets", type=Path, default=Path("artifacts/assets"))
    args = parser.parse_args()

    sys.path.insert(0, str(args.scenario.resolve().parent))
    spec = importlib.util.spec_from_file_location("scenario", args.scenario)
    scenario = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scenario)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    base_dir = Path(tempfile.mkdtemp(prefix="ui-capture-"))
    try:
        from crimson.game.runtime import run_game
        from crimson.game.types import GameConfig
        from crimson.persistence.save_status import ensure_game_status
        from grim.config import ensure_crimson_cfg

        cfg = ensure_crimson_cfg(base_dir)
        cfg.display.width, cfg.display.height = (int(v) for v in args.size.split("x"))
        cfg.display.windowed = True
        cfg.audio.sfx_volume = 0.0
        cfg.audio.music_volume = 0.0
        cfg.save()
        if hasattr(scenario, "STATUS"):
            status = ensure_game_status(base_dir)
            scenario.STATUS(status)
            status.save_if_dirty()

        from crimson.game import loop_view

        driver = Driver(scenario.STEPS, args.out_dir.resolve())
        driver.install()
        real_init = loop_view.GameLoopView.__init__

        def init(view, state):
            real_init(view, state)
            driver.game_state = state

        loop_view.GameLoopView.__init__ = init
        run_game(GameConfig(base_dir=base_dir, assets_dir=args.assets, seed=args.seed, no_intro=True))
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
