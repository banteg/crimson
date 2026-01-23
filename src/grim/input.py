from __future__ import annotations

from dataclasses import dataclass, field

import pyray as rl


@dataclass(slots=True)
class ActionMap:
    bindings: dict[str, tuple[int, ...]] = field(default_factory=dict)

    def bind(self, action: str, *keys: int) -> None:
        if not keys:
            raise ValueError("bind requires at least one key")
        self.bindings[action] = tuple(int(key) for key in keys)

    def is_down(self, action: str) -> bool:
        keys = self.bindings.get(action, ())
        return any(rl.is_key_down(key) for key in keys)

    def was_pressed(self, action: str) -> bool:
        keys = self.bindings.get(action, ())
        return any(rl.is_key_pressed(key) for key in keys)


def is_key_down(key: int) -> bool:
    return rl.is_key_down(key)


def was_key_pressed(key: int) -> bool:
    return rl.is_key_pressed(key)


def is_mouse_button_down(button: int) -> bool:
    return rl.is_mouse_button_down(button)


def was_mouse_button_pressed(button: int) -> bool:
    return rl.is_mouse_button_pressed(button)


def mouse_position() -> tuple[int, int]:
    pos = rl.get_mouse_position()
    return int(pos.x), int(pos.y)
