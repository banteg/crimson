"""Presentation-only ground diagnostics; never serialized into a run or replay."""
from __future__ import annotations

from enum import IntEnum

from grim import canvas
from grim.raylib_api import rl, rl_color


class RtxDebugView(IntEnum):
    SHADED = 0
    SUBSTRATE_NORMAL = 1
    FLUID_NORMAL = 2
    FRESHNESS = 3
    BLOOD_DEPTH = 4
    REFLECTIONS = 5
    DIRECT = 6
    DIRECT_UNSHADOWED = 7
    VISIBILITY = 8
    ALBEDO = 9
    ROUGHNESS = 10
    HEIGHT = 11
    MATERIALS = 12
    AMBIENT = 13
    NO_DIRECT = 14

    @property
    def is_map(self) -> bool:
        return self not in (RtxDebugView.SHADED, RtxDebugView.NO_DIRECT)

    @property
    def token(self) -> str:
        return self.name.lower().replace("_", "-")

    @classmethod
    def parse(cls, value: str) -> RtxDebugView:
        return cls[value.strip().upper().replace("-", "_")]

    def cycle(self, direction: int = 1) -> RtxDebugView:
        return RtxDebugView((int(self) + direction) % len(RtxDebugView))


_DEBUG_HELP = {
    RtxDebugView.SUBSTRATE_NORMAL: "Diffuse normal: RGB = XYZ * 0.5 + 0.5",
    RtxDebugView.FLUID_NORMAL: "Liquid normal: RGB = XYZ * 0.5 + 0.5",
    RtxDebugView.FRESHNESS: "Black = dry; white = fresh (45 s exponential decay)",
    RtxDebugView.BLOOD_DEPTH: "Exposed blood amount: black = none; white = deep",
    RtxDebugView.VISIBILITY: "Direct-radiance weighted: white = visible; black = blocked; blue = no light",
    RtxDebugView.ALBEDO: "Substrate color before blood absorption and lighting",
    RtxDebugView.ROUGHNESS: "Black = smooth; white = rough",
    RtxDebugView.HEIGHT: "Substrate height; blood never adds diffuse relief",
    RtxDebugView.MATERIALS: "R = blood, G = corpse, B = brass; ice = cyan",
    RtxDebugView.NO_DIRECT: "Ground direct lighting removed; ordinary scene, reflections and display mapping",
}


def debug_hotkey(view: RtxDebugView) -> RtxDebugView:
    if not rl.is_key_pressed(rl.KeyboardKey.KEY_F6):
        return view
    reverse = rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT)
    return view.cycle(-1 if reverse else 1)


def draw_debug_label(view: RtxDebugView) -> None:
    if view is RtxDebugView.SHADED:
        return
    title = f"RTX / {view.token}    F6 next / Shift+F6 previous"
    help_text = _DEBUG_HELP.get(view, "Linear contribution mapped as c/(1+c), then gamma encoded")
    y = max(8, canvas.height() - 104)
    width = min(canvas.width() - 16, max(rl.measure_text(title, 18), rl.measure_text(help_text, 14)) + 20)
    rl.draw_rectangle(8, y, width, 56, rl_color(0, 0, 0, 220))
    rl.draw_text(title, 18, y + 8, 18, rl.WHITE)
    rl.draw_text(help_text, 18, y + 32, 14, rl.LIGHTGRAY)
