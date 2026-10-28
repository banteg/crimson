"""Presentation-only ground diagnostics; never serialized into a run or replay."""
from __future__ import annotations

from enum import IntEnum

from grim import canvas
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
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
    SMOKE_DENSITY = 15
    SMOKE_HEAT = 16
    SMOKE_FLOW = 17
    SMOKE_LIGHT = 18

    @property
    def is_map(self) -> bool:
        return self not in (RtxDebugView.SHADED, RtxDebugView.NO_DIRECT)

    @property
    def is_smoke(self) -> bool:
        return self >= RtxDebugView.SMOKE_DENSITY

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
    RtxDebugView.SMOKE_DENSITY: "Smoke opacity through the column: black = clear; white = opaque",
    RtxDebugView.SMOKE_HEAT: "Smoke temperature: black = cold; red, yellow, white = hotter, taller columns",
    RtxDebugView.SMOKE_FLOW: "Planar air velocity: hue = direction; brightness = speed",
    RtxDebugView.SMOKE_LIGHT: "Weapon and sight light scattered by smoke, no sky fill: c/(1+c), then gamma",
}


def debug_hotkey(view: RtxDebugView) -> RtxDebugView:
    if not rl.is_key_pressed(rl.KeyboardKey.KEY_F6):
        return view
    reverse = rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT)
    return view.cycle(-1 if reverse else 1)


def draw_debug_label(view: RtxDebugView, font: SmallFontData) -> None:
    if view is RtxDebugView.SHADED:
        return
    title = f"RTX / {view.token}    F6 next / Shift+F6 previous"
    help_text = _DEBUG_HELP.get(view, "Linear contribution mapped as c/(1+c), then gamma encoded")
    y = max(8, canvas.height() - 104)
    width = min(canvas.width() - 16, max(measure_small_text_width(font, title), measure_small_text_width(font, help_text)) + 20)
    rl.draw_rectangle(8, y, int(width), 52, rl_color(0, 0, 0, 220))
    draw_small_text(font, title, Vec2(18, y + 8), rl.WHITE)
    draw_small_text(font, help_text, Vec2(18, y + 28), rl.LIGHTGRAY)
