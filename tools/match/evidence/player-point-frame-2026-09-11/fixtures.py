"""Extend the shared player-update matrix with ordinary finite branch controls."""

import importlib.util
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, directory, file):
    spec = importlib.util.spec_from_file_location(name, HERE.parent / directory / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scenarios():
    base = load("aim_fixtures", "player-aim-direction-2026-09-11", "fixtures.py")
    yield from base.scenarios()
    rows = [
        ("fortress-cap", {"movement": 2, "move_speed": 0, "perks": {"living_fortress": 1}, "living_fortress_timer": 29.99, "dt": .1}),
        ("point-reload-input", {"movement": 4, "keys": [90], "shot_cooldown": 1}),
    ]
    for mode in (3, 4, 5):
        for speed in (0, 1.999, 2.0, 2.79, 2.8, 3.0):
            for weapon in (1, 7):
                rows.append((f"runner-{mode}-{speed}-{weapon}", {
                    "movement": mode, "move_target_x": 650, "move_target_y": 700, "move_speed": speed, "weapon": weapon,
                    "perks": {"long_distance_runner": 1}, "creatures": [{"index": 0, "x": 400, "y": 500}], "shot_cooldown": 1,
                }))
    for timer in (.001, .025, .05):
        rows.append((f"anxious-underflow-{timer}", {
            "movement": 2, "move_speed": 0, "perks": {"anxious_loader": 1},
            "input_primary_just_pressed": True, "reload_timer": timer,
        }))
    for mx, my in ((200, 200), (200, 201), (201, 200)):
        rows.append((f"cursor-zero-axis-{mx}-{my}", {"movement": 2, "move_speed": 0, "aim": 3, "mouse_x": mx, "mouse_y": my}))
    rows.extend([
        ("computer-aim-near", {"movement": 2, "move_speed": 0, "aim": 5, "aim_position": (300, 400),
                                  "creatures": [{"index": 0, "x": 301, "y": 402}], "shot_cooldown": 1}),
        ("fire-bullets-key", {"movement": 2, "move_speed": 0, "keys": [104, 0x22], "shot_cooldown": 0}),
    ])
    assert len(rows) == 46
    bits = struct.unpack("<I", struct.pack("<f", 183.24853515625))[0]
    for delta in (-2, -1, 2, 3):
        y = struct.unpack("<f", struct.pack("<I", bits + delta))[0]
        rows.append((f"demo-sentinel-{delta}", {
            "movement": 5, "move_speed": .7, "pos_x": 512, "pos_y": 512,
            "creatures": [{"index": 0, "x": 0, "y": y}], "shot_cooldown": 1,
        }))
    rows.append(("demo-sentinel-zero-clamp", {
        "movement": 5, "move_speed": .001, "pos_x": 512, "pos_y": 512,
        "creatures": [{"index": 0, "x": 0, "y": 183.24853515625}], "shot_cooldown": 1,
    }))
    for name, frame in rows:
        yield {"name": "coverage-" + name, "frame": frame}
    shortcut = load("shortcut_verify", "player-fire-bullets-shortcut-2026-09-11", "verify.py")
    for row in shortcut.scenarios():
        yield {"name": "shortcut-" + row["name"], "frame": row["frame"]}
