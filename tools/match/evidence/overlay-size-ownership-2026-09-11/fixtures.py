"""Prior overlay boundary cases plus varied flash sizes and explicit branch controls."""

import itertools
import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent


def cases():
    rows = json.loads((HERE / "prior-frames.json").read_text())
    assert len(rows) == 239
    for flags, health, shield in itertools.product((0, 4, 8), (0.0, 100.0), (0.0, 0.7)):
        rows.append({
            "label": f"branches-{flags}-{health}-{shield}",
            "frame": {
                "weapon_flags": flags, "radioactive": True,
                "players": [{"index": 0, "position": [100.23, 150.27], "health": health, "shield": shield, "flash": 0.7}],
            },
        })
    rng = random.Random(2026091112)
    for index in range(600):
        rows.append({
            "label": f"varied-{index}",
            "frame": {
                "alpha": rng.uniform(0.01, 1.5),
                "camera": [rng.uniform(-300, 300), rng.uniform(-300, 300)],
                "time": rng.uniform(-100, 100),
                "weapon_flags": 4 if index % 2 else 0,
                "line_perk": False,
                "players": [{
                    "index": 0,
                    "position": [rng.uniform(-100, 1000), rng.uniform(-100, 1000)],
                    "size": rng.uniform(20, 120),
                    "aim_heading": rng.uniform(-7, 7),
                    "heading": rng.uniform(-7, 7),
                    "flash": rng.uniform(0, 3),
                    "shield": rng.uniform(0, 2) if index % 3 == 0 else 0.0,
                }],
            },
        })
    assert len(rows) == 851
    return rows
