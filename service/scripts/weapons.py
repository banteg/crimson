"""Write service/web/src/weapons.json from the game's weapon names and icon indices.

Run from the repository root: uv run python service/scripts/weapons.py
"""

from __future__ import annotations

import json
from pathlib import Path

from crimson.weapons import WEAPON_TABLE, weapon_display_name

OUT = Path(__file__).resolve().parents[1] / "web" / "src" / "weapons.json"


def main() -> None:
    weapons = {
        str(int(weapon.weapon_id)): {
            "name": weapon_display_name(weapon.weapon_id),
            "icon_index": weapon.icon_index,
        }
        for weapon in WEAPON_TABLE
    }
    OUT.write_text(json.dumps(weapons, indent=1) + "\n")
    print(f"wrote {len(weapons)} weapons to {OUT}")


if __name__ == "__main__":
    main()
