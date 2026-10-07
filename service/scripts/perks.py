"""Write service/web/src/perks.json from the game's perk names, for the perks a run page lists.

Run from the repository root: uv run python service/scripts/perks.py
"""

from __future__ import annotations

import json
from pathlib import Path

from crimson.perks.ids import PERK_BY_ID

OUT = Path(__file__).resolve().parents[1] / "web" / "src" / "perks.json"


def main() -> None:
    perks = {str(int(perk_id)): meta.name for perk_id, meta in sorted(PERK_BY_ID.items())}
    OUT.write_text(json.dumps(perks, indent=1) + "\n")
    print(f"wrote {len(perks)} perks to {OUT}")


if __name__ == "__main__":
    main()
