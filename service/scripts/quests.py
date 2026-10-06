"""Write service/src/quests.json: each quest's title, from the game's quest table, for the quest boards' menu.

Run from the repository root: uv run python service/scripts/quests.py
"""

from __future__ import annotations

import json
from pathlib import Path

from crimson.quests import quest_by_level
from crimson.quests.level import QUEST_STAGE_COUNT, QUESTS_PER_STAGE, QuestLevel

OUT = Path(__file__).resolve().parents[1] / "src" / "quests.json"


def main() -> None:
    titles = {
        f"{major}.{minor}": quest_by_level(QuestLevel(major, minor)).title
        for major in range(1, QUEST_STAGE_COUNT + 1)
        for minor in range(1, QUESTS_PER_STAGE + 1)
    }
    OUT.write_text(json.dumps(titles, indent=1) + "\n")
    print(f"wrote {len(titles)} quest titles to {OUT.name}")


if __name__ == "__main__":
    main()
