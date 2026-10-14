"""Write service/src/quests.json: each quest's title, from the game's quest table, for the quest boards' menu.

Run from the repository root: uv run python service/scripts/quests.py
"""

from __future__ import annotations

import json
from pathlib import Path

from crimson.quests import quest_by_level
from crimson.quests.dsl.compiler import _ALIASES, _BONUS_ALIASES, _PERK_ALIASES
from crimson.quests.level import QUEST_STAGE_COUNT, QUESTS_PER_STAGE, QuestLevel
from crimson.weapons import WeaponId

SRC = Path(__file__).resolve().parents[1] / "src"
OUT = SRC / "quests.json"
DSL_OUT = SRC / "quest-dsl.json"


def quest_dsl_tables() -> dict[str, dict[str, int]]:
    return {
        "weapons": {
            name.lower(): int(member)
            for name, member in WeaponId.__members__.items()
            if member != WeaponId.NONE and not name.startswith("UNUSED_")
        },
        "bonuses": {name: int(member) for name, member in _BONUS_ALIASES.items()},
        "perks": {name: int(member) for name, member in _PERK_ALIASES.items()},
        "templates": {
            f"{group}.{name}": int(member)
            for group, mapping in _ALIASES.items()
            for name, member in mapping.items()
        },
    }


def main() -> None:
    titles = {
        f"{major}.{minor}": quest_by_level(QuestLevel(major, minor)).title
        for major in range(1, QUEST_STAGE_COUNT + 1)
        for minor in range(1, QUESTS_PER_STAGE + 1)
    }
    OUT.write_text(json.dumps(titles, indent=1) + "\n")
    DSL_OUT.write_text(json.dumps(quest_dsl_tables(), indent=1) + "\n")
    print(f"wrote {len(titles)} quest titles to {OUT.name} and DSL tables to {DSL_OUT.name}")

if __name__ == "__main__":
    main()
