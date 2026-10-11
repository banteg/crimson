from __future__ import annotations

from importlib.resources import files

from ..level import QuestLevel


def stock_source(level: str) -> str:
    """Load an independent DSL translation of a stock builder (not its generated table)."""
    parsed = QuestLevel.parse(level)
    return files("crimson.quests.dsl").joinpath("stock", f"{parsed.text}.quest").read_text(encoding="utf-8")
