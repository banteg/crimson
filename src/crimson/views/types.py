from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ViewContext:
    assets_dir: Path = Path("artifacts") / "assets"


class View(Protocol):
    def update(self, dt: float) -> None: ...

    def draw(self) -> None: ...
