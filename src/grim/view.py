from __future__ import annotations

from pathlib import Path
from typing import Protocol

import msgspec


class ViewContext(msgspec.Struct, frozen=True):
    assets_dir: Path = Path("artifacts") / "assets"
    preserve_bugs: bool = False
    # Write per-tick replay checkpoint sidecars for parity debugging.
    replay_checkpoints: bool = False


class View(Protocol):
    def open(self) -> None: ...

    def update(self, dt: float) -> None: ...

    def draw(self) -> None: ...

    def close(self) -> None: ...
