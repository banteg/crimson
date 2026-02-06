from __future__ import annotations

from pathlib import Path
import random
from typing import Any, Protocol


class PauseBackground(Protocol):
    def draw_pause_background(self) -> None: ...


class GameState(Protocol):
    # Keep this protocol lightweight: frontend code should not depend on the full
    # gameplay/sim stack (enforced via import-linter).
    base_dir: Path
    assets_dir: Path
    rng: random.Random
    config: Any
    status: Any
    preserve_bugs: bool

    texture_cache: Any
    audio: Any
    resource_paq: Path
    logos: Any
    console: Any

    menu_ground: Any
    pause_background: PauseBackground | None

    demo_enabled: bool
    skip_intro: bool
    menu_sign_locked: bool

    quit_requested: bool
    screen_fade_alpha: float
    screen_fade_ramp: bool
