from __future__ import annotations

from pathlib import Path
import random
from typing import Any, Protocol


class PauseBackground(Protocol):
    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None: ...


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
    menu_ground_camera: Any
    pause_background: PauseBackground | None
    pending_lan_session: Any
    lan_in_lobby: bool
    lan_waiting_for_players: bool
    lan_expected_players: int
    lan_connected_players: int
    lan_desync_count: int
    lan_resync_failure_count: int
    lan_last_error: str

    demo_enabled: bool
    skip_intro: bool
    menu_sign_locked: bool

    stats_menu_easter_egg_roll: int

    quit_requested: bool
    screen_fade_alpha: float
    screen_fade_ramp: bool
