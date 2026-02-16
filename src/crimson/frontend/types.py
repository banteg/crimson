from __future__ import annotations

from pathlib import Path
import random
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from grim.audio import AudioState
    from grim.assets import LogoAssets, PaqTextureCache
    from grim.config import CrimsonConfig
    from grim.console import ConsoleState
    from grim.geom import Vec2
    from grim.terrain_render import GroundRenderer

    from ..game.types import PendingLanSession
    from ..net.runtime import LanRuntime
    from ..persistence.save_status import GameStatus


class PauseBackground(Protocol):
    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None: ...


class GameState(Protocol):
    # Keep this protocol lightweight: frontend code should not depend on the full
    # gameplay/sim stack (enforced via import-linter).
    base_dir: Path
    assets_dir: Path
    rng: random.Random
    config: CrimsonConfig
    status: GameStatus
    preserve_bugs: bool

    texture_cache: PaqTextureCache | None
    audio: AudioState | None
    resource_paq: Path
    logos: LogoAssets | None
    console: ConsoleState

    menu_ground: GroundRenderer | None
    menu_ground_camera: Vec2 | None
    pause_background: PauseBackground | None
    pending_lan_session: PendingLanSession | None
    lan_runtime: LanRuntime | None
    lan_in_lobby: bool
    lan_waiting_for_players: bool
    lan_expected_players: int
    lan_connected_players: int
    lan_desync_count: int
    lan_resync_failure_count: int
    lan_last_error: str
    pending_quest_level: str | None

    demo_enabled: bool
    skip_intro: bool
    menu_sign_locked: bool

    stats_menu_easter_egg_roll: int

    quit_requested: bool
    screen_fade_alpha: float
    screen_fade_ramp: bool
