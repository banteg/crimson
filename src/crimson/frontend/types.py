from __future__ import annotations

import random
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from ..pause_background import PauseBackground

if TYPE_CHECKING:
    from grim.assets import LogoAssets, PaqTextureCache
    from grim.audio import AudioState
    from grim.config import CrimsonConfig
    from grim.console import ConsoleState
    from grim.geom import Vec2
    from grim.terrain_render import GroundRenderer

    from ..game.types import PendingNetworkSession
    from ..net.lockstep_runtime import LockstepRuntime
    from ..net.rollback_runtime import RollbackRuntime
    from ..persistence.save_status import GameStatus


class FrontendContext(Protocol):
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
    pending_network_session: PendingNetworkSession | None
    network_runtime: RollbackRuntime | LockstepRuntime | None
    network_in_lobby: bool
    network_waiting_for_players: bool
    network_expected_players: int
    network_connected_players: int
    network_desync_count: int
    network_resync_failure_count: int
    network_last_error: str
    pending_quest_level: str | None

    demo_enabled: bool
    skip_intro: bool
    menu_sign_locked: bool

    stats_menu_easter_egg_roll: int

    quit_requested: bool
    screen_fade_alpha: float
    screen_fade_ramp: bool
