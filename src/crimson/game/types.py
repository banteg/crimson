from __future__ import annotations

import random
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, TypeAlias

import msgspec

from ..game_modes import GameMode
from ..paths import default_runtime_dir
from ..pause_background import PauseBackground
from ..render.rtx.mode import RtxRenderMode


def _default_rtx_render_mode() -> RtxRenderMode:
    return RtxRenderMode.CLASSIC

if TYPE_CHECKING:
    from grim.assets import LogoAssets, PaqTextureCache
    from grim.audio import AudioState
    from grim.config import CrimsonConfig
    from grim.console import ConsoleState
    from grim.geom import Vec2
    from grim.terrain_render import GroundRenderer

    from ..modes.quest_mode import QuestRunOutcome
    from ..net.lockstep_runtime import LockstepRuntime
    from ..net.rollback_runtime import RollbackRuntime
    from ..persistence.save_status import GameStatus


class GameConfig(msgspec.Struct, frozen=True):
    base_dir: Path = msgspec.field(default_factory=default_runtime_dir)
    assets_dir: Path | None = None
    width: int | None = None
    height: int | None = None
    fps: int = 60
    seed: int | None = None
    demo_enabled: bool = False
    no_intro: bool = False
    debug: bool = False
    rtx: bool = False
    preserve_bugs: bool = False
    pending_network_session: "PendingNetworkSession | None" = None


NetworkSessionMode = Literal["survival", "rush", "quests"]
NetworkSessionRole = Literal["host", "join"]
NetcodeMode = Literal["rollback", "lockstep"]


class LockstepEndpoint(msgspec.Struct, frozen=True):
    bind_host: str = "0.0.0.0"
    host: str = "127.0.0.1"
    port: int = 31993


class RollbackEndpoint(msgspec.Struct, frozen=True):
    relay_host: str = "127.0.0.1"
    relay_port: int = 31993
    room_code: str = ""


NetworkEndpoint: TypeAlias = LockstepEndpoint | RollbackEndpoint


class NetworkSessionConfig(msgspec.Struct, frozen=True):
    mode: NetworkSessionMode
    netcode_mode: NetcodeMode
    endpoint: NetworkEndpoint
    player_count: int = 1
    quest_level: str = ""
    rollback_max_ticks: int = 8
    reconnect_timeout_ms: int = 15_000
    input_delay_ticks: int = 1
    preserve_bugs: bool = False

    def lockstep_endpoint(self) -> LockstepEndpoint:
        endpoint = self.endpoint
        if isinstance(endpoint, LockstepEndpoint):
            return endpoint
        raise TypeError("network session requires lockstep endpoint")

    def rollback_endpoint(self) -> RollbackEndpoint:
        endpoint = self.endpoint
        if isinstance(endpoint, RollbackEndpoint):
            return endpoint
        raise TypeError("network session requires rollback endpoint")


class PendingNetworkSession(msgspec.Struct):
    role: NetworkSessionRole
    config: NetworkSessionConfig
    auto_start: bool = False
    started: bool = False
    error: str = ""


class HighScoresRequest(msgspec.Struct):
    game_mode_id: GameMode
    quest_stage_major: int = 0
    quest_stage_minor: int = 0
    highlight_rank: int | None = None


class FrontView(Protocol):
    def open(self) -> None: ...

    def close(self) -> None: ...

    def update(self, dt: float) -> None: ...

    def draw(self) -> None: ...

    def take_action(self) -> str | None: ...


class GameState(msgspec.Struct):
    base_dir: Path
    assets_dir: Path
    rng: random.Random
    config: CrimsonConfig
    status: GameStatus
    console: ConsoleState
    demo_enabled: bool
    preserve_bugs: bool
    logos: LogoAssets | None
    texture_cache: PaqTextureCache | None
    audio: AudioState | None
    resource_paq: Path
    session_start: float
    rtx_mode: RtxRenderMode = msgspec.field(default_factory=_default_rtx_render_mode)
    skip_intro: bool = False
    gamma_ramp: float = 1.0
    snd_freq_adjustment_enabled: bool = True
    menu_ground: GroundRenderer | None = None
    menu_ground_camera: Vec2 | None = None
    menu_sign_locked: bool = False
    stats_menu_easter_egg_roll: int = -1
    pause_background: PauseBackground | None = None
    pending_network_session: PendingNetworkSession | None = None
    network_runtime: "RollbackRuntime | LockstepRuntime | None" = None
    network_in_lobby: bool = False
    network_waiting_for_players: bool = False
    network_expected_players: int = 1
    network_connected_players: int = 1
    network_desync_count: int = 0
    network_resync_failure_count: int = 0
    network_last_error: str = ""
    pending_quest_level: str | None = None
    pending_high_scores: HighScoresRequest | None = None
    quest_outcome: QuestRunOutcome | None = None
    quest_fail_retry_count: int = 0
    terrain_regenerate_requested: bool = False
    survival_elapsed_ms: float = 0.0
    demo_trial_elapsed_ms: int = 0
    quit_requested: bool = False
    screen_fade_alpha: float = 0.0
    screen_fade_ramp: bool = False


__all__ = [
    "FrontView",
    "GameConfig",
    "GameState",
    "HighScoresRequest",
    "LockstepEndpoint",
    "NetcodeMode",
    "NetworkEndpoint",
    "NetworkSessionConfig",
    "NetworkSessionMode",
    "PendingNetworkSession",
    "PauseBackground",
    "RollbackEndpoint",
]
