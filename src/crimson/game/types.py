from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

import msgspec

from grim.rand import Crand

from ..game_modes import GameMode
from ..net.room_code import RoomCode
from ..paths import default_runtime_dir
from ..pause_background import PauseBackground
from ..quests.level import QuestLevel
from ..render.rtx.mode import RtxRenderMode


def _default_rtx_render_mode() -> RtxRenderMode:
    return RtxRenderMode.CLASSIC

if TYPE_CHECKING:
    from grim.assets import RuntimeResources
    from grim.audio import AudioState
    from grim.config import CrimsonConfig
    from grim.console import ConsoleState
    from grim.geom import Vec2
    from grim.terrain_render import GroundRenderer

    from ..modes.quest_mode import QuestRunOutcome
    from ..net.lockstep_runtime import LockstepRuntime
    from ..net.rollback_runtime import RollbackRuntime
    from ..persistence.save_status import GameStatus, GameStatusData


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
    pending_network_session: PendingNetworkSession | None = None


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
    room_code: RoomCode | None = None


type NetworkEndpoint = LockstepEndpoint | RollbackEndpoint


class NetworkSessionConfig(msgspec.Struct, frozen=True):
    mode: NetworkSessionMode
    endpoint: NetworkEndpoint
    netcode_mode: NetcodeMode = "rollback"
    player_count: int = 1
    quest_level: QuestLevel | None = None
    rollback_max_ticks: int = 8
    reconnect_timeout_ms: int = 15_000
    input_delay_ticks: int = 1
    preserve_bugs: bool = False

    def __post_init__(self) -> None:
        endpoint = self.endpoint
        if self.netcode_mode == "lockstep":
            if not isinstance(endpoint, LockstepEndpoint):
                raise TypeError("lockstep sessions require LockstepEndpoint")
            return
        if not isinstance(endpoint, RollbackEndpoint):
            raise TypeError("rollback sessions require RollbackEndpoint")


class PendingNetworkSession(msgspec.Struct):
    role: NetworkSessionRole
    config: NetworkSessionConfig
    auto_start: bool = False
    started: bool = False
    error: str = ""


class HighScoresRequest(msgspec.Struct):
    game_mode_id: GameMode
    quest_level: QuestLevel | None = None
    highlight_rank: int | None = None


@runtime_checkable
class Screen(Protocol):
    def open(self) -> None: ...

    def close(self) -> None: ...

    def update(self, dt: float) -> None: ...

    def draw(self) -> None: ...

    def take_action(self) -> str | None: ...


@runtime_checkable
class GameplayScreen(Screen, PauseBackground, Protocol):
    close_requested: bool
    default_game_mode_id: GameMode

    def bind_status(self, status: GameStatus | None) -> None: ...

    def bind_screen_fade(self, fade: GameState | None) -> None: ...

    def bind_audio(self, audio: AudioState | None, audio_rng: Crand) -> None: ...

    def set_lan_runtime(
        self,
        *,
        enabled: bool,
        role: str,
        expected_players: int,
        connected_players: int,
        waiting_for_players: bool,
    ) -> None: ...

    def bind_lan_runtime(self, runtime: RollbackRuntime | LockstepRuntime | None) -> None: ...

    def set_lan_match_start(
        self,
        *,
        seed: int,
        start_tick: int = 0,
        status: GameStatusData | None = None,
    ) -> None: ...

    def steal_ground_for_menu(self) -> GroundRenderer | None: ...

    def menu_ground_camera(self) -> Vec2: ...

    def console_elapsed_ms(self) -> float: ...

    def prepare_demo_trial_overlay_frame(self) -> None: ...

    def regenerate_terrain_for_console(self) -> None: ...

    def set_rtx_mode(self, mode: RtxRenderMode) -> None: ...

    def set_runtime_updates_per_frame(self, value: int) -> None: ...

    def frame_telemetry(self) -> tuple[int, int, int, float, float, float]: ...


class GameState(msgspec.Struct):
    base_dir: Path
    assets_dir: Path
    rng: Crand
    config: CrimsonConfig
    status: GameStatus
    console: ConsoleState
    demo_enabled: bool
    preserve_bugs: bool
    resources: RuntimeResources | None
    audio: AudioState | None
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
    network_runtime: RollbackRuntime | LockstepRuntime | None = None
    network_in_lobby: bool = False
    network_waiting_for_players: bool = False
    network_expected_players: int = 1
    network_connected_players: int = 1
    network_desync_count: int = 0
    network_resync_failure_count: int = 0
    network_last_error: str = ""
    pending_quest_level: QuestLevel | None = None
    pending_high_scores: HighScoresRequest | None = None
    quest_outcome: QuestRunOutcome | None = None
    quest_fail_retry_count: int = 0
    terrain_regenerate_requested: bool = False
    survival_elapsed_ms: float = 0.0
    demo_trial_elapsed_ms: int = 0
    quit_requested: bool = False
    screen_fade_alpha: float = 0.0
    screen_fade_ramp: bool = False
    runtime_updates_per_frame: int = 0
    input_stall_count: int = 0
    ticks_advanced_per_frame: int = 0
    sim_ms: float = 0.0
    presentation_plan_ms: float = 0.0
    presentation_apply_ms: float = 0.0

__all__ = [
    "GameConfig",
    "GameState",
    "GameplayScreen",
    "HighScoresRequest",
    "LockstepEndpoint",
    "NetcodeMode",
    "NetworkEndpoint",
    "NetworkSessionConfig",
    "NetworkSessionMode",
    "PauseBackground",
    "PendingNetworkSession",
    "RollbackEndpoint",
    "Screen",
]
