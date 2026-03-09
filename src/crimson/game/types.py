from __future__ import annotations

from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, TypeAlias, runtime_checkable

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
    from ..net.lockstep_protocol import StatusSnapshot
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
    room_code: RoomCode | None = None


NetworkEndpoint: TypeAlias = LockstepEndpoint | RollbackEndpoint


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


class FrontRouteId(Enum):
    OPEN_PLAY_GAME = auto()
    OPEN_LAN_SESSION = auto()
    OPEN_LAN_LOBBY = auto()
    OPEN_QUESTS = auto()
    OPEN_PAUSE_MENU = auto()
    START_QUEST = auto()
    QUEST_RESULTS = auto()
    QUEST_FAILED = auto()
    END_NOTE = auto()
    OPEN_HIGH_SCORES = auto()
    START_SURVIVAL = auto()
    START_RUSH = auto()
    START_TYPO = auto()
    START_TUTORIAL = auto()
    OPEN_OPTIONS = auto()
    OPEN_CONTROLS = auto()
    OPEN_STATISTICS = auto()
    OPEN_WEAPON_DATABASE = auto()
    OPEN_PERK_DATABASE = auto()
    OPEN_CREDITS = auto()
    OPEN_ALIEN_ZOOKEEPER = auto()
    OPEN_MODS = auto()
    OPEN_OTHER_GAMES = auto()


_LAN_GAMEPLAY_FRONT_ROUTES = frozenset(
    {
        FrontRouteId.START_QUEST,
        FrontRouteId.START_SURVIVAL,
        FrontRouteId.START_RUSH,
    },
)


def front_route_for_network_mode(mode: NetworkSessionMode) -> FrontRouteId:
    if mode == "quests":
        return FrontRouteId.START_QUEST
    if mode == "rush":
        return FrontRouteId.START_RUSH
    if mode == "survival":
        return FrontRouteId.START_SURVIVAL
    raise ValueError(f"unsupported network session mode: {mode!r}")


def game_mode_for_front_route(route: FrontRouteId) -> GameMode | None:
    match route:
        case FrontRouteId.START_QUEST:
            return GameMode.QUESTS
        case FrontRouteId.START_SURVIVAL:
            return GameMode.SURVIVAL
        case FrontRouteId.START_RUSH:
            return GameMode.RUSH
        case FrontRouteId.START_TYPO:
            return GameMode.TYPO
        case FrontRouteId.START_TUTORIAL:
            return GameMode.TUTORIAL
        case _:
            return None


class BackToMenu(msgspec.Struct, frozen=True, tag="back_to_menu"):
    pass


class BackToPrevious(msgspec.Struct, frozen=True, tag="back_to_previous"):
    pass


class QuitApp(msgspec.Struct, frozen=True, tag="quit_app"):
    pass


class QuitAfterDemo(msgspec.Struct, frozen=True, tag="quit_after_demo"):
    pass


class StartDemo(msgspec.Struct, frozen=True, tag="start_demo"):
    pass


class OpenFrontRoute(msgspec.Struct, frozen=True, tag="open_front_route"):
    route: FrontRouteId

    def __post_init__(self) -> None:
        if not isinstance(self.route, FrontRouteId):
            raise TypeError("OpenFrontRoute.route must be a FrontRouteId")


class OpenFrontRouteWithParent(msgspec.Struct, frozen=True, tag="open_front_route_with_parent"):
    route: FrontRouteId
    parent: FrontRouteId
    clear_stack: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.route, FrontRouteId):
            raise TypeError("OpenFrontRouteWithParent.route must be a FrontRouteId")
        if not isinstance(self.parent, FrontRouteId):
            raise TypeError("OpenFrontRouteWithParent.parent must be a FrontRouteId")
        if type(self.clear_stack) is not bool:
            raise TypeError("OpenFrontRouteWithParent.clear_stack must be a bool")


class OpenLanLobby(msgspec.Struct, frozen=True, tag="open_lan_lobby"):
    route: FrontRouteId

    def __post_init__(self) -> None:
        if not isinstance(self.route, FrontRouteId):
            raise TypeError("OpenLanLobby.route must be a FrontRouteId")
        if self.route not in _LAN_GAMEPLAY_FRONT_ROUTES:
            raise ValueError("OpenLanLobby.route must be a LAN gameplay FrontRouteId")


class StartLanMatch(msgspec.Struct, frozen=True, tag="start_lan_match"):
    route: FrontRouteId
    player_count: int
    quest_level: QuestLevel | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.route, FrontRouteId):
            raise TypeError("StartLanMatch.route must be a FrontRouteId")
        if self.route not in _LAN_GAMEPLAY_FRONT_ROUTES:
            raise ValueError("StartLanMatch.route must be a LAN gameplay FrontRouteId")
        if type(self.player_count) is not int:
            raise TypeError("StartLanMatch.player_count must be an int")
        if self.player_count <= 0:
            raise ValueError("StartLanMatch.player_count must be positive")
        if self.quest_level is not None and not isinstance(self.quest_level, QuestLevel):
            raise TypeError("StartLanMatch.quest_level must be a QuestLevel | None")


ScreenAction: TypeAlias = (
    BackToMenu
    | BackToPrevious
    | QuitApp
    | QuitAfterDemo
    | StartDemo
    | OpenFrontRoute
    | OpenFrontRouteWithParent
    | OpenLanLobby
    | StartLanMatch
)


def is_screen_action(value: object) -> bool:
    return isinstance(
        value,
        (
            BackToMenu,
            BackToPrevious,
            QuitApp,
            QuitAfterDemo,
            StartDemo,
            OpenFrontRoute,
            OpenFrontRouteWithParent,
            OpenLanLobby,
            StartLanMatch,
        ),
    )


@runtime_checkable
class Screen(Protocol):
    def open(self) -> None: ...

    def close(self) -> None: ...

    def update(self, dt: float) -> None: ...

    def draw(self) -> None: ...

    def take_action(self) -> ScreenAction | None: ...


@runtime_checkable
class GameplayScreen(Screen, PauseBackground, Protocol):
    close_requested: bool
    default_game_mode_id: GameMode

    def bind_status(self, status: "GameStatus | None") -> None: ...

    def bind_screen_fade(self, fade: "GameState | None") -> None: ...

    def bind_audio(self, audio: "AudioState | None", audio_rng: Crand) -> None: ...

    def set_lan_runtime(
        self,
        *,
        enabled: bool,
        role: str,
        expected_players: int,
        connected_players: int,
        waiting_for_players: bool,
    ) -> None: ...

    def bind_lan_runtime(self, runtime: "RollbackRuntime | LockstepRuntime | None") -> None: ...

    def set_lan_match_start(
        self,
        *,
        seed: int,
        start_tick: int = 0,
        status_snapshot: "StatusSnapshot | None" = None,
    ) -> None: ...

    def steal_ground_for_menu(self) -> "GroundRenderer | None": ...

    def menu_ground_camera(self) -> "Vec2": ...

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
    network_runtime: "RollbackRuntime | LockstepRuntime | None" = None
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
    "BackToMenu",
    "BackToPrevious",
    "FrontRouteId",
    "GameplayScreen",
    "GameConfig",
    "GameState",
    "HighScoresRequest",
    "LockstepEndpoint",
    "NetcodeMode",
    "NetworkEndpoint",
    "NetworkSessionConfig",
    "NetworkSessionMode",
    "OpenFrontRoute",
    "OpenFrontRouteWithParent",
    "OpenLanLobby",
    "PendingNetworkSession",
    "PauseBackground",
    "QuitAfterDemo",
    "QuitApp",
    "RollbackEndpoint",
    "Screen",
    "ScreenAction",
    "StartDemo",
    "StartLanMatch",
    "front_route_for_network_mode",
    "game_mode_for_front_route",
    "is_screen_action",
]
