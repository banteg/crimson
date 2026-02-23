from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol

from ..paths import default_runtime_dir
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
    from ..net.net_runtime import NetRuntime
    from ..net.runtime import LanRuntime
    from ..persistence.save_status import GameStatus


@dataclass(frozen=True, slots=True)
class GameConfig:
    base_dir: Path = field(default_factory=default_runtime_dir)
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
    pending_net_session: "PendingNetSession | None" = None
    pending_lan_session: "PendingLanSession | None" = None


LanSessionMode = Literal["survival", "rush", "quests"]
LanSessionRole = Literal["host", "join"]
NetSessionMode = LanSessionMode
NetSessionRole = LanSessionRole
NetcodeMode = Literal["rollback", "lockstep_legacy"]


@dataclass(frozen=True, slots=True)
class LanSessionConfig:
    mode: LanSessionMode
    player_count: int = 1
    quest_level: str = ""
    bind_host: str = "0.0.0.0"
    relay_host: str = ""
    relay_port: int = 31993
    room_code: str = ""
    host_ip: str = ""
    port: int = 31993
    netcode_mode: NetcodeMode = "rollback"
    rollback_max_ticks: int = 8
    reconnect_timeout_ms: int = 15_000
    input_delay_ticks: int = 1
    preserve_bugs: bool = False

    def resolved_relay_host(self) -> str:
        host = str(self.relay_host).strip()
        if host:
            return host
        fallback = str(self.host_ip).strip()
        if fallback:
            return fallback
        return "127.0.0.1"

    def resolved_relay_port(self) -> int:
        relay_port = int(self.relay_port)
        if relay_port > 0:
            return relay_port
        return int(self.port)


@dataclass(slots=True)
class PendingLanSession:
    role: LanSessionRole
    config: LanSessionConfig
    auto_start: bool = False
    started: bool = False
    error: str = ""


NetSessionConfig = LanSessionConfig
PendingNetSession = PendingLanSession


@dataclass(slots=True)
class HighScoresRequest:
    game_mode_id: int
    quest_stage_major: int = 0
    quest_stage_minor: int = 0
    highlight_rank: int | None = None


class FrontView(Protocol):
    def open(self) -> None: ...

    def close(self) -> None: ...

    def update(self, dt: float) -> None: ...

    def draw(self) -> None: ...

    def take_action(self) -> str | None: ...


class PauseBackground(Protocol):
    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None: ...


@dataclass(slots=True)
class GameState:
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
    rtx_mode: RtxRenderMode = field(default_factory=_default_rtx_render_mode)
    skip_intro: bool = False
    gamma_ramp: float = 1.0
    snd_freq_adjustment_enabled: bool = True
    menu_ground: GroundRenderer | None = None
    menu_ground_camera: Vec2 | None = None
    menu_sign_locked: bool = False
    stats_menu_easter_egg_roll: int = -1
    pause_background: PauseBackground | None = None
    pending_net_session: PendingNetSession | None = None
    net_runtime: "NetRuntime | LanRuntime | None" = None
    net_in_lobby: bool = False
    net_waiting_for_players: bool = False
    net_expected_players: int = 1
    net_connected_players: int = 1
    net_desync_count: int = 0
    net_resync_failure_count: int = 0
    net_last_error: str = ""
    pending_lan_session: PendingLanSession | None = None
    lan_runtime: "NetRuntime | LanRuntime | None" = None
    lan_in_lobby: bool = False
    lan_waiting_for_players: bool = False
    lan_expected_players: int = 1
    lan_connected_players: int = 1
    lan_desync_count: int = 0
    lan_resync_failure_count: int = 0
    lan_last_error: str = ""
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
    "LanSessionConfig",
    "NetSessionConfig",
    "NetcodeMode",
    "PendingNetSession",
    "PendingLanSession",
    "PauseBackground",
]
