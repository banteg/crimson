from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import msgspec

from grim.rand import Crand

from ..game_modes import GameMode
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
    "PauseBackground",
    "Screen",
]
