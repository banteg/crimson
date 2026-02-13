from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import random
from typing import TYPE_CHECKING, Protocol

from ..paths import default_runtime_dir

if TYPE_CHECKING:
    from grim.audio import AudioState
    from grim.assets import LogoAssets, PaqTextureCache
    from grim.config import CrimsonConfig
    from grim.console import ConsoleState
    from grim.geom import Vec2
    from grim.terrain_render import GroundRenderer
    from ..modes.quest_mode import QuestRunOutcome
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
    preserve_bugs: bool = False


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
    skip_intro: bool = False
    gamma_ramp: float = 1.0
    snd_freq_adjustment_enabled: bool = True
    menu_ground: GroundRenderer | None = None
    menu_ground_camera: Vec2 | None = None
    menu_sign_locked: bool = False
    stats_menu_easter_egg_roll: int = -1
    pause_background: PauseBackground | None = None
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
    "PauseBackground",
]
