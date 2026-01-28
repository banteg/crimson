from __future__ import annotations

from dataclasses import dataclass
import random

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.view import ViewContext

from ..game_modes import GameMode
from ..gameplay import weapon_assign_player
from ..persistence.save_status import GameStatus
from ..quests import quest_by_level
from ..quests.runtime import build_quest_spawn_table
from ..quests.types import QuestContext, QuestDefinition, SpawnEntry
from ..terrain_assets import terrain_texture_by_id
from .base_gameplay_mode import BaseGameplayMode

WORLD_SIZE = 1024.0


@dataclass(slots=True)
class _QuestRunState:
    quest: QuestDefinition | None = None
    level: str = ""
    spawn_entries: tuple[SpawnEntry, ...] = ()
    total_spawn_count: int = 0
    max_trigger_time_ms: int = 0
    spawn_timeline_ms: float = 0.0
    quest_name_timer_ms: float = 0.0
    no_creatures_timer_ms: float = 0.0
    completion_transition_ms: float = -1.0


def _quest_seed(level: str) -> int:
    tier_text, quest_text = level.split(".", 1)
    try:
        return int(tier_text) * 100 + int(quest_text)
    except ValueError:
        return sum(ord(ch) for ch in level)


def _quest_attempt_counter_index(level: str) -> int | None:
    try:
        tier_text, quest_text = level.split(".", 1)
        tier = int(tier_text)
        quest = int(quest_text)
    except ValueError:
        return None
    global_index = (tier - 1) * 10 + (quest - 1)
    if not (0 <= global_index < 40):
        return None
    return global_index + 11


class QuestMode(BaseGameplayMode):
    def __init__(
        self,
        ctx: ViewContext,
        *,
        demo_mode_active: bool = False,
        texture_cache: PaqTextureCache | None = None,
        config: CrimsonConfig | None = None,
        audio: AudioState | None = None,
        audio_rng: random.Random | None = None,
    ) -> None:
        super().__init__(
            ctx,
            world_size=WORLD_SIZE,
            default_game_mode_id=int(GameMode.QUESTS),
            demo_mode_active=bool(demo_mode_active),
            difficulty_level=0,
            hardcore=False,
            texture_cache=texture_cache,
            config=config,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._quest = _QuestRunState()
        self._selected_level: str | None = None

    def select_level(self, level: str | None) -> None:
        self._selected_level = level

    def open(self) -> None:
        super().open()
        if self._selected_level is not None:
            self.prepare_new_run(self._selected_level, status=None)

    def prepare_new_run(self, level: str, *, status: GameStatus | None) -> None:
        quest = quest_by_level(level)
        if quest is None:
            self._quest = _QuestRunState(level=level)
            return

        hardcore_flag = False
        if self._config is not None:
            hardcore_flag = bool(int(self._config.data.get("hardcore_flag", 0) or 0))

        self._world.hardcore = hardcore_flag
        seed = _quest_seed(level)

        self._world.reset(seed=seed, player_count=1)
        self._bind_world()

        base_id, overlay_id, detail_id = quest.terrain_ids or (0, 1, 0)
        base = terrain_texture_by_id(int(base_id))
        overlay = terrain_texture_by_id(int(overlay_id))
        detail = terrain_texture_by_id(int(detail_id))
        if base is not None and overlay is not None:
            base_key, base_path = base
            overlay_key, overlay_path = overlay
            detail_key = detail[0] if detail is not None else None
            detail_path = detail[1] if detail is not None else None
            self._world.set_terrain(
                base_key=base_key,
                overlay_key=overlay_key,
                base_path=base_path,
                overlay_path=overlay_path,
                detail_key=detail_key,
                detail_path=detail_path,
            )

        weapon_assign_player(self._player, int(quest.start_weapon_id))

        ctx = QuestContext(width=int(self._world.world_size), height=int(self._world.world_size), player_count=1)
        entries = build_quest_spawn_table(
            quest,
            ctx,
            seed=seed,
            hardcore=hardcore_flag,
            full_version=not self._world.demo_mode_active,
        )
        total_spawn_count = sum(int(entry.count) for entry in entries)
        max_trigger_ms = max((int(entry.trigger_ms) for entry in entries), default=0)

        self._quest = _QuestRunState(
            quest=quest,
            level=str(level),
            spawn_entries=entries,
            total_spawn_count=int(total_spawn_count),
            max_trigger_time_ms=int(max_trigger_ms),
            spawn_timeline_ms=0.0,
            quest_name_timer_ms=0.0,
            no_creatures_timer_ms=0.0,
            completion_transition_ms=-1.0,
        )

        if status is not None:
            idx = _quest_attempt_counter_index(level)
            if idx is not None:
                status.increment_quest_play_count(idx)

    def update(self, dt: float) -> None:
        self._update_audio(dt)
        self._update_ui_mouse()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True

    def draw(self) -> None:
        self._world.draw(draw_aim_indicators=True)
        self._draw_screen_fade()

