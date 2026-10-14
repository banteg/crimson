from __future__ import annotations

import msgspec

from grim.assets import TextureId
from grim.audio import AudioState
from grim.config import (
    CrimsonConfig,
)
from grim.console import ConsoleState
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl, rl_color
from grim.sfx_map import SfxId
from grim.view import ViewContext

from ..debug import debug_enabled
from ..game_modes import GameMode
from ..input_codes import PadCode, pad_nav_pressed
from ..perks.selection import perk_selection_prepared_choices
from ..persistence.highscores import UNI_NUM_MASK, HighScoreRecord
from ..quests import quest_by_level
from ..quests.custom import CustomQuest
from ..quests.level import QuestLevel
from ..quests.types import QuestDefinition
from ..replay import ReplayRecorder
from ..screens.actions import ShowQuestOutcome
from ..sim.mode_updates import QuestSpawnState
from ..sim.run_result import RunOutcome
from ..sim.sessions import DeterministicSessionTick
from ..ui.overlays.quest_run import (
    draw_quest_complete_banner_overlay,
    draw_quest_title_timer_overlay,
)
from .base_gameplay_mode import (
    BaseGameplayMode,
)
from .components.highscore_record_builder import build_highscore_record

UI_HINT_COLOR = rl_color(140, 140, 140, 255)
UI_SPONSOR_COLOR = rl_color(255, 255, 255, int(255 * 0.5))


class QuestRunOutcome(msgspec.Struct, frozen=True):
    kind: str  # "completed" | "failed"
    # The stock level, or None for a custom quest.
    level: QuestLevel | None
    base_time_ms: int
    player_health_values: tuple[float, ...]
    pending_perk_count: int
    record: HighScoreRecord
    custom_quest: CustomQuest | None = None


class QuestMode(BaseGameplayMode):
    def __init__(
        self,
        ctx: ViewContext,
        *,
        config: CrimsonConfig,
        console: ConsoleState | None = None,
        audio: AudioState | None = None,
        audio_rng: Crand,
    ) -> None:
        # The base class asks whether runs rank while it sets up.
        self._custom_quest: CustomQuest | None = None
        super().__init__(
            ctx,
            default_game_mode_id=GameMode.QUESTS,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._quest_def: QuestDefinition | None = None
        self._quest_level: QuestLevel | None = self.config.gameplay.quest_level or QuestLevel(1, 1)
        self._quest_highscore_random_tag: int = 0
        self._quest_spawn_state = QuestSpawnState()
        self._replay_recorder: ReplayRecorder | None = None

    def open(self) -> None:
        super().open()
        self._prepare_selected_quest()

    def close(self) -> None:
        self._world_runtime.end_session()
        super().close()

    def _replay_checkpoint_elapsed_ms(self) -> float:
        return float(self._quest_spawn_state.spawn_timeline_ms)


    def _finish_run(self, outcome: RunOutcome) -> None:
        self._close_run("completed" if outcome == RunOutcome.QUEST_COMPLETED else "failed")

    def select_custom_quest(self, quest: CustomQuest | None) -> None:
        """The custom quest the next run plays, or None for a stock level: known before the screen opens, whose
        world reset already takes its seed and player count from whether the run ranks."""
        self._custom_quest = quest

    def _prepare_selected_quest(self) -> None:
        self._quest_def = None
        self._quest_highscore_random_tag = 0
        self._reset_gameplay_frame_clock()
        if self._custom_quest is not None:
            self._quest_level = None
            self._prepare_run(custom_quest=self._custom_quest)
            return
        level = self.config.gameplay.quest_level or QuestLevel(1, 1)
        self._quest_level = level
        quest = quest_by_level(level)
        if quest is None:
            self._world_runtime.end_session()
            return
        self._prepare_run(quest_level=quest.level)

    def _prepare_run(
        self,
        *,
        quest_level: QuestLevel | None = None,
        custom_quest: CustomQuest | None = None,
    ) -> None:
        prepared = self._initialize_run(GameMode.QUESTS, quest_level=quest_level, custom_quest=custom_quest)
        spawn_state = prepared.session.mode_state
        assert isinstance(spawn_state, QuestSpawnState)
        self._quest_spawn_state = spawn_state
        self._quest_highscore_random_tag = prepared.quest_highscore_random_tag & UNI_NUM_MASK
        self._quest_def = prepared.quest
        self._reset_gameplay_frame_clock()

    def _handle_input(self) -> None:
        if debug_enabled() and (not self._perk_menu.open):
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F2):
                self._debug_cheat_used()
                self.state.debug_god_mode = not bool(self.state.debug_god_mode)
                self.audio_bridge.play_sfx(SfxId.UI_BUTTONCLICK)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F3):
                self._debug_cheat_used()
                self.state.perk_selection.pending_count += 1
                self.state.perk_selection.choices_dirty = True
                self.audio_bridge.play_sfx(SfxId.UI_LEVELUP)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
                self._debug_cheat_used()
                self._debug_cycle_weapon(-1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
                self._debug_cheat_used()
                self._debug_cycle_weapon(1)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or pad_nav_pressed(PadCode.START):
            self._request_pause()
            return

    def _tick_death_timers(self, dt: float, *, rate: float = 20.0) -> None:
        delta = float(dt) * float(rate)
        if delta <= 0.0:
            return
        for player in self.world.players:
            if float(player.health) > 0.0:
                continue
            if float(player.death_timer) < 0.0:
                continue
            player.death_timer = float(player.death_timer) - delta

    def _close_run(self, kind: str) -> None:
        assert self._quest_level is not None or self._custom_quest is not None, "a quest outcome needs its quest"
        base_time_ms = int(self._quest_spawn_state.spawn_timeline_ms)
        record = build_highscore_record(
            state=self.state,
            player=self.player,
            run_elapsed_ms=base_time_ms,
            creature_kill_count=int(self.creatures.kill_count),
            rand_value=int(self._quest_highscore_random_tag),
        )
        if replay_number := self._save_replay():
            record.replay_number = replay_number
        self._action = ShowQuestOutcome(
            QuestRunOutcome(
                kind=kind,
                level=self._quest_level,
                custom_quest=self._custom_quest,
                base_time_ms=base_time_ms,
                player_health_values=tuple(float(player.health) for player in self.world.players),
                pending_perk_count=int(self.state.perk_selection.pending_count),
                record=record,
            ),
        )
    def _on_tick_applied(self, tick: DeterministicSessionTick) -> bool:
        if tick.save_status:
            # Native `quest_mode_update` calls `game_save_status` itself, so the completion and the unlock
            # reach game.cfg even when a death then turns the pending results into Quest Failed.
            try:
                self.state.status.save_if_dirty()
            except OSError as exc:
                if self._console is not None:
                    self._console.log.log(f"quest: status not saved ({exc})")
        return super()._on_tick_applied(tick)

    def update(self, dt: float) -> None:
        frame = self._begin_mode_update(float(dt))
        if frame is None:
            return

        self._update_perk_ui(dt_ui_ms=float(frame.dt_ui_ms))

        sim_dt = 0.0 if (self._paused or self._perk_menu.active) else float(frame.dt)
        session = self._sim_session
        if sim_dt <= 0.0:
            self._reset_gameplay_frame_clock()
            # Match legacy transition behavior: keep countdown moving, but at
            # real-time pace while perk-menu transition is holding world ticks.
            self._tick_death_timers(float(frame.dt), rate=1.0)
            self._finish_run_if_over()
            return
        if session is None:
            return

        self._run_deterministic_session_ticks(
            dt_frame=float(sim_dt),
            session=session,
            recorder=self._replay_recorder,
        )

    def draw(self) -> None:
        perk_menu_active = self._perk_menu.active
        entity_alpha = self._world_entity_alpha()
        self._draw_world(entity_alpha=entity_alpha)
        self._draw_screen_fade()
        # Native order: perk prompt, aim indicators, then the HUD over both.
        self._draw_perk_prompt()
        self._draw_aim_indicators(show_aim=not perk_menu_active, entity_alpha=entity_alpha)

        hud_bottom = 0.0
        if not perk_menu_active:
            total = self._quest_spawn_state.total_creatures
            kills = int(self.creatures.kill_count)
            quest_progress_ratio = float(kills) / float(total) if total > 0 else None
            self._draw_target_health_bar()
            hud_bottom = self._draw_hud(
                elapsed_ms=float(self._quest_spawn_state.spawn_timeline_ms),
                quest_progress_ratio=quest_progress_ratio,
            )

        if debug_enabled() and (not perk_menu_active):
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            god = "on" if self.state.debug_god_mode else "off"
            self._draw_ui_text(f"debug: [/] weapon  F3 perk+1  F2 god={god}", Vec2(x, y), UI_HINT_COLOR)

        self._draw_quest_title()
        self._draw_quest_complete_banner()

        self._perk_menu.draw(
            self._perk_menu_ui_context(),
            perk_selection_prepared_choices(self.state),
        )

        self._draw_keybind_help()
        if perk_menu_active:
            self._draw_game_cursor()


    def _draw_quest_title(self) -> None:
        font = self._grim_mono
        if font is None:
            return
        quest, custom = self._quest_def, self._custom_quest
        if quest is not None:
            title, number, subtitle = quest.title, quest.level.text, ""
        elif custom is not None:
            # A custom quest has no stock number; its author's byline goes under the title.
            title, number, subtitle = custom.title, "", custom.byline
        else:
            return
        draw_quest_title_timer_overlay(
            font,
            title,
            number,
            subtitle=subtitle,
            timer_ms=float(self._quest_spawn_state.stage_banner_timer_ms),
        )

    def _draw_quest_complete_banner(self) -> None:
        tex = self.render_resources.resources.texture(TextureId.UI_TEXT_LEVEL_COMPLETE)
        draw_quest_complete_banner_overlay(
            tex,
            timer_ms=float(self._quest_spawn_state.completion_transition_ms),
        )
