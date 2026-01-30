from __future__ import annotations

from dataclasses import dataclass
import random

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.fonts.grim_mono import GrimMonoFont, load_grim_mono_font
from grim.view import ViewContext

from ..game_modes import GameMode
from ..gameplay import most_used_weapon_id_for_player, weapon_assign_player
from ..input_codes import config_keybinds, input_code_is_down, input_code_is_pressed, player_move_fire_binds
from ..persistence.save_status import GameStatus
from ..quests import quest_by_level
from ..quests.runtime import build_quest_spawn_table, tick_quest_completion_transition
from ..quests.timeline import quest_spawn_table_empty, tick_quest_mode_spawns
from ..quests.types import QuestContext, QuestDefinition, SpawnEntry
from ..terrain_assets import terrain_texture_by_id
from ..ui.cursor import draw_aim_cursor, draw_menu_cursor
from ..ui.hud import draw_hud_overlay, hud_ui_scale
from ..ui.perk_menu import PerkMenuAssets, load_perk_menu_assets
from ..views.quest_title_overlay import draw_quest_title_overlay
from .base_gameplay_mode import BaseGameplayMode

WORLD_SIZE = 1024.0
QUEST_TITLE_FADE_IN_MS = 500.0
QUEST_TITLE_HOLD_MS = 1000.0
QUEST_TITLE_FADE_OUT_MS = 500.0
QUEST_TITLE_TOTAL_MS = QUEST_TITLE_FADE_IN_MS + QUEST_TITLE_HOLD_MS + QUEST_TITLE_FADE_OUT_MS


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


@dataclass(frozen=True, slots=True)
class QuestRunOutcome:
    kind: str  # "completed" | "failed"
    level: str
    base_time_ms: int
    player_health: float
    player2_health: float | None
    pending_perk_count: int
    experience: int
    kill_count: int
    weapon_id: int
    shots_fired: int
    shots_hit: int
    most_used_weapon_id: int


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


def _quest_level_label(level: str) -> str:
    try:
        tier_text, quest_text = level.split(".", 1)
        return f"{int(tier_text)}-{int(quest_text)}"
    except Exception:
        return level.replace(".", "-", 1)


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
        self._outcome: QuestRunOutcome | None = None
        self._ui_assets: PerkMenuAssets | None = None
        self._grim_mono: GrimMonoFont | None = None

    def open(self) -> None:
        super().open()
        self._quest = _QuestRunState()
        self._outcome = None
        self._ui_assets = load_perk_menu_assets(self._assets_root)
        if self._ui_assets.missing:
            self._missing_assets.extend(self._ui_assets.missing)
        try:
            self._grim_mono = load_grim_mono_font(self._assets_root, self._missing_assets)
        except Exception:
            self._grim_mono = None

    def close(self) -> None:
        if self._grim_mono is not None:
            rl.unload_texture(self._grim_mono.texture)
            self._grim_mono = None
        self._ui_assets = None
        super().close()

    def select_level(self, level: str | None) -> None:
        self._selected_level = level

    def consume_outcome(self) -> QuestRunOutcome | None:
        outcome = self._outcome
        self._outcome = None
        return outcome

    def prepare_new_run(self, level: str, *, status: GameStatus | None) -> None:
        quest = quest_by_level(level)
        if quest is None:
            self._quest = _QuestRunState(level=level)
            return
        self._outcome = None

        hardcore_flag = False
        if self._config is not None:
            hardcore_flag = bool(int(self._config.data.get("hardcore_flag", 0) or 0))

        self._world.hardcore = hardcore_flag
        seed = _quest_seed(level)

        player_count = 1
        config = self._config
        if config is not None:
            try:
                player_count = int(config.data.get("player_count", 1) or 1)
            except Exception:
                player_count = 1
        self._world.reset(seed=seed, player_count=max(1, min(4, player_count)))
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

        # Quest metadata stores native (1-based) weapon ids; the rewrite uses 0-based ids.
        start_weapon_id = max(0, int(quest.start_weapon_id) - 1)
        for player in self._world.players:
            weapon_assign_player(player, start_weapon_id)

        ctx = QuestContext(
            width=int(self._world.world_size),
            height=int(self._world.world_size),
            player_count=len(self._world.players),
        )
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

    def _handle_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True

    def _build_input(self):
        keybinds = config_keybinds(self._config)
        if not keybinds:
            keybinds = (0x11, 0x1F, 0x1E, 0x20, 0x100)
        up_key, down_key, left_key, right_key, fire_key = player_move_fire_binds(keybinds, 0)

        move_x = 0.0
        move_y = 0.0
        if input_code_is_down(left_key):
            move_x -= 1.0
        if input_code_is_down(right_key):
            move_x += 1.0
        if input_code_is_down(up_key):
            move_y -= 1.0
        if input_code_is_down(down_key):
            move_y += 1.0

        mouse = self._ui_mouse_pos()
        aim_x, aim_y = self._world.screen_to_world(float(mouse.x), float(mouse.y))

        fire_down = input_code_is_down(fire_key)
        fire_pressed = input_code_is_pressed(fire_key)
        reload_key = 0x102
        if self._config is not None:
            reload_key = int(self._config.data.get("keybind_reload", reload_key) or reload_key)
        reload_pressed = input_code_is_pressed(reload_key)

        from ..gameplay import PlayerInput

        return PlayerInput(
            move_x=move_x,
            move_y=move_y,
            aim_x=float(aim_x),
            aim_y=float(aim_y),
            fire_down=bool(fire_down),
            fire_pressed=bool(fire_pressed),
            reload_pressed=bool(reload_pressed),
        )

    def update(self, dt: float) -> None:
        self._update_audio(dt)

        dt_frame = self._tick_frame(dt)[0]
        dt_ms = float(dt_frame * 1000.0)
        self._handle_input()

        if self.close_requested:
            return

        any_alive = any(player.health > 0.0 for player in self._world.players)
        dt_world = 0.0 if self._paused or (not any_alive) else dt_frame
        if dt_world <= 0.0:
            return

        self._quest.quest_name_timer_ms += dt_ms

        input_state = self._build_input()
        self._world.update(
            dt_world,
            inputs=[input_state for _ in self._world.players],
            auto_pick_perks=False,
            game_mode=int(GameMode.QUESTS),
            perk_progression_enabled=True,
        )

        any_alive_after = any(player.health > 0.0 for player in self._world.players)
        if not any_alive_after:
            if self._outcome is None:
                fired = 0
                hit = 0
                try:
                    fired = int(self._state.shots_fired[int(self._player.index)])
                    hit = int(self._state.shots_hit[int(self._player.index)])
                except Exception:
                    fired = 0
                    hit = 0
                fired = max(0, int(fired))
                hit = max(0, min(int(hit), fired))
                most_used_weapon_id = most_used_weapon_id_for_player(
                    self._state,
                    player_index=int(self._player.index),
                    fallback_weapon_id=int(self._player.weapon_id),
                )
                player2_health = None
                if len(self._world.players) >= 2:
                    player2_health = float(self._world.players[1].health)
                self._outcome = QuestRunOutcome(
                    kind="failed",
                    level=str(self._quest.level),
                    base_time_ms=int(self._quest.spawn_timeline_ms),
                    player_health=float(self._player.health),
                    player2_health=player2_health,
                    pending_perk_count=int(self._state.perk_selection.pending_count),
                    experience=int(self._player.experience),
                    kill_count=int(self._creatures.kill_count),
                    weapon_id=int(self._player.weapon_id),
                    shots_fired=fired,
                    shots_hit=hit,
                    most_used_weapon_id=int(most_used_weapon_id),
                )
            self.close_requested = True
            return

        creatures_none_active = not bool(self._creatures.iter_active())

        entries, timeline_ms, creatures_none_active, no_creatures_timer_ms, spawns = tick_quest_mode_spawns(
            self._quest.spawn_entries,
            quest_spawn_timeline_ms=float(self._quest.spawn_timeline_ms),
            frame_dt_ms=dt_world * 1000.0,
            terrain_width=float(self._world.world_size),
            creatures_none_active=creatures_none_active,
            no_creatures_timer_ms=float(self._quest.no_creatures_timer_ms),
        )
        self._quest.spawn_entries = entries
        self._quest.spawn_timeline_ms = float(timeline_ms)
        self._quest.no_creatures_timer_ms = float(no_creatures_timer_ms)

        for call in spawns:
            self._creatures.spawn_template(
                int(call.template_id),
                call.pos,
                float(call.heading),
                self._state.rng,
                rand=self._state.rng.rand,
            )

        completion_ms, completed = tick_quest_completion_transition(
            float(self._quest.completion_transition_ms),
            frame_dt_ms=dt_world * 1000.0,
            creatures_none_active=bool(creatures_none_active),
            spawn_table_empty=quest_spawn_table_empty(self._quest.spawn_entries),
        )
        self._quest.completion_transition_ms = float(completion_ms)
        if completed:
            if self._outcome is None:
                fired = 0
                hit = 0
                try:
                    fired = int(self._state.shots_fired[int(self._player.index)])
                    hit = int(self._state.shots_hit[int(self._player.index)])
                except Exception:
                    fired = 0
                    hit = 0
                fired = max(0, int(fired))
                hit = max(0, min(int(hit), fired))
                most_used_weapon_id = most_used_weapon_id_for_player(
                    self._state,
                    player_index=int(self._player.index),
                    fallback_weapon_id=int(self._player.weapon_id),
                )
                player2_health = None
                if len(self._world.players) >= 2:
                    player2_health = float(self._world.players[1].health)
                self._outcome = QuestRunOutcome(
                    kind="completed",
                    level=str(self._quest.level),
                    base_time_ms=int(self._quest.spawn_timeline_ms),
                    player_health=float(self._player.health),
                    player2_health=player2_health,
                    pending_perk_count=int(self._state.perk_selection.pending_count),
                    experience=int(self._player.experience),
                    kill_count=int(self._creatures.kill_count),
                    weapon_id=int(self._player.weapon_id),
                    shots_fired=fired,
                    shots_hit=hit,
                    most_used_weapon_id=int(most_used_weapon_id),
                )
            self.close_requested = True

    def draw(self) -> None:
        self._world.draw(draw_aim_indicators=True)
        self._draw_screen_fade()

        hud_bottom = 0.0
        if self._hud_assets is not None:
            hud_bottom = draw_hud_overlay(
                self._hud_assets,
                player=self._player,
                players=self._world.players,
                bonus_hud=self._state.bonus_hud,
                elapsed_ms=float(self._quest.spawn_timeline_ms),
                font=self._small,
                frame_dt_ms=self._last_dt_ms,
                show_xp=False,
                show_time=True,
            )
            total = int(self._quest.total_spawn_count)
            if total > 0:
                kills = int(self._creatures.kill_count)
                ratio = max(0.0, min(1.0, float(kills) / float(total)))
                scale = hud_ui_scale(float(rl.get_screen_width()), float(rl.get_screen_height()))
                bar_x = 255.0 * scale
                bar_y = 30.0 * scale
                bar_w = 120.0 * scale
                bar_h = 6.0 * scale
                bg = rl.Color(40, 40, 48, 200)
                fg = rl.Color(220, 220, 220, 240)
                rl.draw_rectangle(int(bar_x), int(bar_y), int(bar_w), int(bar_h), bg)
                inner_w = max(0.0, bar_w - 2.0 * scale)
                inner_h = max(0.0, bar_h - 2.0 * scale)
                rl.draw_rectangle(
                    int(bar_x + scale),
                    int(bar_y + scale),
                    int(inner_w * ratio),
                    int(inner_h),
                    fg,
                )
                self._draw_ui_text(f"{kills}/{total}", bar_x + bar_w + 8.0 * scale, bar_y - 3.0 * scale, rl.Color(220, 220, 220, 255), scale=0.8 * scale)

        self._draw_quest_title()

        warn_y = float(rl.get_screen_height()) - 28.0
        if self._world.missing_assets:
            warn = "Missing world assets: " + ", ".join(self._world.missing_assets)
            self._draw_ui_text(warn, 24.0, warn_y, rl.Color(240, 80, 80, 255), scale=0.8)
            warn_y -= float(self._ui_line_height(scale=0.8)) + 2.0
        if self._hud_missing:
            warn = "Missing HUD assets: " + ", ".join(self._hud_missing)
            self._draw_ui_text(warn, 24.0, warn_y, rl.Color(240, 80, 80, 255), scale=0.8)

        self._draw_aim_cursor()
        if self._paused:
            self._draw_game_cursor()
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            self._draw_ui_text("paused (TAB)", x, y, rl.Color(140, 140, 140, 255))

    def _draw_game_cursor(self) -> None:
        assets = self._ui_assets
        cursor_tex = assets.cursor if assets is not None else None
        draw_menu_cursor(
            self._world.particles_texture,
            cursor_tex,
            x=float(self._ui_mouse_x),
            y=float(self._ui_mouse_y),
            pulse_time=float(self._cursor_pulse_time),
        )

    def _draw_aim_cursor(self) -> None:
        assets = self._ui_assets
        aim_tex = assets.aim if assets is not None else None
        draw_aim_cursor(
            self._world.particles_texture,
            aim_tex,
            x=float(self._ui_mouse_x),
            y=float(self._ui_mouse_y),
        )

    def _draw_quest_title(self) -> None:
        font = self._grim_mono
        quest = self._quest.quest
        if font is None or quest is None:
            return
        timer_ms = float(self._quest.quest_name_timer_ms)
        if timer_ms <= 0.0 or timer_ms > QUEST_TITLE_TOTAL_MS:
            return
        if timer_ms < QUEST_TITLE_FADE_IN_MS and QUEST_TITLE_FADE_IN_MS > 1e-3:
            alpha = timer_ms / QUEST_TITLE_FADE_IN_MS
        elif timer_ms < (QUEST_TITLE_FADE_IN_MS + QUEST_TITLE_HOLD_MS):
            alpha = 1.0
        else:
            t = timer_ms - (QUEST_TITLE_FADE_IN_MS + QUEST_TITLE_HOLD_MS)
            alpha = max(0.0, 1.0 - (t / max(1e-3, QUEST_TITLE_FADE_OUT_MS)))

        draw_quest_title_overlay(font, quest.title, _quest_level_label(self._quest.level), alpha=alpha)
