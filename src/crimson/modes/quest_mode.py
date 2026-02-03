from __future__ import annotations

from dataclasses import dataclass
import random

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.console import ConsoleState
from grim.config import CrimsonConfig
from grim.fonts.grim_mono import GrimMonoFont, load_grim_mono_font
from grim.math import clamp
from grim.view import ViewContext

from ..debug import debug_enabled
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
from ..ui.hud import draw_hud_overlay, hud_flags_for_game_mode
from ..ui.perk_menu import PerkMenuAssets, draw_ui_text, load_perk_menu_assets
from ..views.quest_title_overlay import draw_quest_title_overlay
from ..weapons import WEAPON_BY_ID
from .base_gameplay_mode import BaseGameplayMode
from .components.perk_menu_controller import PerkMenuContext, PerkMenuController

WORLD_SIZE = 1024.0
QUEST_TITLE_FADE_IN_MS = 500.0
QUEST_TITLE_HOLD_MS = 1000.0
QUEST_TITLE_FADE_OUT_MS = 500.0
QUEST_TITLE_TOTAL_MS = QUEST_TITLE_FADE_IN_MS + QUEST_TITLE_HOLD_MS + QUEST_TITLE_FADE_OUT_MS

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))

PERK_PROMPT_MAX_TIMER_MS = 200.0
PERK_PROMPT_OUTSET_X = 50.0
# Perk prompt bar geometry comes from `ui_menu_assets_init` + `ui_menu_layout_init`:
# - `ui_menu_item_element` is set_rect(512x64, offset -72,-60)
# - the perk prompt mutates quad coords: x = (x - 300) * 0.75, y = y * 0.75
PERK_PROMPT_BAR_SCALE = 0.75
PERK_PROMPT_BAR_BASE_OFFSET_X = -72.0
PERK_PROMPT_BAR_BASE_OFFSET_Y = -60.0
PERK_PROMPT_BAR_SHIFT_X = -300.0

# `ui_textLevelUp` is set_rect(75x25, offset -230,-27), then its quad coords are:
# x = x * 0.85 - 46, y = y * 0.85 - 4
PERK_PROMPT_LEVEL_UP_SCALE = 0.85
PERK_PROMPT_LEVEL_UP_BASE_OFFSET_X = -230.0
PERK_PROMPT_LEVEL_UP_BASE_OFFSET_Y = -27.0
PERK_PROMPT_LEVEL_UP_BASE_W = 75.0
PERK_PROMPT_LEVEL_UP_BASE_H = 25.0
PERK_PROMPT_LEVEL_UP_SHIFT_X = -46.0
PERK_PROMPT_LEVEL_UP_SHIFT_Y = -4.0

PERK_PROMPT_TEXT_MARGIN_X = 16.0

_DEBUG_WEAPON_IDS = tuple(sorted(WEAPON_BY_ID))
PERK_PROMPT_TEXT_OFFSET_Y = 8.0


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
        console: ConsoleState | None = None,
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
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._quest = _QuestRunState()
        self._selected_level: str | None = None
        self._outcome: QuestRunOutcome | None = None
        self._perk_menu_assets: PerkMenuAssets | None = None
        self._grim_mono: GrimMonoFont | None = None

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_prompt_pulse = 0.0
        self._perk_menu = PerkMenuController(on_close=self._reset_perk_prompt)

    def open(self) -> None:
        super().open()
        self._quest = _QuestRunState()
        self._outcome = None
        self._perk_menu_assets = load_perk_menu_assets(self._assets_root)
        if self._perk_menu_assets.missing:
            self._missing_assets.extend(self._perk_menu_assets.missing)
        try:
            self._grim_mono = load_grim_mono_font(self._assets_root, self._missing_assets)
        except Exception:
            self._grim_mono = None

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_prompt_pulse = 0.0
        self._perk_menu.reset()

    def close(self) -> None:
        if self._grim_mono is not None:
            rl.unload_texture(self._grim_mono.texture)
            self._grim_mono = None
        self._perk_menu_assets = None
        super().close()

    def _reset_perk_prompt(self) -> None:
        if int(self._state.perk_selection.pending_count) > 0:
            # Reset the prompt swing so each pending perk replays the intro.
            self._perk_prompt_timer_ms = 0.0
            self._perk_prompt_hover = False
            self._perk_prompt_pulse = 0.0

    def _perk_menu_context(self) -> PerkMenuContext:
        fx_toggle = int(self._config.data.get("fx_toggle", 0) or 0) if self._config is not None else 0
        fx_detail = bool(int(self._config.data.get("fx_detail_0", 0) or 0)) if self._config is not None else False
        players = self._world.players
        return PerkMenuContext(
            state=self._state,
            perk_state=self._state.perk_selection,
            players=players,
            creatures=self._creatures.entries,
            player=self._player,
            game_mode=int(GameMode.QUESTS),
            player_count=len(players),
            fx_toggle=fx_toggle,
            fx_detail=fx_detail,
            font=self._small,
            assets=self._perk_menu_assets,
            mouse=self._ui_mouse_pos(),
            play_sfx=self._world.audio_router.play_sfx,
        )

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
        self._state.status = status
        self._state.quest_stage_major, self._state.quest_stage_minor = quest.level_key

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

        # Quest metadata already stores native (1-based) weapon ids.
        start_weapon_id = max(1, int(quest.start_weapon_id))
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
        if self._perk_menu.open and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._world.audio_router.play_sfx("sfx_ui_buttonclick")
            self._perk_menu.close()
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if debug_enabled() and (not self._perk_menu.open):
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F2):
                self._state.debug_god_mode = not bool(self._state.debug_god_mode)
                self._world.audio_router.play_sfx("sfx_ui_buttonclick")
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F3):
                self._state.perk_selection.pending_count += 1
                self._state.perk_selection.choices_dirty = True
                self._world.audio_router.play_sfx("sfx_ui_levelup")
            if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
                self._debug_cycle_weapon(-1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
                self._debug_cycle_weapon(1)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._action = "open_pause_menu"
            return

    def _debug_cycle_weapon(self, delta: int) -> None:
        weapon_ids = _DEBUG_WEAPON_IDS
        if not weapon_ids:
            return
        current = int(self._player.weapon_id)
        try:
            idx = weapon_ids.index(current)
        except ValueError:
            idx = 0
        weapon_id = int(weapon_ids[(idx + int(delta)) % len(weapon_ids)])
        weapon_assign_player(self._player, weapon_id, state=self._state)

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

    def _perk_prompt_label(self) -> str:
        if self._config is not None and not bool(int(self._config.data.get("ui_info_texts", 1) or 0)):
            return ""
        pending = int(self._state.perk_selection.pending_count)
        if pending <= 0:
            return ""
        suffix = f" ({pending})" if pending > 1 else ""
        return f"Press Mouse2 to pick a perk{suffix}"

    def _perk_prompt_hinge(self) -> tuple[float, float]:
        screen_w = float(rl.get_screen_width())
        hinge_x = screen_w + PERK_PROMPT_OUTSET_X
        hinge_y = 80.0 if int(screen_w) == 640 else 40.0
        return hinge_x, hinge_y

    def _perk_prompt_rect(self, label: str, *, scale: float = UI_TEXT_SCALE) -> rl.Rectangle:
        hinge_x, hinge_y = self._perk_prompt_hinge()
        if self._perk_menu_assets is not None and self._perk_menu_assets.menu_item is not None:
            tex = self._perk_menu_assets.menu_item
            bar_w = float(tex.width) * PERK_PROMPT_BAR_SCALE
            bar_h = float(tex.height) * PERK_PROMPT_BAR_SCALE
            local_x = (PERK_PROMPT_BAR_BASE_OFFSET_X + PERK_PROMPT_BAR_SHIFT_X) * PERK_PROMPT_BAR_SCALE
            local_y = PERK_PROMPT_BAR_BASE_OFFSET_Y * PERK_PROMPT_BAR_SCALE
            return rl.Rectangle(
                float(hinge_x + local_x),
                float(hinge_y + local_y),
                float(bar_w),
                float(bar_h),
            )

        margin = 16.0 * scale
        text_w = float(self._ui_text_width(label, scale))
        text_h = float(self._ui_line_height(scale))
        x = float(rl.get_screen_width()) - margin - text_w
        y = margin
        return rl.Rectangle(x, y, text_w, text_h)

    def _close_failed_run(self) -> None:
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

    def _draw_perk_prompt(self) -> None:
        if self._perk_menu.active:
            return
        if not any(player.health > 0.0 for player in self._world.players):
            return
        pending = int(self._state.perk_selection.pending_count)
        if pending <= 0:
            return
        label = self._perk_prompt_label()
        if not label:
            return

        alpha = float(self._perk_prompt_timer_ms) / PERK_PROMPT_MAX_TIMER_MS
        if alpha <= 1e-3:
            return

        hinge_x, hinge_y = self._perk_prompt_hinge()
        # Prompt swings counter-clockwise; raylib's Y-down makes positive rotation clockwise.
        rot_deg = -(1.0 - alpha) * 90.0
        tint = rl.Color(255, 255, 255, int(255 * alpha))

        text_w = float(self._ui_text_width(label, UI_TEXT_SCALE))
        x = float(rl.get_screen_width()) - PERK_PROMPT_TEXT_MARGIN_X - text_w
        y = hinge_y + PERK_PROMPT_TEXT_OFFSET_Y
        color = rl.Color(UI_TEXT_COLOR.r, UI_TEXT_COLOR.g, UI_TEXT_COLOR.b, int(255 * alpha))
        draw_ui_text(self._small, label, x, y, scale=UI_TEXT_SCALE, color=color)

        if self._perk_menu_assets is not None and self._perk_menu_assets.menu_item is not None:
            tex = self._perk_menu_assets.menu_item
            bar_w = float(tex.width) * PERK_PROMPT_BAR_SCALE
            bar_h = float(tex.height) * PERK_PROMPT_BAR_SCALE
            local_x = (PERK_PROMPT_BAR_BASE_OFFSET_X + PERK_PROMPT_BAR_SHIFT_X) * PERK_PROMPT_BAR_SCALE
            local_y = PERK_PROMPT_BAR_BASE_OFFSET_Y * PERK_PROMPT_BAR_SCALE
            src = rl.Rectangle(float(tex.width), 0.0, -float(tex.width), float(tex.height))
            dst = rl.Rectangle(float(hinge_x), float(hinge_y), float(bar_w), float(bar_h))
            origin = rl.Vector2(float(-local_x), float(-local_y))
            rl.draw_texture_pro(tex, src, dst, origin, rot_deg, tint)

        if self._perk_menu_assets is not None and self._perk_menu_assets.title_level_up is not None:
            tex = self._perk_menu_assets.title_level_up
            local_x = PERK_PROMPT_LEVEL_UP_BASE_OFFSET_X * PERK_PROMPT_LEVEL_UP_SCALE + PERK_PROMPT_LEVEL_UP_SHIFT_X
            local_y = PERK_PROMPT_LEVEL_UP_BASE_OFFSET_Y * PERK_PROMPT_LEVEL_UP_SCALE + PERK_PROMPT_LEVEL_UP_SHIFT_Y
            w = PERK_PROMPT_LEVEL_UP_BASE_W * PERK_PROMPT_LEVEL_UP_SCALE
            h = PERK_PROMPT_LEVEL_UP_BASE_H * PERK_PROMPT_LEVEL_UP_SCALE
            pulse_alpha = (100.0 + float(int(self._perk_prompt_pulse * 155.0 / 1000.0))) / 255.0
            pulse_alpha = max(0.0, min(1.0, pulse_alpha))
            label_alpha = max(0.0, min(1.0, alpha * pulse_alpha))
            pulse_tint = rl.Color(255, 255, 255, int(255 * label_alpha))
            src = rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height))
            dst = rl.Rectangle(float(hinge_x), float(hinge_y), float(w), float(h))
            origin = rl.Vector2(float(-local_x), float(-local_y))
            rl.draw_texture_pro(tex, src, dst, origin, rot_deg, pulse_tint)
            if label_alpha > 0.0:
                rl.begin_blend_mode(rl.BLEND_ADDITIVE)
                rl.draw_texture_pro(tex, src, dst, origin, rot_deg, pulse_tint)
                rl.end_blend_mode()

    def update(self, dt: float) -> None:
        self._update_audio(dt)

        dt_frame, dt_ui_ms = self._tick_frame(dt)
        self._handle_input()
        if self._action == "open_pause_menu":
            return

        if self.close_requested:
            return

        any_alive = any(player.health > 0.0 for player in self._world.players)
        perk_pending = int(self._state.perk_selection.pending_count) > 0 and any_alive

        self._perk_prompt_hover = False
        perk_ctx = self._perk_menu_context()
        if self._perk_menu.open:
            self._perk_menu.handle_input(perk_ctx, dt_frame=dt_frame, dt_ui_ms=dt_ui_ms)

        perk_menu_active = self._perk_menu.active

        if (not perk_menu_active) and perk_pending and (not self._paused):
            label = self._perk_prompt_label()
            if label:
                rect = self._perk_prompt_rect(label)
                self._perk_prompt_hover = rl.check_collision_point_rec(self._ui_mouse_pos(), rect)

            keybinds = config_keybinds(self._config)
            if not keybinds:
                keybinds = (0x11, 0x1F, 0x1E, 0x20, 0x100)
            _up_key, _down_key, _left_key, _right_key, fire_key = player_move_fire_binds(keybinds, 0)

            pick_key = 0x101
            if self._config is not None:
                pick_key = int(self._config.data.get("keybind_pick_perk", pick_key) or pick_key)

            if input_code_is_pressed(pick_key) and (not input_code_is_down(fire_key)):
                self._perk_prompt_pulse = 1000.0
                self._perk_menu.open_if_available(perk_ctx)
            elif self._perk_prompt_hover and input_code_is_pressed(fire_key):
                self._perk_prompt_pulse = 1000.0
                self._perk_menu.open_if_available(perk_ctx)

        perk_menu_active = self._perk_menu.active

        if not self._paused:
            pulse_delta = dt_ui_ms * (6.0 if self._perk_prompt_hover else -2.0)
            self._perk_prompt_pulse = clamp(self._perk_prompt_pulse + pulse_delta, 0.0, 1000.0)

        prompt_active = perk_pending and (not perk_menu_active) and (not self._paused)
        if prompt_active:
            self._perk_prompt_timer_ms = clamp(self._perk_prompt_timer_ms + dt_ui_ms, 0.0, PERK_PROMPT_MAX_TIMER_MS)
        else:
            self._perk_prompt_timer_ms = clamp(self._perk_prompt_timer_ms - dt_ui_ms, 0.0, PERK_PROMPT_MAX_TIMER_MS)

        self._perk_menu.tick_timeline(dt_ui_ms)

        dt_world = 0.0 if self._paused or (not any_alive) or self._perk_menu.active else dt_frame
        if dt_world <= 0.0:
            if not any(player.health > 0.0 for player in self._world.players):
                self._close_failed_run()
            return

        self._quest.quest_name_timer_ms += dt_world * 1000.0

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
            self._close_failed_run()
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

        detail_preset = 5
        if self._world.config is not None:
            detail_preset = int(self._world.config.data.get("detail_preset", 5) or 5)
        for call in spawns:
            self._creatures.spawn_template(
                int(call.template_id),
                call.pos,
                float(call.heading),
                self._state.rng,
                rand=self._state.rng.rand,
                state=self._state,
                detail_preset=detail_preset,
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
        perk_menu_active = self._perk_menu.active
        self._world.draw(draw_aim_indicators=not perk_menu_active)
        self._draw_screen_fade()

        hud_bottom = 0.0
        if (not perk_menu_active) and self._hud_assets is not None:
            total = int(self._quest.total_spawn_count)
            kills = int(self._creatures.kill_count)
            quest_progress_ratio = float(kills) / float(total) if total > 0 else None
            hud_flags = hud_flags_for_game_mode(self._config_game_mode_id())
            self._draw_target_health_bar()
            hud_bottom = draw_hud_overlay(
                self._hud_assets,
                state=self._hud_state,
                player=self._player,
                players=self._world.players,
                bonus_hud=self._state.bonus_hud,
                elapsed_ms=float(self._quest.spawn_timeline_ms),
                font=self._small,
                frame_dt_ms=self._last_dt_ms,
                show_health=hud_flags.show_health,
                show_weapon=hud_flags.show_weapon,
                show_xp=hud_flags.show_xp,
                show_time=hud_flags.show_time,
                show_quest_hud=hud_flags.show_quest_hud,
                quest_progress_ratio=quest_progress_ratio,
                small_indicators=self._hud_small_indicators(),
            )

        if debug_enabled() and (not perk_menu_active):
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            god = "on" if self._state.debug_god_mode else "off"
            self._draw_ui_text(f"debug: [/] weapon  F3 perk+1  F2 god={god}", x, y, UI_HINT_COLOR, scale=0.9)

        self._draw_quest_title()

        warn_y = float(rl.get_screen_height()) - 28.0
        if self._world.missing_assets:
            warn = "Missing world assets: " + ", ".join(self._world.missing_assets)
            self._draw_ui_text(warn, 24.0, warn_y, rl.Color(240, 80, 80, 255), scale=0.8)
            warn_y -= float(self._ui_line_height(scale=0.8)) + 2.0
        if self._hud_missing:
            warn = "Missing HUD assets: " + ", ".join(self._hud_missing)
            self._draw_ui_text(warn, 24.0, warn_y, rl.Color(240, 80, 80, 255), scale=0.8)

        self._draw_perk_prompt()
        self._perk_menu.draw(self._perk_menu_context())

        if perk_menu_active:
            self._draw_game_cursor()
        elif self._paused:
            self._draw_game_cursor()
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            if debug_enabled() and (not perk_menu_active):
                y += float(self._ui_line_height(scale=0.9))
            self._draw_ui_text("paused (TAB)", x, y, UI_HINT_COLOR)
        else:
            self._draw_aim_cursor()

    def _draw_game_cursor(self) -> None:
        assets = self._perk_menu_assets
        cursor_tex = assets.cursor if assets is not None else None
        draw_menu_cursor(
            self._world.particles_texture,
            cursor_tex,
            x=float(self._ui_mouse_x),
            y=float(self._ui_mouse_y),
            pulse_time=float(self._cursor_pulse_time),
        )

    def _draw_aim_cursor(self) -> None:
        assets = self._perk_menu_assets
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
