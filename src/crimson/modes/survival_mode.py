from __future__ import annotations

from dataclasses import dataclass
import random

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.console import ConsoleState
from grim.config import CrimsonConfig
from grim.math import clamp
from grim.view import ViewContext

from ..creatures.spawn import advance_survival_spawn_stage, tick_survival_wave_spawns
from ..debug import debug_enabled
from ..game_modes import GameMode
from ..gameplay import (
    PlayerInput,
    most_used_weapon_id_for_player,
    survival_check_level_up,
    weapon_assign_player,
)
from ..persistence.highscores import HighScoreRecord
from ..perks import PerkId
from ..ui.cursor import draw_aim_cursor, draw_menu_cursor
from ..ui.hud import draw_hud_overlay, hud_flags_for_game_mode
from ..input_codes import config_keybinds, input_code_is_down, input_code_is_pressed, player_move_fire_binds
from ..ui.perk_menu import PERK_MENU_TRANSITION_MS, draw_ui_text, load_perk_menu_assets
from ..weapons import WEAPON_BY_ID
from .base_gameplay_mode import BaseGameplayMode
from .components.perk_menu_controller import PerkMenuContext, PerkMenuController

WORLD_SIZE = 1024.0

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)

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
PERK_PROMPT_TEXT_OFFSET_Y = 8.0

_DEBUG_WEAPON_IDS = tuple(sorted(WEAPON_BY_ID))


@dataclass(slots=True)
class _SurvivalState:
    elapsed_ms: float = 0.0
    stage: int = 0
    spawn_cooldown: float = 0.0


class SurvivalMode(BaseGameplayMode):
    def __init__(
        self,
        ctx: ViewContext,
        *,
        texture_cache: PaqTextureCache | None = None,
        config: CrimsonConfig | None = None,
        console: ConsoleState | None = None,
        audio: AudioState | None = None,
        audio_rng: random.Random | None = None,
    ) -> None:
        super().__init__(
            ctx,
            world_size=WORLD_SIZE,
            default_game_mode_id=int(GameMode.SURVIVAL),
            demo_mode_active=False,
            difficulty_level=0,
            hardcore=False,
            texture_cache=texture_cache,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._survival = _SurvivalState()

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_prompt_pulse = 0.0
        self._perk_menu = PerkMenuController(on_close=self._reset_perk_prompt)
        self._hud_fade_ms = PERK_MENU_TRANSITION_MS
        self._perk_menu_assets = None
        self._cursor_time = 0.0

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
            game_mode=int(GameMode.SURVIVAL),
            player_count=len(players),
            fx_toggle=fx_toggle,
            fx_detail=fx_detail,
            font=self._small,
            assets=self._perk_menu_assets,
            mouse=self._ui_mouse_pos(),
            play_sfx=self._world.audio_router.play_sfx,
        )

    def _wrap_ui_text(self, text: str, *, max_width: float, scale: float = UI_TEXT_SCALE) -> list[str]:
        lines: list[str] = []
        for raw in text.splitlines() or [""]:
            para = raw.strip()
            if not para:
                lines.append("")
                continue
            current = ""
            for word in para.split():
                candidate = word if not current else f"{current} {word}"
                if current and self._ui_text_width(candidate, scale) > max_width:
                    lines.append(current)
                    current = word
                else:
                    current = candidate
            if current:
                lines.append(current)
        return lines

    def _camera_world_to_screen(self, x: float, y: float) -> tuple[float, float]:
        return self._world.world_to_screen(x, y)

    def _camera_screen_to_world(self, x: float, y: float) -> tuple[float, float]:
        return self._world.screen_to_world(x, y)

    def open(self) -> None:
        super().open()

        self._perk_menu_assets = load_perk_menu_assets(self._assets_root)
        if self._perk_menu_assets.missing:
            self._missing_assets.extend(self._perk_menu_assets.missing)
        self._perk_menu.reset()
        self._cursor_time = 0.0
        self._cursor_pulse_time = 0.0
        self._survival = _SurvivalState()

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_prompt_pulse = 0.0
        self._hud_fade_ms = PERK_MENU_TRANSITION_MS

    def close(self) -> None:
        if self._perk_menu_assets is not None:
            self._perk_menu_assets = None
        super().close()

    def _handle_input(self) -> None:
        if self._game_over_active:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
                self._action = "back_to_menu"
                self.close_requested = True
            return
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
            if rl.is_key_pressed(rl.KeyboardKey.KEY_X):
                self._player.experience += 5000
                survival_check_level_up(self._player, self._state.perk_selection)

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

    def _build_input(self) -> PlayerInput:
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
        aim_x, aim_y = self._camera_screen_to_world(float(mouse.x), float(mouse.y))

        fire_down = input_code_is_down(fire_key)
        fire_pressed = input_code_is_pressed(fire_key)
        reload_key = 0x102
        if self._config is not None:
            reload_key = int(self._config.data.get("keybind_reload", reload_key) or reload_key)
        reload_pressed = input_code_is_pressed(reload_key)

        return PlayerInput(
            move_x=move_x,
            move_y=move_y,
            aim_x=aim_x,
            aim_y=aim_y,
            fire_down=fire_down,
            fire_pressed=fire_pressed,
            reload_pressed=reload_pressed,
        )

    def _player_name_default(self) -> str:
        config = self._config
        if config is None:
            return ""
        raw = config.data.get("player_name")
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw).split(b"\x00", 1)[0].decode("latin-1", errors="ignore")
        if isinstance(raw, str):
            return raw
        return ""

    def _enter_game_over(self) -> None:
        if self._game_over_active:
            return
        record = HighScoreRecord.blank()
        record.score_xp = int(self._player.experience)
        record.survival_elapsed_ms = int(self._survival.elapsed_ms)
        record.creature_kill_count = int(self._creatures.kill_count)

        weapon_id = most_used_weapon_id_for_player(self._state, player_index=int(self._player.index), fallback_weapon_id=int(self._player.weapon_id))
        record.most_used_weapon_id = int(weapon_id)
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
        record.shots_fired = fired
        record.shots_hit = hit

        record.game_mode_id = int(self._config.data.get("game_mode", 1)) if self._config is not None else 1
        self._game_over_record = record
        self._game_over_ui.open()
        self._game_over_active = True
        self._perk_menu.close()

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

    def update(self, dt: float) -> None:
        self._update_audio(dt)

        dt_frame, dt_ui_ms = self._tick_frame(dt)
        self._cursor_time += dt_frame
        self._handle_input()
        if self._action == "open_pause_menu":
            return

        if self._game_over_active:
            record = self._game_over_record
            if record is None:
                self._enter_game_over()
                record = self._game_over_record
            if record is not None:
                action = self._game_over_ui.update(
                    dt,
                    record=record,
                    player_name_default=self._player_name_default(),
                    play_sfx=self._world.audio_router.play_sfx,
                    rand=self._state.rng.rand,
                    mouse=self._ui_mouse_pos(),
                )
                if action == "play_again":
                    self.open()
                    return
                if action == "high_scores":
                    self._action = "open_high_scores"
                    return
                if action == "main_menu":
                    self._action = "back_to_menu"
                    self.close_requested = True
                    return
            return

        any_alive = any(player.health > 0.0 for player in self._world.players)
        perk_pending = int(self._state.perk_selection.pending_count) > 0 and any_alive

        self._perk_prompt_hover = False
        perk_ctx = self._perk_menu_context()
        if self._perk_menu.open:
            self._perk_menu.handle_input(perk_ctx, dt_frame=dt_frame, dt_ui_ms=dt_ui_ms)
            dt = 0.0

        perk_menu_active = self._perk_menu.active

        if (not perk_menu_active) and perk_pending and (not self._paused):
            label = self._perk_prompt_label()
            if label:
                rect = self._perk_prompt_rect(label)
                mouse = self._ui_mouse_pos()
                self._perk_prompt_hover = rl.check_collision_point_rec(mouse, rect)

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

        if not self._paused and not self._game_over_active:
            pulse_delta = dt_ui_ms * (6.0 if self._perk_prompt_hover else -2.0)
            self._perk_prompt_pulse = clamp(self._perk_prompt_pulse + pulse_delta, 0.0, 1000.0)

        if self._paused or (not any_alive) or perk_menu_active:
            dt = 0.0

        prompt_active = perk_pending and (not perk_menu_active) and (not self._paused)
        if prompt_active:
            self._perk_prompt_timer_ms = clamp(self._perk_prompt_timer_ms + dt_ui_ms, 0.0, PERK_PROMPT_MAX_TIMER_MS)
        else:
            self._perk_prompt_timer_ms = clamp(self._perk_prompt_timer_ms - dt_ui_ms, 0.0, PERK_PROMPT_MAX_TIMER_MS)

        self._perk_menu.tick_timeline(dt_ui_ms)
        if self._perk_menu.active:
            self._hud_fade_ms = 0.0
        else:
            self._hud_fade_ms = clamp(self._hud_fade_ms + dt_ui_ms, 0.0, PERK_MENU_TRANSITION_MS)

        self._survival.elapsed_ms += dt * 1000.0

        if dt <= 0.0:
            if not any_alive:
                self._enter_game_over()
            return

        input_state = self._build_input()
        self._world.update(
            dt,
            inputs=[input_state for _ in self._world.players],
            auto_pick_perks=False,
            game_mode=int(GameMode.SURVIVAL),
            perk_progression_enabled=True,
        )

        # Scripted milestone spawns based on level.
        stage, milestone_calls = advance_survival_spawn_stage(self._survival.stage, player_level=self._player.level)
        self._survival.stage = stage
        detail_preset = 5
        if self._world.config is not None:
            detail_preset = int(self._world.config.data.get("detail_preset", 5) or 5)
        for call in milestone_calls:
            self._creatures.spawn_template(
                int(call.template_id),
                call.pos,
                float(call.heading),
                self._state.rng,
                rand=self._state.rng.rand,
                state=self._state,
                detail_preset=detail_preset,
            )

        # Regular wave spawns based on elapsed time.
        cooldown, wave_spawns = tick_survival_wave_spawns(
            self._survival.spawn_cooldown,
            dt * 1000.0,
            self._state.rng,
            player_count=len(self._world.players),
            survival_elapsed_ms=self._survival.elapsed_ms,
            player_experience=self._player.experience,
            terrain_width=int(self._world.world_size),
            terrain_height=int(self._world.world_size),
        )
        self._survival.spawn_cooldown = cooldown
        self._creatures.spawn_inits(wave_spawns)

        if not any(player.health > 0.0 for player in self._world.players):
            self._enter_game_over()

    def _draw_perk_prompt(self) -> None:
        if self._game_over_active:
            return
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

    def _draw_game_cursor(self) -> None:
        mouse_x = float(self._ui_mouse_x)
        mouse_y = float(self._ui_mouse_y)
        cursor_tex = self._perk_menu_assets.cursor if self._perk_menu_assets is not None else None
        draw_menu_cursor(
            self._world.particles_texture,
            cursor_tex,
            x=mouse_x,
            y=mouse_y,
            pulse_time=float(self._cursor_pulse_time),
        )

    def _draw_aim_cursor(self) -> None:
        mouse_x = float(self._ui_mouse_x)
        mouse_y = float(self._ui_mouse_y)
        aim_tex = self._perk_menu_assets.aim if self._perk_menu_assets is not None else None
        draw_aim_cursor(self._world.particles_texture, aim_tex, x=mouse_x, y=mouse_y)

    def draw(self) -> None:
        perk_menu_active = self._perk_menu.active
        self._world.draw(draw_aim_indicators=(not self._game_over_active) and (not perk_menu_active))
        self._draw_screen_fade()

        hud_bottom = 0.0
        if (not self._game_over_active) and (not perk_menu_active) and self._hud_assets is not None:
            hud_alpha = clamp(self._hud_fade_ms / PERK_MENU_TRANSITION_MS, 0.0, 1.0)
            hud_flags = hud_flags_for_game_mode(self._config_game_mode_id())
            self._draw_target_health_bar(alpha=hud_alpha)
            hud_bottom = draw_hud_overlay(
                self._hud_assets,
                player=self._player,
                players=self._world.players,
                bonus_hud=self._state.bonus_hud,
                elapsed_ms=self._survival.elapsed_ms,
                score=self._player.experience,
                font=self._small,
                alpha=hud_alpha,
                frame_dt_ms=self._last_dt_ms,
                show_health=hud_flags.show_health,
                show_weapon=hud_flags.show_weapon,
                show_xp=hud_flags.show_xp,
                show_time=hud_flags.show_time,
                show_quest_hud=hud_flags.show_quest_hud,
                small_indicators=self._hud_small_indicators(),
            )

        if debug_enabled() and (not self._game_over_active) and (not perk_menu_active):
            # Minimal debug text.
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            line = float(self._ui_line_height())
            self._draw_ui_text(f"survival: t={self._survival.elapsed_ms/1000.0:6.1f}s  stage={self._survival.stage}", x, y, UI_TEXT_COLOR)
            self._draw_ui_text(f"xp={self._player.experience}  level={self._player.level}  kills={self._creatures.kill_count}", x, y + line, UI_HINT_COLOR)
            god = "on" if self._state.debug_god_mode else "off"
            self._draw_ui_text(f"debug: [/] weapon  F3 perk+1  F2 god={god}  X xp+5000", x, y + line * 2.0, UI_HINT_COLOR, scale=0.9)
            if self._paused:
                self._draw_ui_text("paused (TAB)", x, y + line * 3.0, UI_HINT_COLOR)
            if self._player.health <= 0.0:
                self._draw_ui_text("game over", x, y + line * 3.0, UI_ERROR_COLOR)
        warn_y = float(rl.get_screen_height()) - 28.0
        if self._world.missing_assets:
            warn = "Missing world assets: " + ", ".join(self._world.missing_assets)
            self._draw_ui_text(warn, 24.0, warn_y, UI_ERROR_COLOR, scale=0.8)
            warn_y -= float(self._ui_line_height(scale=0.8)) + 2.0
        if self._hud_missing:
            warn = "Missing HUD assets: " + ", ".join(self._hud_missing)
            self._draw_ui_text(warn, 24.0, warn_y, UI_ERROR_COLOR, scale=0.8)

        self._draw_perk_prompt()
        if not self._game_over_active:
            self._perk_menu.draw(self._perk_menu_context())
        if (not self._game_over_active) and perk_menu_active:
            self._draw_game_cursor()
        if (not self._game_over_active) and (not perk_menu_active):
            self._draw_aim_cursor()

        if self._game_over_active and self._game_over_record is not None:
            self._game_over_ui.draw(
                record=self._game_over_record,
                banner_kind=self._game_over_banner,
                hud_assets=self._hud_assets,
                mouse=self._ui_mouse_pos(),
            )
