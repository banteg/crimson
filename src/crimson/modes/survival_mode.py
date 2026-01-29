from __future__ import annotations

from dataclasses import dataclass
import random

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.view import ViewContext

from ..creatures.spawn import advance_survival_spawn_stage, tick_survival_wave_spawns
from ..debug import debug_enabled
from ..game_modes import GameMode
from ..gameplay import PlayerInput, perk_selection_current_choices, perk_selection_pick, survival_check_level_up
from ..persistence.highscores import HighScoreRecord
from ..perks import PERK_BY_ID, PerkId
from ..ui.cursor import draw_aim_cursor, draw_menu_cursor
from ..ui.hud import draw_hud_overlay
from ..ui.perk_menu import (
    PerkMenuLayout,
    UiButtonState,
    button_draw,
    button_update,
    button_width,
    draw_menu_panel,
    draw_menu_item,
    draw_ui_text,
    load_perk_menu_assets,
    menu_item_hit_rect,
    perk_menu_compute_layout,
    ui_origin,
    ui_scale,
    wrap_ui_text,
)
from .base_gameplay_mode import BaseGameplayMode, _clamp

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

PERK_MENU_TRANSITION_MS = 500.0


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
            audio=audio,
            audio_rng=audio_rng,
        )
        self._survival = _SurvivalState()

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_prompt_pulse = 0.0
        self._perk_menu_open = False
        self._perk_menu_selected = 0
        self._perk_menu_timeline_ms = 0.0
        self._hud_fade_ms = PERK_MENU_TRANSITION_MS
        self._perk_menu_assets = None
        self._perk_ui_layout = PerkMenuLayout()
        self._perk_cancel_button = UiButtonState("Cancel")
        self._cursor_time = 0.0

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
        self._perk_ui_layout = PerkMenuLayout()
        self._perk_cancel_button = UiButtonState("Cancel")
        self._cursor_time = 0.0
        self._cursor_pulse_time = 0.0
        self._survival = _SurvivalState()

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_prompt_pulse = 0.0
        self._perk_menu_open = False
        self._perk_menu_selected = 0
        self._perk_menu_timeline_ms = 0.0
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
        if self._perk_menu_open and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._close_perk_menu()
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if debug_enabled() and rl.is_key_pressed(rl.KeyboardKey.KEY_X):
            self._player.experience += 5000
            survival_check_level_up(self._player, self._state.perk_selection)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True

    def _build_input(self) -> PlayerInput:
        move_x = 0.0
        move_y = 0.0
        if rl.is_key_down(rl.KeyboardKey.KEY_A):
            move_x -= 1.0
        if rl.is_key_down(rl.KeyboardKey.KEY_D):
            move_x += 1.0
        if rl.is_key_down(rl.KeyboardKey.KEY_W):
            move_y -= 1.0
        if rl.is_key_down(rl.KeyboardKey.KEY_S):
            move_y += 1.0

        mouse = self._ui_mouse_pos()
        aim_x, aim_y = self._camera_screen_to_world(float(mouse.x), float(mouse.y))

        fire_down = rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
        fire_pressed = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        reload_pressed = rl.is_key_pressed(rl.KeyboardKey.KEY_R)

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

        # Missing fidelity: we don't track usage/hit stats yet.
        record.most_used_weapon_id = int(self._player.weapon_id) + 1
        record.shots_fired = 0
        record.shots_hit = 0

        record.game_mode_id = int(self._config.data.get("game_mode", 1)) if self._config is not None else 1
        self._game_over_record = record
        self._game_over_ui.open()
        self._game_over_active = True
        self._perk_menu_open = False

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

    def _open_perk_menu(self) -> None:
        choices = perk_selection_current_choices(
            self._state,
            [self._player],
            self._state.perk_selection,
            game_mode=int(GameMode.SURVIVAL),
            player_count=1,
        )
        if not choices:
            self._perk_menu_open = False
            return
        self._perk_menu_open = True
        self._perk_menu_selected = 0

    def _close_perk_menu(self) -> None:
        self._perk_menu_open = False
        if int(self._state.perk_selection.pending_count) > 0:
            # Reset the prompt swing so each pending perk replays the intro.
            self._perk_prompt_timer_ms = 0.0
            self._perk_prompt_hover = False
            self._perk_prompt_pulse = 0.0

    def _perk_menu_handle_input(self, dt_ms: float) -> None:
        if self._perk_menu_assets is None:
            self._close_perk_menu()
            return
        perk_state = self._state.perk_selection
        choices = perk_selection_current_choices(
            self._state,
            [self._player],
            perk_state,
            game_mode=int(GameMode.SURVIVAL),
            player_count=1,
        )
        if not choices:
            self._close_perk_menu()
            return
        if self._perk_menu_selected >= len(choices):
            self._perk_menu_selected = 0

        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._perk_menu_selected = (self._perk_menu_selected + 1) % len(choices)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._perk_menu_selected = (self._perk_menu_selected - 1) % len(choices)

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        origin_x, origin_y = ui_origin(screen_w, screen_h, scale)
        menu_t = _clamp(self._perk_menu_timeline_ms / PERK_MENU_TRANSITION_MS, 0.0, 1.0)
        slide_x = (menu_t - 1.0) * (self._perk_ui_layout.panel_w * scale)

        mouse = self._ui_mouse_pos()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        master_owned = int(self._player.perk_counts[int(PerkId.PERK_MASTER)]) > 0
        expert_owned = int(self._player.perk_counts[int(PerkId.PERK_EXPERT)]) > 0
        computed = perk_menu_compute_layout(
            self._perk_ui_layout,
            screen_w=screen_w,
            origin_x=origin_x + slide_x,
            origin_y=origin_y,
            scale=scale,
            choice_count=len(choices),
            expert_owned=expert_owned,
            master_owned=master_owned,
        )

        for idx, perk_id in enumerate(choices):
            meta = PERK_BY_ID.get(int(perk_id))
            label = meta.name if meta is not None else f"Perk {int(perk_id)}"
            item_x = computed.list_x
            item_y = computed.list_y + float(idx) * computed.list_step_y
            rect = menu_item_hit_rect(self._small, label, x=item_x, y=item_y, scale=scale)
            if rl.check_collision_point_rec(mouse, rect):
                self._perk_menu_selected = idx
                if click:
                    perk_selection_pick(
                        self._state,
                        [self._player],
                        perk_state,
                        idx,
                        game_mode=int(GameMode.SURVIVAL),
                        player_count=1,
                    )
                    self._close_perk_menu()
                    return
                break

        cancel_w = button_width(self._small, self._perk_cancel_button.label, scale=scale, force_wide=self._perk_cancel_button.force_wide)
        cancel_x = computed.cancel_x
        button_y = computed.cancel_y

        if button_update(
            self._perk_cancel_button,
            x=cancel_x,
            y=button_y,
            width=cancel_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._close_perk_menu()
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) or rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            perk_selection_pick(
                self._state,
                [self._player],
                perk_state,
                self._perk_menu_selected,
                game_mode=int(GameMode.SURVIVAL),
                player_count=1,
            )
            self._close_perk_menu()

    def update(self, dt: float) -> None:
        self._update_audio(dt)

        dt_frame = float(dt)
        dt_ui_ms = float(min(dt_frame, 0.1) * 1000.0)
        self._update_ui_mouse()
        self._cursor_time += dt_frame
        self._cursor_pulse_time += dt_frame * 1.1
        self._handle_input()

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

        perk_pending = int(self._state.perk_selection.pending_count) > 0 and self._player.health > 0.0

        self._perk_prompt_hover = False
        if self._perk_menu_open:
            self._perk_menu_handle_input(dt_ui_ms)
            dt = 0.0

        perk_menu_active = self._perk_menu_open or self._perk_menu_timeline_ms > 1e-3

        if (not perk_menu_active) and perk_pending:
            label = self._perk_prompt_label()
            if label:
                rect = self._perk_prompt_rect(label)
                mouse = self._ui_mouse_pos()
                self._perk_prompt_hover = rl.check_collision_point_rec(mouse, rect)
            if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_RIGHT) and (
                not rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT)
            ):
                self._perk_prompt_pulse = 1000.0
                self._open_perk_menu()
            elif self._perk_prompt_hover and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
                self._perk_prompt_pulse = 1000.0
                self._open_perk_menu()

        if not self._paused and not self._game_over_active:
            pulse_delta = dt_ui_ms * (6.0 if self._perk_prompt_hover else -2.0)
            self._perk_prompt_pulse = _clamp(self._perk_prompt_pulse + pulse_delta, 0.0, 1000.0)

        if self._paused or self._player.health <= 0.0 or perk_menu_active:
            dt = 0.0

        prompt_active = perk_pending and (not perk_menu_active) and (not self._paused)
        if prompt_active:
            self._perk_prompt_timer_ms = _clamp(self._perk_prompt_timer_ms + dt_ui_ms, 0.0, PERK_PROMPT_MAX_TIMER_MS)
        else:
            self._perk_prompt_timer_ms = _clamp(self._perk_prompt_timer_ms - dt_ui_ms, 0.0, PERK_PROMPT_MAX_TIMER_MS)

        if self._perk_menu_open:
            self._perk_menu_timeline_ms = _clamp(self._perk_menu_timeline_ms + dt_ui_ms, 0.0, PERK_MENU_TRANSITION_MS)
        else:
            self._perk_menu_timeline_ms = _clamp(self._perk_menu_timeline_ms - dt_ui_ms, 0.0, PERK_MENU_TRANSITION_MS)
        if self._perk_menu_timeline_ms > 1e-3 or self._perk_menu_open:
            self._hud_fade_ms = 0.0
        else:
            self._hud_fade_ms = _clamp(self._hud_fade_ms + dt_ui_ms, 0.0, PERK_MENU_TRANSITION_MS)

        self._survival.elapsed_ms += dt * 1000.0

        if dt <= 0.0:
            if self._player.health <= 0.0:
                self._enter_game_over()
            return

        input_state = self._build_input()
        self._world.update(
            dt,
            inputs=[input_state],
            auto_pick_perks=False,
            game_mode=int(GameMode.SURVIVAL),
            perk_progression_enabled=True,
        )

        # Scripted milestone spawns based on level.
        stage, milestone_calls = advance_survival_spawn_stage(self._survival.stage, player_level=self._player.level)
        self._survival.stage = stage
        for call in milestone_calls:
            self._creatures.spawn_template(
                int(call.template_id),
                call.pos,
                float(call.heading),
                self._state.rng,
                rand=self._state.rng.rand,
            )

        # Regular wave spawns based on elapsed time.
        cooldown, wave_spawns = tick_survival_wave_spawns(
            self._survival.spawn_cooldown,
            dt * 1000.0,
            self._state.rng,
            player_count=1,
            survival_elapsed_ms=self._survival.elapsed_ms,
            player_experience=self._player.experience,
            terrain_width=int(self._world.world_size),
            terrain_height=int(self._world.world_size),
        )
        self._survival.spawn_cooldown = cooldown
        self._creatures.spawn_inits(wave_spawns)

        if self._player.health <= 0.0:
            self._enter_game_over()

    def _draw_perk_prompt(self) -> None:
        if self._game_over_active:
            return
        if self._perk_menu_open or self._perk_menu_timeline_ms > 1e-3:
            return
        if self._player.health <= 0.0:
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

    def _draw_perk_menu(self) -> None:
        if self._game_over_active:
            return
        menu_t = _clamp(self._perk_menu_timeline_ms / PERK_MENU_TRANSITION_MS, 0.0, 1.0)
        if menu_t <= 1e-3:
            return
        if self._perk_menu_assets is None:
            return

        perk_state = self._state.perk_selection
        choices = perk_selection_current_choices(
            self._state,
            [self._player],
            perk_state,
            game_mode=int(GameMode.SURVIVAL),
            player_count=1,
        )
        if not choices:
            return
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        origin_x, origin_y = ui_origin(screen_w, screen_h, scale)
        slide_x = (menu_t - 1.0) * (self._perk_ui_layout.panel_w * scale)

        master_owned = int(self._player.perk_counts[int(PerkId.PERK_MASTER)]) > 0
        expert_owned = int(self._player.perk_counts[int(PerkId.PERK_EXPERT)]) > 0
        computed = perk_menu_compute_layout(
            self._perk_ui_layout,
            screen_w=screen_w,
            origin_x=origin_x + slide_x,
            origin_y=origin_y,
            scale=scale,
            choice_count=len(choices),
            expert_owned=expert_owned,
            master_owned=master_owned,
        )

        panel_tex = self._perk_menu_assets.menu_panel
        if panel_tex is not None:
            draw_menu_panel(panel_tex, dst=computed.panel)

        title_tex = self._perk_menu_assets.title_pick_perk
        if title_tex is not None:
            src = rl.Rectangle(0.0, 0.0, float(title_tex.width), float(title_tex.height))
            rl.draw_texture_pro(title_tex, src, computed.title, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        sponsor = None
        if master_owned:
            sponsor = "extra perks sponsored by the Perk Master"
        elif expert_owned:
            sponsor = "extra perk sponsored by the Perk Expert"
        if sponsor:
            draw_ui_text(
                self._small,
                sponsor,
                computed.sponsor_x,
                computed.sponsor_y,
                scale=scale,
                color=UI_SPONSOR_COLOR,
            )

        mouse = self._ui_mouse_pos()
        for idx, perk_id in enumerate(choices):
            meta = PERK_BY_ID.get(int(perk_id))
            label = meta.name if meta is not None else f"Perk {int(perk_id)}"
            item_x = computed.list_x
            item_y = computed.list_y + float(idx) * computed.list_step_y
            rect = menu_item_hit_rect(self._small, label, x=item_x, y=item_y, scale=scale)
            hovered = rl.check_collision_point_rec(mouse, rect) or (idx == self._perk_menu_selected)
            draw_menu_item(self._small, label, x=item_x, y=item_y, scale=scale, hovered=hovered)

        selected = choices[self._perk_menu_selected]
        meta = PERK_BY_ID.get(int(selected))
        desc = meta.description if meta is not None else "Unknown perk."
        desc_x = float(computed.desc.x)
        desc_y = float(computed.desc.y)
        desc_w = float(computed.desc.width)
        desc_h = float(computed.desc.height)
        desc_scale = scale * 0.85
        desc_lines = wrap_ui_text(self._small, desc, max_width=desc_w, scale=desc_scale)
        line_h = float(self._small.cell_size * desc_scale) if self._small is not None else float(20 * desc_scale)
        y = desc_y
        for line in desc_lines:
            if y + line_h > desc_y + desc_h:
                break
            draw_ui_text(self._small, line, desc_x, y, scale=desc_scale, color=UI_TEXT_COLOR)
            y += line_h

        cancel_w = button_width(self._small, self._perk_cancel_button.label, scale=scale, force_wide=self._perk_cancel_button.force_wide)
        cancel_x = computed.cancel_x
        button_y = computed.cancel_y
        button_draw(self._perk_menu_assets, self._small, self._perk_cancel_button, x=cancel_x, y=button_y, width=cancel_w, scale=scale)

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
        perk_menu_active = self._perk_menu_open or self._perk_menu_timeline_ms > 1e-3
        self._world.draw(draw_aim_indicators=(not self._game_over_active) and (not perk_menu_active))
        self._draw_screen_fade()

        hud_bottom = 0.0
        if (not self._game_over_active) and (not perk_menu_active) and self._hud_assets is not None:
            hud_alpha = _clamp(self._hud_fade_ms / PERK_MENU_TRANSITION_MS, 0.0, 1.0)
            hud_bottom = draw_hud_overlay(
                self._hud_assets,
                player=self._player,
                bonus_hud=self._state.bonus_hud,
                elapsed_ms=self._survival.elapsed_ms,
                score=self._player.experience,
                font=self._small,
                alpha=hud_alpha,
            )

        if (not self._game_over_active) and (not perk_menu_active):
            # Minimal debug text.
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            line = float(self._ui_line_height())
            self._draw_ui_text(f"survival: t={self._survival.elapsed_ms/1000.0:6.1f}s  stage={self._survival.stage}", x, y, UI_TEXT_COLOR)
            self._draw_ui_text(f"xp={self._player.experience}  level={self._player.level}  kills={self._creatures.kill_count}", x, y + line, UI_HINT_COLOR)
            if self._paused:
                self._draw_ui_text("paused (TAB)", x, y + line * 2.0, UI_HINT_COLOR)
            if self._player.health <= 0.0:
                self._draw_ui_text("game over", x, y + line * 2.0, UI_ERROR_COLOR)
        warn_y = float(rl.get_screen_height()) - 28.0
        if self._world.missing_assets:
            warn = "Missing world assets: " + ", ".join(self._world.missing_assets)
            self._draw_ui_text(warn, 24.0, warn_y, UI_ERROR_COLOR, scale=0.8)
            warn_y -= float(self._ui_line_height(scale=0.8)) + 2.0
        if self._hud_missing:
            warn = "Missing HUD assets: " + ", ".join(self._hud_missing)
            self._draw_ui_text(warn, 24.0, warn_y, UI_ERROR_COLOR, scale=0.8)

        self._draw_perk_prompt()
        self._draw_perk_menu()
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
