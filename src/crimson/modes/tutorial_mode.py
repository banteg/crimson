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

from ..creatures.runtime import CreatureFlags
from ..game_modes import GameMode
from ..gameplay import PlayerInput, survival_check_level_up, weapon_assign_player
from ..input_codes import config_keybinds, input_code_is_down, input_code_is_pressed, player_move_fire_binds
from ..tutorial.timeline import TutorialFrameActions, TutorialState, tick_tutorial_timeline
from ..ui.cursor import draw_aim_cursor, draw_menu_cursor
from ..ui.hud import draw_hud_overlay, hud_flags_for_game_mode
from ..ui.perk_menu import (
    PerkMenuAssets,
    UiButtonState,
    button_draw,
    button_update,
    button_width,
    load_perk_menu_assets,
)
from .base_gameplay_mode import BaseGameplayMode
from .components.perk_menu_controller import PerkMenuContext, PerkMenuController


UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))


@dataclass(slots=True)
class _TutorialUiLayout:
    panel_y: float = 64.0
    panel_pad_x: float = 20.0
    panel_pad_y: float = 8.0


class TutorialMode(BaseGameplayMode):
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
            world_size=1024.0,
            default_game_mode_id=int(GameMode.TUTORIAL),
            demo_mode_active=bool(demo_mode_active),
            difficulty_level=0,
            hardcore=False,
            texture_cache=texture_cache,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._tutorial = TutorialState()
        self._tutorial_actions = TutorialFrameActions()

        self._ui_assets: PerkMenuAssets | None = None
        self._ui_layout = _TutorialUiLayout()

        self._perk_menu = PerkMenuController()

        self._skip_button = UiButtonState("Skip tutorial", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._repeat_button = UiButtonState("Repeat tutorial", force_wide=True)

    def open(self) -> None:
        super().open()
        self._ui_assets = load_perk_menu_assets(self._assets_root)
        if self._ui_assets.missing:
            self._missing_assets.extend(self._ui_assets.missing)

        self._perk_menu.reset()

        self._skip_button = UiButtonState("Skip tutorial", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._repeat_button = UiButtonState("Repeat tutorial", force_wide=True)

        self._tutorial = TutorialState()
        self._tutorial_actions = TutorialFrameActions()

        self._state.perk_selection.pending_count = 0
        self._state.perk_selection.choices.clear()
        self._state.perk_selection.choices_dirty = True

        self._player.pos_x = float(self._world.world_size) * 0.5
        self._player.pos_y = float(self._world.world_size) * 0.5
        weapon_assign_player(self._player, 1)

    def close(self) -> None:
        self._ui_assets = None
        super().close()

    def _perk_menu_context(self) -> PerkMenuContext:
        fx_toggle = int(self._config.data.get("fx_toggle", 0) or 0) if self._config is not None else 0
        fx_detail = bool(int(self._config.data.get("fx_detail_0", 0) or 0)) if self._config is not None else False
        return PerkMenuContext(
            state=self._state,
            perk_state=self._state.perk_selection,
            players=[self._player],
            creatures=self._creatures.entries,
            player=self._player,
            game_mode=int(GameMode.TUTORIAL),
            player_count=1,
            fx_toggle=fx_toggle,
            fx_detail=fx_detail,
            font=self._small,
            assets=self._ui_assets,
            mouse=self._ui_mouse_pos(),
            play_sfx=None,
        )

    def _handle_input(self) -> None:
        if self._perk_menu.open and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._perk_menu.close()
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._action = "open_pause_menu"
            return

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
        aim_x, aim_y = self._world.screen_to_world(float(mouse.x), float(mouse.y))

        fire_down = input_code_is_down(fire_key)
        fire_pressed = input_code_is_pressed(fire_key)
        reload_key = 0x102
        if self._config is not None:
            reload_key = int(self._config.data.get("keybind_reload", reload_key) or reload_key)
        reload_pressed = input_code_is_pressed(reload_key)

        return PlayerInput(
            move_x=move_x,
            move_y=move_y,
            aim_x=float(aim_x),
            aim_y=float(aim_y),
            fire_down=bool(fire_down),
            fire_pressed=bool(fire_pressed),
            reload_pressed=bool(reload_pressed),
        )

    def _prompt_panel_rect(self, text: str, *, y: float, scale: float) -> tuple[rl.Rectangle, list[str], float]:
        lines = text.splitlines() if text else [""]
        line_h = float(self._ui_line_height(scale))
        max_w = 0.0
        for line in lines:
            max_w = max(max_w, float(self._ui_text_width(line, scale)))

        pad_x = self._ui_layout.panel_pad_x * scale
        pad_y = self._ui_layout.panel_pad_y * scale
        w = max_w + pad_x * 2.0
        h = float(len(lines)) * line_h + pad_y * 2.0

        screen_w = float(rl.get_screen_width())
        x = (screen_w - w) * 0.5
        rect = rl.Rectangle(float(x), float(y), float(w), float(h))
        return rect, lines, line_h

    def _update_prompt_buttons(self, *, dt_ms: float, mouse: rl.Vector2, click: bool) -> None:
        if self._ui_assets is None:
            return

        stage = int(self._tutorial.stage_index)
        prompt_alpha = float(self._tutorial_actions.prompt_alpha)
        if stage == 8:
            self._play_button.alpha = prompt_alpha
            self._repeat_button.alpha = prompt_alpha
            self._play_button.enabled = prompt_alpha > 1e-3
            self._repeat_button.enabled = prompt_alpha > 1e-3
        else:
            skip_alpha = clamp(float(self._tutorial.stage_timer_ms - 1000) * 0.001, 0.0, 1.0)
            self._skip_button.alpha = skip_alpha
            self._skip_button.enabled = skip_alpha > 1e-3

        if stage == 8:
            rect, _lines, _line_h = self._prompt_panel_rect(self._tutorial_actions.prompt_text, y=self._ui_layout.panel_y, scale=1.0)
            gap = 18.0
            button_y = rect.y + rect.height + 10.0
            play_w = button_width(self._small, self._play_button.label, scale=1.0, force_wide=True)
            repeat_w = button_width(self._small, self._repeat_button.label, scale=1.0, force_wide=True)
            play_x = rect.x + 10.0
            repeat_x = play_x + play_w + gap
            if button_update(self._play_button, x=play_x, y=button_y, width=play_w, dt_ms=dt_ms, mouse=mouse, click=click):
                self.close_requested = True
                return
            if button_update(self._repeat_button, x=repeat_x, y=button_y, width=repeat_w, dt_ms=dt_ms, mouse=mouse, click=click):
                self.open()
                return
            return

        if self._skip_button.enabled:
            y = float(rl.get_screen_height()) - 50.0
            w = button_width(self._small, self._skip_button.label, scale=1.0, force_wide=True)
            if button_update(self._skip_button, x=10.0, y=y, width=w, dt_ms=dt_ms, mouse=mouse, click=click):
                self.close_requested = True

    def update(self, dt: float) -> None:
        self._update_audio(dt)
        dt_frame, dt_ui_ms = self._tick_frame(dt, clamp_cursor_pulse=True)

        self._handle_input()
        if self._action == "open_pause_menu":
            return
        if self.close_requested:
            return

        perk_ctx = self._perk_menu_context()
        perk_pending = int(self._state.perk_selection.pending_count) > 0 and self._player.health > 0.0
        if int(self._tutorial.stage_index) == 6 and perk_pending and not self._perk_menu.open:
            self._perk_menu.open_if_available(perk_ctx)

        perk_menu_active = self._perk_menu.active
        if self._perk_menu.open:
            self._perk_menu.handle_input(perk_ctx, dt_frame=dt_frame, dt_ui_ms=dt_ui_ms)
        self._perk_menu.tick_timeline(dt_ui_ms)

        dt_world = 0.0 if self._paused or perk_menu_active else dt_frame

        input_state = self._build_input()
        any_move_active = bool(input_state.move_x or input_state.move_y)
        any_fire_active = bool(input_state.fire_pressed or input_state.fire_down)

        hint_alive_before = False
        hint_ref = self._tutorial.hint_bonus_creature_ref
        if hint_ref is not None and 0 <= int(hint_ref) < len(self._creatures.entries):
            entry = self._creatures.entries[int(hint_ref)]
            hint_alive_before = bool(entry.active and entry.hp > 0.0)

        if dt_world > 0.0:
            self._world.update(
                dt_world,
                inputs=[input_state],
                auto_pick_perks=False,
                game_mode=int(GameMode.TUTORIAL),
                perk_progression_enabled=True,
            )

        hint_alive_after = hint_alive_before
        if hint_ref is not None and 0 <= int(hint_ref) < len(self._creatures.entries):
            entry = self._creatures.entries[int(hint_ref)]
            hint_alive_after = bool(entry.active and entry.hp > 0.0)
        hint_bonus_died = hint_alive_before and (not hint_alive_after)

        creatures_none_active = not bool(self._creatures.iter_active())
        bonus_pool_empty = not bool(self._state.bonus_pool.iter_active())
        perk_pending_count = int(self._state.perk_selection.pending_count)

        self._tutorial, actions = tick_tutorial_timeline(
            self._tutorial,
            frame_dt_ms=dt_world * 1000.0,
            any_move_active=any_move_active,
            any_fire_active=any_fire_active,
            creatures_none_active=creatures_none_active,
            bonus_pool_empty=bonus_pool_empty,
            perk_pending_count=perk_pending_count,
            hint_bonus_died=hint_bonus_died,
        )
        self._tutorial_actions = actions

        self._player.health = float(actions.force_player_health)
        if actions.force_player_experience is not None:
            self._player.experience = int(actions.force_player_experience)
            survival_check_level_up(self._player, self._state.perk_selection)

        detail_preset = 5
        if self._world.config is not None:
            detail_preset = int(self._world.config.data.get("detail_preset", 5) or 5)

        for call in actions.spawn_bonuses:
            spawned = self._state.bonus_pool.spawn_at(
                float(call.pos[0]),
                float(call.pos[1]),
                int(call.bonus_id),
                int(call.amount),
                world_width=float(self._world.world_size),
                world_height=float(self._world.world_size),
            )
            if spawned is not None:
                self._state.effects.spawn_burst(
                    pos_x=float(spawned.pos_x),
                    pos_y=float(spawned.pos_y),
                    count=12,
                    rand=self._state.rng.rand,
                    detail_preset=detail_preset,
                )

        for call in actions.spawn_templates:
            mapping, primary = self._creatures.spawn_template(
                int(call.template_id),
                call.pos,
                float(call.heading),
                self._state.rng,
                rand=self._state.rng.rand,
            )
            if int(call.template_id) == 0x27 and primary is not None and actions.stage5_bonus_carrier_drop is not None:
                drop_id, drop_amount = actions.stage5_bonus_carrier_drop
                self._tutorial.hint_bonus_creature_ref = int(primary)
                if 0 <= int(primary) < len(self._creatures.entries):
                    creature = self._creatures.entries[int(primary)]
                    creature.flags |= CreatureFlags.BONUS_ON_DEATH
                    creature.bonus_id = int(drop_id)
                    creature.bonus_duration_override = int(drop_amount)

        mouse = self._ui_mouse_pos()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        self._update_prompt_buttons(dt_ms=dt_ui_ms, mouse=mouse, click=click)

    def draw(self) -> None:
        perk_menu_active = self._perk_menu.active
        self._world.draw(draw_aim_indicators=not perk_menu_active)
        self._draw_screen_fade()

        hud_bottom = 0.0
        if (not perk_menu_active) and self._hud_assets is not None:
            hud_flags = hud_flags_for_game_mode(self._config_game_mode_id())
            self._draw_target_health_bar()
            hud_bottom = draw_hud_overlay(
                self._hud_assets,
                state=self._hud_state,
                player=self._player,
                players=self._world.players,
                bonus_hud=self._state.bonus_hud,
                elapsed_ms=float(self._tutorial.stage_timer_ms),
                score=int(self._player.experience),
                font=self._small,
                alpha=1.0,
                frame_dt_ms=self._last_dt_ms,
                show_health=hud_flags.show_health,
                show_weapon=hud_flags.show_weapon,
                show_xp=hud_flags.show_xp,
                show_time=hud_flags.show_time,
                show_quest_hud=hud_flags.show_quest_hud,
                small_indicators=self._hud_small_indicators(),
            )

        self._draw_tutorial_prompts(hud_bottom=hud_bottom)

        warn_y = float(rl.get_screen_height()) - 28.0
        if self._world.missing_assets:
            warn = "Missing world assets: " + ", ".join(self._world.missing_assets)
            self._draw_ui_text(warn, 24.0, warn_y, UI_ERROR_COLOR, scale=0.8)
            warn_y -= float(self._ui_line_height(scale=0.8)) + 2.0
        if self._hud_missing:
            warn = "Missing HUD assets: " + ", ".join(self._hud_missing)
            self._draw_ui_text(warn, 24.0, warn_y, UI_ERROR_COLOR, scale=0.8)

        if perk_menu_active:
            self._perk_menu.draw(self._perk_menu_context())
            self._draw_menu_cursor()
        else:
            self._draw_aim_cursor()

    def _draw_tutorial_prompts(self, *, hud_bottom: float) -> None:
        actions = self._tutorial_actions
        if actions.prompt_text and actions.prompt_alpha > 1e-3:
            self._draw_prompt_panel(actions.prompt_text, alpha=float(actions.prompt_alpha), y=self._ui_layout.panel_y)
        if actions.hint_text and actions.hint_alpha > 1e-3:
            y = self._ui_layout.panel_y + 84.0
            self._draw_prompt_panel(actions.hint_text, alpha=float(actions.hint_alpha), y=y)

        if self._ui_assets is None:
            return

        stage = int(self._tutorial.stage_index)
        if stage == 8:
            rect, _lines, _line_h = self._prompt_panel_rect(actions.prompt_text, y=self._ui_layout.panel_y, scale=1.0)
            gap = 18.0
            button_y = rect.y + rect.height + 10.0
            play_w = button_width(self._small, self._play_button.label, scale=1.0, force_wide=True)
            repeat_w = button_width(self._small, self._repeat_button.label, scale=1.0, force_wide=True)
            play_x = rect.x + 10.0
            repeat_x = play_x + play_w + gap
            button_draw(self._ui_assets, self._small, self._play_button, x=play_x, y=button_y, width=play_w, scale=1.0)
            button_draw(self._ui_assets, self._small, self._repeat_button, x=repeat_x, y=button_y, width=repeat_w, scale=1.0)
            return

        if self._skip_button.alpha > 1e-3:
            y = float(rl.get_screen_height()) - 50.0
            w = button_width(self._small, self._skip_button.label, scale=1.0, force_wide=True)
            button_draw(self._ui_assets, self._small, self._skip_button, x=10.0, y=y, width=w, scale=1.0)

        if self._paused:
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            self._draw_ui_text("paused (TAB)", x, y, UI_HINT_COLOR)

    def _draw_prompt_panel(self, text: str, *, alpha: float, y: float) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        rect, lines, line_h = self._prompt_panel_rect(text, y=float(y), scale=1.0)
        fill = rl.Color(0, 0, 0, int(255 * alpha * 0.8))
        border = rl.Color(255, 255, 255, int(255 * alpha))
        rl.draw_rectangle(int(rect.x), int(rect.y), int(rect.width), int(rect.height), fill)
        rl.draw_rectangle_lines(int(rect.x), int(rect.y), int(rect.width), int(rect.height), border)

        text_alpha = int(255 * clamp(alpha * 0.9, 0.0, 1.0))
        color = rl.Color(255, 255, 255, text_alpha)
        x = float(rect.x + self._ui_layout.panel_pad_x)
        line_y = float(rect.y + self._ui_layout.panel_pad_y)
        for line in lines:
            self._draw_ui_text(line, x, line_y, color, scale=1.0)
            line_y += line_h

    def _draw_menu_cursor(self) -> None:
        assets = self._ui_assets
        if assets is None:
            return
        cursor_tex = assets.cursor
        draw_menu_cursor(
            self._world.particles_texture,
            cursor_tex,
            x=float(self._ui_mouse_x),
            y=float(self._ui_mouse_y),
            pulse_time=float(self._cursor_pulse_time),
        )

    def _draw_aim_cursor(self) -> None:
        assets = self._ui_assets
        if assets is None:
            return
        aim_tex = assets.aim
        draw_aim_cursor(
            self._world.particles_texture,
            aim_tex,
            x=float(self._ui_mouse_x),
            y=float(self._ui_mouse_y),
        )
