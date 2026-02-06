from __future__ import annotations

from dataclasses import dataclass
import math
import random

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.console import ConsoleState
from grim.config import CrimsonConfig
from grim.view import ViewContext

from ..creatures.spawn import CreatureFlags, CreatureInit, CreatureTypeId
from ..game_modes import GameMode
from ..typo.player import build_typo_player_input, enforce_typo_player_frame
from ..typo.names import CreatureNameTable, load_typo_dictionary
from ..typo.spawns import tick_typo_spawns
from ..typo.typing import TypingBuffer
from ..ui.cursor import draw_aim_cursor, draw_menu_cursor
from ..ui.hud import draw_hud_overlay, hud_flags_for_game_mode
from ..ui.perk_menu import load_perk_menu_assets
from .base_gameplay_mode import BaseGameplayMode
from .components.highscore_record_builder import build_highscore_record_for_game_over

WORLD_SIZE = 1024.0

UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)

NAME_LABEL_SCALE = 1.0
NAME_LABEL_BG_ALPHA = 0.67

# Original typoshooter input box constants (from 0x004457C0)
TYPING_PANEL_WIDTH = 182.0
TYPING_PANEL_HEIGHT = 53.0
TYPING_PANEL_ALPHA = 0.7
TYPING_TEXT_X = 6.0
TYPING_PROMPT = ">"
TYPING_CURSOR = "_"
TYPING_CURSOR_X_OFFSET = 14.0


@dataclass(slots=True)
class _TypoState:
    elapsed_ms: int = 0
    spawn_cooldown_ms: int = 0


class TypoShooterMode(BaseGameplayMode):
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
            default_game_mode_id=int(GameMode.TYPO),
            demo_mode_active=False,
            difficulty_level=0,
            hardcore=False,
            texture_cache=texture_cache,
            config=config,
            console=console,
            audio=audio,
            audio_rng=audio_rng,
        )
        self._typo = _TypoState()
        self._typing = TypingBuffer()
        self._names = CreatureNameTable.sized(0)
        self._aim_target_x = 0.0
        self._aim_target_y = 0.0
        self._unique_words: list[str] | None = None

        self._ui_assets = None

    def open(self) -> None:
        super().open()
        self._ui_assets = load_perk_menu_assets(self._assets_root)
        if self._ui_assets.missing:
            self._missing_assets.extend(self._ui_assets.missing)
        self._typo = _TypoState()
        self._typing = TypingBuffer()
        self._names = CreatureNameTable.sized(len(self._creatures.entries))
        self._unique_words = None

        dictionary_path = self._base_dir / "typo_dictionary.txt"
        if dictionary_path.is_file():
            words = load_typo_dictionary(dictionary_path)
            if words:
                self._unique_words = words

        self._aim_target_x = float(self._player.pos.x) + 128.0
        self._aim_target_y = float(self._player.pos.y)

        enforce_typo_player_frame(self._player)

    def close(self) -> None:
        if self._ui_assets is not None:
            self._ui_assets = None
        super().close()

    def _handle_input(self) -> None:
        if self._game_over_active:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
                self._action = "back_to_menu"
                self.close_requested = True
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._action = "open_pause_menu"
            return

    def _active_mask(self) -> list[bool]:
        return [bool(entry.active) for entry in self._creatures.entries]

    def _handle_typing_input(self) -> tuple[bool, bool]:
        fire_pressed = False
        reload_pressed = False

        if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
            self._typing.backspace()
            if self._world.audio_router is not None:
                key = "sfx_ui_typeclick_01" if (self._state.rng.rand() & 1) == 0 else "sfx_ui_typeclick_02"
                self._world.audio_router.play_sfx(key)

        codepoint = int(rl.get_char_pressed())
        while codepoint > 0:
            if codepoint not in (13, 8) and 0x20 <= codepoint <= 0xFF:
                try:
                    ch = chr(codepoint)
                except ValueError:
                    ch = ""
                if ch:
                    self._typing.push_char(ch)
                    if self._world.audio_router is not None:
                        key = "sfx_ui_typeclick_01" if (self._state.rng.rand() & 1) == 0 else "sfx_ui_typeclick_02"
                        self._world.audio_router.play_sfx(key)
            codepoint = int(rl.get_char_pressed())

        enter_pressed = rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) or rl.is_key_pressed(rl.KeyboardKey.KEY_KP_ENTER)
        if enter_pressed:
            had_text = bool(self._typing.text)
            active = self._active_mask()

            def _find_target(name: str) -> int | None:
                return self._names.find_by_name(name, active_mask=active)

            result = self._typing.enter(find_target=_find_target)
            if had_text and self._world.audio_router is not None:
                self._world.audio_router.play_sfx("sfx_ui_typeenter")
            if result.fire_requested and result.target_creature_idx is not None:
                target_idx = int(result.target_creature_idx)
                if 0 <= target_idx < len(self._creatures.entries):
                    creature = self._creatures.entries[target_idx]
                    if creature.active:
                        self._aim_target_x = float(creature.x)
                        self._aim_target_y = float(creature.y)
                fire_pressed = True
            if result.reload_requested:
                reload_pressed = True

        return fire_pressed, reload_pressed

    def _spawn_tinted_creature(
        self, *, type_id: CreatureTypeId, pos_x: float, pos_y: float, tint_rgba: tuple[float, float, float, float]
    ) -> int:
        rand = self._state.rng.rand
        heading = float(int(rand()) % 314) * 0.01
        size = float(int(rand()) % 20 + 47)

        flags = CreatureFlags(0)
        move_speed = 1.7
        if int(type_id) in (int(CreatureTypeId.SPIDER_SP1), int(CreatureTypeId.SPIDER_SP2)):
            flags |= CreatureFlags.AI7_LINK_TIMER
            move_speed *= 1.2
            size *= 0.8

        init = CreatureInit(
            origin_template_id=0,
            pos_x=float(pos_x),
            pos_y=float(pos_y),
            heading=float(heading),
            phase_seed=0.0,
            type_id=type_id,
            flags=flags,
            ai_mode=2,
            health=1.0,
            max_health=1.0,
            move_speed=float(move_speed),
            reward_value=1.0,
            size=float(size),
            contact_damage=100.0,
            tint=tint_rgba,
        )
        return self._creatures.spawn_init(init, rand=rand)

    def _enter_game_over(self) -> None:
        if self._game_over_active:
            return

        record = build_highscore_record_for_game_over(
            state=self._state,
            player=self._player,
            survival_elapsed_ms=int(self._typo.elapsed_ms),
            creature_kill_count=int(self._creatures.kill_count),
            game_mode_id=int(GameMode.TYPO),
            shots_fired=int(self._typing.shots_fired),
            shots_hit=int(self._typing.shots_hit),
            clamp_shots_hit=False,
        )

        self._game_over_record = record
        self._game_over_ui.open()
        self._game_over_active = True

    def update(self, dt: float) -> None:
        self._update_audio(dt)

        dt_frame = self._tick_frame(dt)[0]
        self._handle_input()
        if self._action == "open_pause_menu":
            return

        if self._game_over_active:
            self._update_game_over_ui(dt)
            return

        dt_world = 0.0 if self._paused else dt_frame

        # Native: delay game-over transition until the trooper death animation finishes
        # (checks `death_timer < 0.0` in the main gameplay loop).
        if self._player.health <= 0.0:
            if dt_world > 0.0:
                self._player.death_timer -= float(dt_world) * 20.0
            if self._player.death_timer < 0.0:
                self._enter_game_over()
                self._update_game_over_ui(dt)
                return
            return

        fire_pressed = False
        reload_pressed = False
        if dt_world > 0.0:
            fire_pressed, reload_pressed = self._handle_typing_input()

        if dt_world <= 0.0:
            return

        enforce_typo_player_frame(self._player)
        input_state = build_typo_player_input(
            aim_x=float(self._aim_target_x),
            aim_y=float(self._aim_target_y),
            fire_requested=bool(fire_pressed),
            reload_requested=bool(reload_pressed),
        )
        self._world.update(
            dt_world,
            inputs=[input_state],
            auto_pick_perks=False,
            game_mode=int(GameMode.TYPO),
            perk_progression_enabled=False,
        )
        enforce_typo_player_frame(self._player)

        self._state.bonuses.weapon_power_up = 0.0
        self._state.bonuses.reflex_boost = 0.0
        self._state.bonus_pool.reset()

        cooldown, spawns = tick_typo_spawns(
            elapsed_ms=int(self._typo.elapsed_ms),
            spawn_cooldown_ms=int(self._typo.spawn_cooldown_ms),
            frame_dt_ms=int(dt_world * 1000.0),
            player_count=1,
            world_width=float(self._world.world_size),
            world_height=float(self._world.world_size),
        )
        self._typo.spawn_cooldown_ms = int(cooldown)
        for call in spawns:
            creature_idx = self._spawn_tinted_creature(
                type_id=call.type_id,
                pos_x=float(call.pos.x),
                pos_y=float(call.pos.y),
                tint_rgba=call.tint_rgba,
            )
            self._names.assign_random(
                creature_idx,
                self._state.rng,
                score_xp=int(self._player.experience),
                active_mask=self._active_mask(),
                unique_words=self._unique_words,
            )

        self._typo.elapsed_ms += int(dt_world * 1000.0)
        # Death/game-over flow is handled at the start of the next frame so the
        # trooper death animation can play before the UI slides in.

    def _draw_game_cursor(self) -> None:
        mouse_x = float(self._ui_mouse_x)
        mouse_y = float(self._ui_mouse_y)
        cursor_tex = self._ui_assets.cursor if self._ui_assets is not None else None
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
        aim_tex = self._ui_assets.aim if self._ui_assets is not None else None
        draw_aim_cursor(self._world.particles_texture, aim_tex, x=mouse_x, y=mouse_y)

    def _draw_name_labels(self) -> None:
        names = self._names.names
        if not names:
            return

        for idx, creature in enumerate(self._creatures.entries):
            if not creature.active:
                continue
            if not (0 <= idx < len(names)):
                continue
            text = names[idx]
            if not text:
                continue

            label_alpha = 1.0
            hitbox = float(creature.hitbox_size)
            if hitbox < 0.0:
                label_alpha = max(0.0, min(1.0, (hitbox + 10.0) * 0.1))
            if label_alpha <= 1e-3:
                continue

            sx, sy = self._world.world_to_screen(float(creature.x), float(creature.y))
            y = float(sy) - 50.0
            text_w = float(self._ui_text_width(text, scale=NAME_LABEL_SCALE))
            text_h = 15.0
            x = float(sx) - text_w * 0.5

            bg_alpha = label_alpha * NAME_LABEL_BG_ALPHA
            bg = rl.Color(0, 0, 0, int(255 * bg_alpha))
            fg = rl.Color(255, 255, 255, int(255 * label_alpha))
            rl.draw_rectangle_rec(rl.Rectangle(x - 4.0, y, text_w + 8.0, text_h), bg)
            self._draw_ui_text(text, x, y, fg, scale=NAME_LABEL_SCALE)

    def _draw_typing_box(self) -> None:
        screen_h = float(rl.get_screen_height())

        # Original positioning from 0x004457C0:
        # v38 = screen_height - 128.0
        # Panel Y = v38 - 16.0 = screen_height - 144.0
        # Text Y = v38 + 1.0 = screen_height - 127.0
        panel_x = -1.0
        panel_y = screen_h - 144.0  # v38 - 16.0
        text_y = screen_h - 127.0  # v38 + 1.0

        # Draw panel backdrop using ind_panel texture (original: DAT_0048f7c4)
        if self._hud_assets is not None and self._hud_assets.ind_panel is not None:
            tex = self._hud_assets.ind_panel
            src = rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height))
            dst = rl.Rectangle(
                panel_x,
                panel_y,
                TYPING_PANEL_WIDTH,
                TYPING_PANEL_HEIGHT,
            )
            tint = rl.Color(255, 255, 255, int(255 * TYPING_PANEL_ALPHA))
            rl.draw_texture_pro(tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)

        # Draw prompt + typing text
        # Original draws with format string that includes prompt "> "
        text = self._typing.text
        full_text = TYPING_PROMPT + text
        text_color = rl.Color(255, 255, 255, 255)
        self._draw_ui_text(full_text, TYPING_TEXT_X, text_y, text_color, scale=1.0)

        # Draw cursor (original: alpha = sin(game_time_s * 4.0) > 0.0 ? 0.4 : 1.0)
        cursor_dim = math.sin(float(self._cursor_pulse_time) * 4.0) > 0.0
        cursor_alpha = 0.4 if cursor_dim else 1.0
        cursor_color = rl.Color(255, 255, 255, int(255 * cursor_alpha))

        # Cursor position: text_width + 14.0 (original)
        text_w = float(self._ui_text_width(text))
        cursor_x = text_w + TYPING_CURSOR_X_OFFSET
        cursor_y = text_y

        # Draw cursor as "_" character (original: DAT_004712b8 = "_")
        self._draw_ui_text(TYPING_CURSOR, cursor_x, cursor_y, cursor_color, scale=1.0)

    def draw(self) -> None:
        alive = self._player.health > 0.0
        show_gameplay_ui = alive and (not self._game_over_active)

        self._world.draw(draw_aim_indicators=show_gameplay_ui)
        self._draw_screen_fade()

        if show_gameplay_ui:
            self._draw_name_labels()

        if show_gameplay_ui and self._hud_assets is not None:
            hud_flags = hud_flags_for_game_mode(self._config_game_mode_id())
            self._draw_target_health_bar()
            draw_hud_overlay(
                self._hud_assets,
                state=self._hud_state,
                player=self._player,
                players=self._world.players,
                bonus_hud=self._state.bonus_hud,
                elapsed_ms=float(self._typo.elapsed_ms),
                font=self._small,
                frame_dt_ms=self._last_dt_ms,
                show_health=hud_flags.show_health,
                show_weapon=hud_flags.show_weapon,
                show_xp=hud_flags.show_xp,
                show_time=hud_flags.show_time,
                show_quest_hud=hud_flags.show_quest_hud,
                small_indicators=self._hud_small_indicators(),
            )

        if show_gameplay_ui:
            self._draw_typing_box()

        warn_y = float(rl.get_screen_height()) - 28.0
        if self._world.missing_assets:
            warn = "Missing world assets: " + ", ".join(self._world.missing_assets)
            self._draw_ui_text(warn, 24.0, warn_y, UI_ERROR_COLOR, scale=0.8)
            warn_y -= float(self._ui_line_height(scale=0.8)) + 2.0
        if self._hud_missing:
            warn = "Missing HUD assets: " + ", ".join(self._hud_missing)
            self._draw_ui_text(warn, 24.0, warn_y, UI_ERROR_COLOR, scale=0.8)

        if show_gameplay_ui:
            self._draw_aim_cursor()
        elif self._game_over_active:
            self._draw_game_cursor()
            if self._game_over_record is not None:
                self._game_over_ui.draw(
                    record=self._game_over_record,
                    banner_kind=self._game_over_banner,
                    hud_assets=self._hud_assets,
                    mouse=self._ui_mouse_pos(),
                )
