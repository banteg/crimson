from __future__ import annotations

from dataclasses import dataclass
import random

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import AudioState
from grim.config import CrimsonConfig
from grim.view import ViewContext

from ..creatures.spawn import CreatureFlags, CreatureInit, CreatureTypeId
from ..game_modes import GameMode
from ..gameplay import PlayerInput, weapon_assign_player
from ..persistence.highscores import HighScoreRecord
from ..typo.names import CreatureNameTable
from ..typo.spawns import tick_typo_spawns
from ..typo.typing import TypingBuffer
from ..ui.cursor import draw_aim_cursor, draw_menu_cursor
from ..ui.hud import draw_hud_overlay
from ..ui.perk_menu import load_perk_menu_assets
from .base_gameplay_mode import BaseGameplayMode

WORLD_SIZE = 1024.0
TYPO_WEAPON_ID = 3

UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


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
            audio=audio,
            audio_rng=audio_rng,
        )
        self._typo = _TypoState()
        self._typing = TypingBuffer()
        self._names = CreatureNameTable.sized(0)
        self._aim_target_x = 0.0
        self._aim_target_y = 0.0

        self._ui_assets = None

    def open(self) -> None:
        super().open()
        self._ui_assets = load_perk_menu_assets(self._assets_root)
        if self._ui_assets.missing:
            self._missing_assets.extend(self._ui_assets.missing)
        self._typo = _TypoState()
        self._typing = TypingBuffer()
        self._names = CreatureNameTable.sized(len(self._creatures.entries))

        self._aim_target_x = float(self._player.pos_x) + 128.0
        self._aim_target_y = float(self._player.pos_y)

        self._enforce_typo_loadout()

    def close(self) -> None:
        if self._ui_assets is not None:
            self._ui_assets = None
        super().close()

    def _enforce_typo_loadout(self) -> None:
        if int(self._player.weapon_id) != TYPO_WEAPON_ID:
            weapon_assign_player(self._player, TYPO_WEAPON_ID)
        self._player.ammo = max(0, int(self._player.clip_size))

    def _handle_input(self) -> None:
        if self._game_over_active:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
                self.close_requested = True
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True

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
            if codepoint not in (13, 8):
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

    def _spawn_tinted_creature(self, *, type_id: CreatureTypeId, pos_x: float, pos_y: float, tint_rgba: tuple[float, float, float, float]) -> int:
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

        record = HighScoreRecord.blank()
        record.score_xp = int(self._player.experience)
        record.survival_elapsed_ms = int(self._typo.elapsed_ms)
        record.creature_kill_count = int(self._creatures.kill_count)
        record.most_used_weapon_id = int(self._player.weapon_id) + 1
        record.shots_fired = int(self._typing.shots_fired)
        record.shots_hit = int(self._typing.shots_hit)
        record.game_mode_id = int(GameMode.TYPO)

        self._game_over_record = record
        self._game_over_ui.open()
        self._game_over_active = True

    def update(self, dt: float) -> None:
        self._update_audio(dt)

        dt_frame = float(dt)
        dt_ui_ms = float(min(dt_frame, 0.1) * 1000.0)
        self._update_ui_mouse()
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
                if action in {"main_menu", "high_scores"}:
                    self.close_requested = True
            return

        dt_world = 0.0 if self._paused or self._player.health <= 0.0 else dt_frame

        fire_pressed = False
        reload_pressed = False
        if dt_world > 0.0:
            fire_pressed, reload_pressed = self._handle_typing_input()

        if dt_world <= 0.0:
            if self._player.health <= 0.0:
                self._enter_game_over()
            return

        self._enforce_typo_loadout()
        input_state = PlayerInput(
            move_x=0.0,
            move_y=0.0,
            aim_x=float(self._aim_target_x),
            aim_y=float(self._aim_target_y),
            fire_down=False,
            fire_pressed=bool(fire_pressed),
            reload_pressed=bool(reload_pressed),
        )
        self._world.update(
            dt_world,
            inputs=[input_state],
            auto_pick_perks=False,
            game_mode=int(GameMode.TYPO),
            perk_progression_enabled=False,
        )

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
                pos_x=float(call.pos_x),
                pos_y=float(call.pos_y),
                tint_rgba=call.tint_rgba,
            )
            self._names.assign_random(
                creature_idx,
                self._state.rng,
                score_xp=int(self._player.experience),
                active_mask=self._active_mask(),
            )

        self._typo.elapsed_ms += int(dt_world * 1000.0)
        if self._player.health <= 0.0:
            self._enter_game_over()

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

    def draw(self) -> None:
        self._world.draw(draw_aim_indicators=(not self._game_over_active))
        self._draw_screen_fade()

        hud_bottom = 0.0
        if (not self._game_over_active) and self._hud_assets is not None:
            hud_bottom = draw_hud_overlay(
                self._hud_assets,
                player=self._player,
                bonus_hud=self._state.bonus_hud,
                elapsed_ms=float(self._typo.elapsed_ms),
                font=self._small,
                show_weapon=False,
                show_xp=False,
                show_time=True,
            )

        if not self._game_over_active:
            x = 18.0
            y = max(18.0, hud_bottom + 10.0)
            line = float(self._ui_line_height())
            self._draw_ui_text(f"typo: t={self._typo.elapsed_ms/1000.0:6.1f}s", x, y, UI_TEXT_COLOR)
            self._draw_ui_text(f"score={self._player.experience}  hits={self._typing.shots_hit}/{self._typing.shots_fired}", x, y + line, UI_HINT_COLOR)
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

        if not self._game_over_active:
            self._draw_aim_cursor()
        else:
            self._draw_game_cursor()
            if self._game_over_record is not None:
                self._game_over_ui.draw(
                    record=self._game_over_record,
                    banner_kind=self._game_over_banner,
                    hud_assets=self._hud_assets,
                    mouse=self._ui_mouse_pos(),
                )
