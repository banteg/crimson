from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.fonts.small import measure_small_text_width
from grim.view import ViewContext

from ..creatures.runtime import CreaturePool
from ..creatures.spawn import SpawnEnv, advance_survival_spawn_stage, tick_survival_wave_spawns
from ..gameplay import (
    GameplayState,
    PlayerInput,
    PlayerState,
    bonus_hud_update,
    perk_selection_current_choices,
    perk_selection_pick,
    player_update,
    survival_progression_update,
    weapon_assign_player,
)
from ..perks import PERK_BY_ID, PerkId
from ..ui.hud import HudAssets, draw_hud_overlay, load_hud_assets
from ..ui.perk_menu import (
    PerkMenuLayout,
    UiButtonState,
    button_draw,
    button_update,
    button_width,
    cursor_draw,
    draw_menu_panel,
    draw_menu_item,
    draw_ui_text,
    load_perk_menu_assets,
    menu_item_hit_rect,
    ui_origin,
    ui_scale,
    wrap_ui_text,
)
from ..weapons import WEAPON_TABLE
from .registry import register_view

WORLD_SIZE = 1024.0
GAME_MODE_SURVIVAL = 3

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_SPONSOR_COLOR = rl.Color(255, 255, 255, int(255 * 0.5))
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


@dataclass(slots=True)
class _SurvivalState:
    elapsed_ms: float = 0.0
    stage: int = 0
    spawn_cooldown: float = 0.0


class SurvivalView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None

        self.close_requested = False
        self._paused = False
        self._damage_scale_by_type = {
            entry.weapon_id: float(entry.damage_mult or 1.0)
            for entry in WEAPON_TABLE
            if entry.weapon_id >= 0
        }

        self._spawn_env = SpawnEnv(
            terrain_width=WORLD_SIZE,
            terrain_height=WORLD_SIZE,
            demo_mode_active=False,
            hardcore=False,
            difficulty_level=0,
        )

        self._state = GameplayState()
        self._player = PlayerState(index=0, pos_x=WORLD_SIZE * 0.5, pos_y=WORLD_SIZE * 0.5)
        self._creatures = CreaturePool(env=self._spawn_env)
        self._survival = _SurvivalState()

        self._hud_assets: HudAssets | None = None
        self._hud_missing: list[str] = []

        self._camera_x = -1.0
        self._camera_y = -1.0

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_menu_open = False
        self._perk_menu_selected = 0
        self._perk_menu_assets = None
        self._perk_ui_layout = PerkMenuLayout()
        self._perk_cancel_button = UiButtonState("Cancel")
        self._perk_cursor_hidden = False

    def _ui_line_height(self, scale: float = UI_TEXT_SCALE) -> int:
        if self._small is not None:
            return int(self._small.cell_size * scale)
        return int(20 * scale)

    def _ui_text_width(self, text: str, scale: float = UI_TEXT_SCALE) -> int:
        if self._small is not None:
            return int(measure_small_text_width(self._small, text, scale))
        return int(rl.measure_text(text, int(20 * scale)))

    def _draw_ui_text(
        self,
        text: str,
        x: float,
        y: float,
        color: rl.Color,
        scale: float = UI_TEXT_SCALE,
    ) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, x, y, scale, color)
        else:
            rl.draw_text(text, int(x), int(y), int(20 * scale), color)

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
        return self._camera_x + x, self._camera_y + y

    def _camera_screen_to_world(self, x: float, y: float) -> tuple[float, float]:
        return x - self._camera_x, y - self._camera_y

    def _update_camera(self, dt: float) -> None:
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        if screen_w > WORLD_SIZE:
            screen_w = WORLD_SIZE
        if screen_h > WORLD_SIZE:
            screen_h = WORLD_SIZE

        focus_x = self._player.pos_x
        focus_y = self._player.pos_y
        desired_x = (screen_w * 0.5) - focus_x
        desired_y = (screen_h * 0.5) - focus_y

        min_x = screen_w - WORLD_SIZE
        min_y = screen_h - WORLD_SIZE
        desired_x = _clamp(desired_x, min_x, -1.0)
        desired_y = _clamp(desired_y, min_y, -1.0)

        t = _clamp(dt * 6.0, 0.0, 1.0)
        self._camera_x = _lerp(self._camera_x, desired_x, t)
        self._camera_y = _lerp(self._camera_y, desired_y, t)

    def open(self) -> None:
        self._missing_assets.clear()
        self._hud_missing.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None

        self._hud_assets = load_hud_assets(self._assets_root)
        if self._hud_assets.missing:
            self._hud_missing = list(self._hud_assets.missing)

        self._perk_menu_assets = load_perk_menu_assets(self._assets_root)
        if self._perk_menu_assets.missing:
            self._missing_assets.extend(self._perk_menu_assets.missing)
        self._perk_ui_layout = PerkMenuLayout()
        self._perk_cancel_button = UiButtonState("Cancel")
        self._perk_cursor_hidden = False
        rl.show_cursor()

        self._paused = False
        self.close_requested = False

        self._state = GameplayState()
        self._state.rng.srand(0xBEEF)

        self._player = PlayerState(index=0, pos_x=WORLD_SIZE * 0.5, pos_y=WORLD_SIZE * 0.5)
        weapon_assign_player(self._player, 0)  # pistol

        self._creatures = CreaturePool(env=self._spawn_env)
        self._survival = _SurvivalState()

        self._camera_x = -1.0
        self._camera_y = -1.0

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_menu_open = False
        self._perk_menu_selected = 0

    def close(self) -> None:
        if self._perk_cursor_hidden:
            rl.show_cursor()
            self._perk_cursor_hidden = False
        if self._perk_menu_assets is not None:
            self._perk_menu_assets.unload()
            self._perk_menu_assets = None
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._hud_assets is not None:
            self._hud_assets.unload()
            self._hud_assets = None

    def _decay_global_timers(self, dt: float) -> None:
        bonuses = self._state.bonuses
        bonuses.weapon_power_up = max(0.0, bonuses.weapon_power_up - dt)
        bonuses.reflex_boost = max(0.0, bonuses.reflex_boost - dt)
        bonuses.energizer = max(0.0, bonuses.energizer - dt)
        bonuses.double_experience = max(0.0, bonuses.double_experience - dt)
        bonuses.freeze = max(0.0, bonuses.freeze - dt)

    def _handle_input(self) -> None:
        if self._perk_menu_open and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._perk_menu_open = False
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            self._paused = not self._paused

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self.close_requested = True

        if self._player.health <= 0.0 and rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            self.open()

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

        mouse = rl.get_mouse_position()
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

    def _perk_prompt_label(self) -> str:
        pending = int(self._state.perk_selection.pending_count)
        if pending <= 0:
            return ""
        suffix = f" ({pending})" if pending > 1 else ""
        return f"Press P to pick a perk{suffix}"

    def _perk_prompt_rect(self, label: str, *, scale: float = UI_TEXT_SCALE) -> rl.Rectangle:
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
            game_mode=GAME_MODE_SURVIVAL,
            player_count=1,
        )
        if not choices:
            self._perk_menu_open = False
            return
        self._perk_menu_open = True
        self._perk_menu_selected = 0

    def _perk_menu_handle_input(self, dt_ms: float) -> None:
        if self._perk_menu_assets is None:
            self._perk_menu_open = False
            return
        perk_state = self._state.perk_selection
        choices = perk_selection_current_choices(
            self._state,
            [self._player],
            perk_state,
            game_mode=GAME_MODE_SURVIVAL,
            player_count=1,
        )
        if not choices:
            self._perk_menu_open = False
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

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        expert_owned = int(self._player.perk_counts[int(PerkId.PERK_EXPERT)]) > 0
        list_y = self._perk_ui_layout.list_y - (10.0 if expert_owned else 0.0)
        list_step = 18.0 if expert_owned else self._perk_ui_layout.list_step_y

        for idx, perk_id in enumerate(choices):
            meta = PERK_BY_ID.get(int(perk_id))
            label = meta.name if meta is not None else f"Perk {int(perk_id)}"
            item_x = origin_x + self._perk_ui_layout.list_x * scale
            item_y = origin_y + (list_y + float(idx) * list_step) * scale
            rect = menu_item_hit_rect(self._small, label, x=item_x, y=item_y, scale=scale)
            if rl.check_collision_point_rec(mouse, rect):
                self._perk_menu_selected = idx
                if click:
                    perk_selection_pick(
                        self._state,
                        [self._player],
                        perk_state,
                        idx,
                        game_mode=GAME_MODE_SURVIVAL,
                        player_count=1,
                    )
                    self._perk_menu_open = False
                    return
                break

        cancel_w = button_width(self._small, self._perk_cancel_button.label, scale=scale, force_wide=self._perk_cancel_button.force_wide)
        cancel_x = origin_x + self._perk_ui_layout.cancel_x * scale
        button_y = origin_y + self._perk_ui_layout.button_y * scale

        if button_update(
            self._perk_cancel_button,
            x=cancel_x,
            y=button_y,
            width=cancel_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._perk_menu_open = False
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) or rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            perk_selection_pick(
                self._state,
                [self._player],
                perk_state,
                self._perk_menu_selected,
                game_mode=GAME_MODE_SURVIVAL,
                player_count=1,
            )
            self._perk_menu_open = False

    def update(self, dt: float) -> None:
        dt_ui_ms = float(min(dt, 0.1) * 1000.0)
        self._handle_input()

        perk_pending = int(self._state.perk_selection.pending_count) > 0 and self._player.health > 0.0

        if self._perk_menu_open:
            if not self._perk_cursor_hidden:
                rl.hide_cursor()
                self._perk_cursor_hidden = True
            self._perk_menu_handle_input(dt_ui_ms)
            dt = 0.0
        else:
            if self._perk_cursor_hidden:
                rl.show_cursor()
                self._perk_cursor_hidden = False

        if (not self._perk_menu_open) and perk_pending:
            label = self._perk_prompt_label()
            if label:
                rect = self._perk_prompt_rect(label)
                mouse = rl.get_mouse_position()
                self._perk_prompt_hover = rl.check_collision_point_rec(mouse, rect)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_P) or (
                self._perk_prompt_hover and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            ):
                self._open_perk_menu()

        if self._paused or self._player.health <= 0.0 or self._perk_menu_open:
            dt = 0.0

        prompt_active = perk_pending and (not self._perk_menu_open) and (not self._paused)
        if prompt_active:
            self._perk_prompt_timer_ms = _clamp(self._perk_prompt_timer_ms + dt_ui_ms, 0.0, 200.0)
        else:
            self._perk_prompt_timer_ms = _clamp(self._perk_prompt_timer_ms - dt_ui_ms, 0.0, 200.0)

        self._survival.elapsed_ms += dt * 1000.0

        if dt <= 0.0:
            return

        # Existing projectiles update first; new spawns (from player_update) take effect next tick.
        self._state.projectiles.update(
            dt,
            self._creatures.entries,
            world_size=WORLD_SIZE,
            damage_scale_by_type=self._damage_scale_by_type,
            rng=self._state.rng.rand,
            runtime_state=self._state,
        )
        self._state.secondary_projectiles.update_pulse_gun(dt, self._creatures.entries)

        self._decay_global_timers(dt)

        input_state = self._build_input()
        player_update(self._player, input_state, dt, self._state, world_size=WORLD_SIZE)

        self._creatures.update(
            dt,
            state=self._state,
            players=[self._player],
            world_width=WORLD_SIZE,
            world_height=WORLD_SIZE,
        )

        self._state.bonus_pool.update(dt, state=self._state, players=[self._player], creatures=self._creatures.entries)
        survival_progression_update(self._state, [self._player], game_mode=GAME_MODE_SURVIVAL, auto_pick=False)

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
                env=self._spawn_env,
            )

        # Regular wave spawns based on elapsed time.
        cooldown, wave_spawns = tick_survival_wave_spawns(
            self._survival.spawn_cooldown,
            dt * 1000.0,
            self._state.rng,
            player_count=1,
            survival_elapsed_ms=self._survival.elapsed_ms,
            player_experience=self._player.experience,
            terrain_width=int(WORLD_SIZE),
            terrain_height=int(WORLD_SIZE),
        )
        self._survival.spawn_cooldown = cooldown
        self._creatures.spawn_inits(wave_spawns)

        bonus_hud_update(self._state, [self._player])
        self._update_camera(dt)

    def _draw_perk_prompt(self) -> None:
        if self._perk_menu_open:
            return
        if self._player.health <= 0.0:
            return
        pending = int(self._state.perk_selection.pending_count)
        if pending <= 0:
            return
        label = self._perk_prompt_label()
        if not label:
            return

        alpha = float(self._perk_prompt_timer_ms) / 200.0
        if alpha <= 1e-3:
            return

        rect = self._perk_prompt_rect(label)
        color = rl.Color(UI_TEXT_COLOR.r, UI_TEXT_COLOR.g, UI_TEXT_COLOR.b, int(255 * alpha))
        draw_ui_text(self._small, label, rect.x, rect.y, scale=UI_TEXT_SCALE, color=color)

    def _draw_perk_menu(self) -> None:
        if not self._perk_menu_open:
            return
        if self._perk_menu_assets is None:
            return

        perk_state = self._state.perk_selection
        choices = perk_selection_current_choices(
            self._state,
            [self._player],
            perk_state,
            game_mode=GAME_MODE_SURVIVAL,
            player_count=1,
        )
        if not choices:
            return
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        origin_x, origin_y = ui_origin(screen_w, screen_h, scale)

        panel_tex = self._perk_menu_assets.menu_panel
        if panel_tex is not None:
            dst = rl.Rectangle(
                origin_x + self._perk_ui_layout.panel_x * scale,
                origin_y + self._perk_ui_layout.panel_y * scale,
                self._perk_ui_layout.panel_w * scale,
                self._perk_ui_layout.panel_h * scale,
            )
            draw_menu_panel(panel_tex, dst=dst)

        title_tex = self._perk_menu_assets.title_pick_perk
        if title_tex is not None:
            src = rl.Rectangle(0.0, 0.0, float(title_tex.width), float(title_tex.height))
            dst = rl.Rectangle(
                origin_x + self._perk_ui_layout.title_x * scale,
                origin_y + self._perk_ui_layout.title_y * scale,
                self._perk_ui_layout.title_w * scale,
                self._perk_ui_layout.title_h * scale,
            )
            rl.draw_texture_pro(title_tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        master_owned = int(self._player.perk_counts[int(PerkId.PERK_MASTER)]) > 0
        expert_owned = int(self._player.perk_counts[int(PerkId.PERK_EXPERT)]) > 0
        sponsor = None
        if master_owned:
            sponsor = "extra perks sponsored by the Perk Master"
        elif expert_owned:
            sponsor = "extra perk sponsored by the Perk Expert"
        if sponsor:
            draw_ui_text(
                self._small,
                sponsor,
                origin_x + (self._perk_ui_layout.title_x - 28.0) * scale,
                origin_y + (self._perk_ui_layout.title_y - 8.0) * scale,
                scale=scale,
                color=UI_SPONSOR_COLOR,
            )

        list_y = self._perk_ui_layout.list_y - (10.0 if expert_owned else 0.0)
        list_step = 18.0 if expert_owned else self._perk_ui_layout.list_step_y

        mouse = rl.get_mouse_position()
        for idx, perk_id in enumerate(choices):
            meta = PERK_BY_ID.get(int(perk_id))
            label = meta.name if meta is not None else f"Perk {int(perk_id)}"
            item_x = origin_x + self._perk_ui_layout.list_x * scale
            item_y = origin_y + (list_y + float(idx) * list_step) * scale
            rect = menu_item_hit_rect(self._small, label, x=item_x, y=item_y, scale=scale)
            hovered = rl.check_collision_point_rec(mouse, rect) or (idx == self._perk_menu_selected)
            draw_menu_item(self._small, label, x=item_x, y=item_y, scale=scale, hovered=hovered)

        selected = choices[self._perk_menu_selected]
        meta = PERK_BY_ID.get(int(selected))
        desc = meta.description if meta is not None else "Unknown perk."
        desc_x = origin_x + self._perk_ui_layout.desc_x * scale
        desc_y = origin_y + self._perk_ui_layout.desc_y * scale
        desc_w = self._perk_ui_layout.desc_w * scale
        desc_h = self._perk_ui_layout.desc_h * scale
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
        cancel_x = origin_x + self._perk_ui_layout.cancel_x * scale
        button_y = origin_y + self._perk_ui_layout.button_y * scale
        button_draw(self._perk_menu_assets, self._small, self._perk_cancel_button, x=cancel_x, y=button_y, width=cancel_w, scale=scale)

        cursor_draw(self._perk_menu_assets, mouse=mouse, scale=scale)

    def draw(self) -> None:
        rl.clear_background(rl.Color(10, 10, 12, 255))

        # World bounds.
        x0, y0 = self._camera_world_to_screen(0.0, 0.0)
        x1, y1 = self._camera_world_to_screen(WORLD_SIZE, WORLD_SIZE)
        rl.draw_rectangle_lines(int(x0), int(y0), int(x1 - x0), int(y1 - y0), rl.Color(40, 40, 55, 255))

        # Creatures (debug shapes).
        for creature in self._creatures.entries:
            if not (creature.active and creature.hp > 0.0):
                continue
            sx, sy = self._camera_world_to_screen(creature.x, creature.y)
            color = rl.Color(220, 90, 90, 255)
            if creature.type_id == 0:
                color = rl.Color(140, 220, 140, 255)  # zombie
            elif creature.type_id == 1:
                color = rl.Color(120, 200, 240, 255)  # lizard
            elif creature.type_id == 2:
                color = rl.Color(220, 160, 80, 255)  # alien
            elif creature.type_id in (3, 4):
                color = rl.Color(220, 90, 200, 255)  # spiders
            rl.draw_circle(int(sx), int(sy), float(creature.size * 0.5), color)

        # Bonuses.
        for bonus in self._state.bonus_pool.entries:
            if bonus.bonus_id == 0:
                continue
            sx, sy = self._camera_world_to_screen(bonus.pos_x, bonus.pos_y)
            rl.draw_circle(int(sx), int(sy), 10.0, rl.Color(220, 220, 90, 255))

        # Projectiles.
        for proj in self._state.projectiles.iter_active():
            sx, sy = self._camera_world_to_screen(proj.pos_x, proj.pos_y)
            rl.draw_circle(int(sx), int(sy), 2.0, rl.Color(240, 220, 160, 255))

        for proj in self._state.secondary_projectiles.iter_active():
            sx, sy = self._camera_world_to_screen(proj.pos_x, proj.pos_y)
            color = rl.Color(120, 200, 240, 255) if proj.type_id != 3 else rl.Color(200, 240, 160, 255)
            rl.draw_circle(int(sx), int(sy), 3.0, color)

        # Player.
        px, py = self._camera_world_to_screen(self._player.pos_x, self._player.pos_y)
        rl.draw_circle(int(px), int(py), 14.0, rl.Color(90, 190, 120, 255))
        rl.draw_circle_lines(int(px), int(py), 14.0, rl.Color(40, 80, 50, 255))

        aim_len = 42.0
        ax = px + self._player.aim_dir_x * aim_len
        ay = py + self._player.aim_dir_y * aim_len
        rl.draw_line(int(px), int(py), int(ax), int(ay), rl.Color(240, 240, 240, 255))

        hud_bottom = 0.0
        if self._hud_assets is not None:
            hud_bottom = draw_hud_overlay(
                self._hud_assets,
                player=self._player,
                bonus_hud=self._state.bonus_hud,
                elapsed_ms=self._survival.elapsed_ms,
                score=self._player.experience,
                font=self._small,
            )

        # Minimal debug text.
        x = 18.0
        y = max(18.0, hud_bottom + 10.0)
        line = float(self._ui_line_height())
        self._draw_ui_text(f"survival: t={self._survival.elapsed_ms/1000.0:6.1f}s  stage={self._survival.stage}", x, y, UI_TEXT_COLOR)
        self._draw_ui_text(f"xp={self._player.experience}  level={self._player.level}  kills={self._creatures.kill_count}", x, y + line, UI_HINT_COLOR)
        if self._paused:
            self._draw_ui_text("paused (TAB)", x, y + line * 2.0, UI_HINT_COLOR)
        if self._player.health <= 0.0:
            self._draw_ui_text("game over (ENTER to restart)", x, y + line * 2.0, UI_ERROR_COLOR)
        if self._hud_missing:
            warn = "Missing HUD assets: " + ", ".join(self._hud_missing)
            self._draw_ui_text(warn, 24.0, float(rl.get_screen_height()) - 28.0, UI_ERROR_COLOR, scale=0.8)

        self._draw_perk_prompt()
        self._draw_perk_menu()


@register_view("survival", "Survival (debug)")
def _create_survival_view(*, ctx: ViewContext) -> SurvivalView:
    return SurvivalView(ctx)
