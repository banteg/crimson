from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.fonts.small import measure_small_text_width
from grim.view import ViewContext

from ..creatures.spawn import advance_survival_spawn_stage, tick_survival_wave_spawns
from ..game_world import GameWorld
from ..gameplay import PlayerInput, perk_selection_current_choices, perk_selection_pick
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
    perk_menu_compute_layout,
    ui_origin,
    ui_scale,
    wrap_ui_text,
)
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
        self._world = GameWorld(
            assets_dir=ctx.assets_dir,
            world_size=WORLD_SIZE,
            demo_mode_active=False,
            difficulty_level=0,
            hardcore=False,
        )
        self._bind_world()
        self._survival = _SurvivalState()

        self._hud_assets: HudAssets | None = None
        self._hud_missing: list[str] = []

        self._perk_prompt_timer_ms = 0.0
        self._perk_prompt_hover = False
        self._perk_menu_open = False
        self._perk_menu_selected = 0
        self._perk_menu_assets = None
        self._perk_ui_layout = PerkMenuLayout()
        self._perk_cancel_button = UiButtonState("Cancel")
        self._perk_cursor_hidden = False

    def _bind_world(self) -> None:
        self._state = self._world.state
        self._creatures = self._world.creatures
        self._player = self._world.players[0]

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
        return self._world.world_to_screen(x, y)

    def _camera_screen_to_world(self, x: float, y: float) -> tuple[float, float]:
        return self._world.screen_to_world(x, y)

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

        self._world.open()
        self._world.reset(seed=0xBEEF, player_count=1)
        self._bind_world()
        self._survival = _SurvivalState()

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
        self._world.close()

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

        master_owned = int(self._player.perk_counts[int(PerkId.PERK_MASTER)]) > 0
        expert_owned = int(self._player.perk_counts[int(PerkId.PERK_EXPERT)]) > 0
        computed = perk_menu_compute_layout(
            self._perk_ui_layout,
            origin_x=origin_x,
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
                        game_mode=GAME_MODE_SURVIVAL,
                        player_count=1,
                    )
                    self._perk_menu_open = False
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

        input_state = self._build_input()
        self._world.update(
            dt,
            inputs=[input_state],
            auto_pick_perks=False,
            game_mode=GAME_MODE_SURVIVAL,
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

        master_owned = int(self._player.perk_counts[int(PerkId.PERK_MASTER)]) > 0
        expert_owned = int(self._player.perk_counts[int(PerkId.PERK_EXPERT)]) > 0
        computed = perk_menu_compute_layout(
            self._perk_ui_layout,
            origin_x=origin_x,
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

        mouse = rl.get_mouse_position()
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

        cursor_draw(self._perk_menu_assets, mouse=mouse, scale=scale)

    def draw(self) -> None:
        rl.clear_background(rl.Color(10, 10, 12, 255))

        # World bounds.
        world_size = float(self._world.world_size)
        x0, y0 = self._camera_world_to_screen(0.0, 0.0)
        x1, y1 = self._camera_world_to_screen(world_size, world_size)
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
