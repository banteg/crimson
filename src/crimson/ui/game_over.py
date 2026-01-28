from __future__ import annotations

from dataclasses import dataclass, field
import math
from pathlib import Path

import pyray as rl

from grim.assets import TextureLoader
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width

from ..persistence.highscores import (
    NAME_MAX_EDIT,
    TABLE_MAX,
    HighScoreRecord,
    rank_index,
    read_highscore_table,
    scores_path_for_config,
    upsert_highscore_record,
)
from ..weapons import WEAPON_BY_ID
from .hud import HudAssets
from .perk_menu import (
    PerkMenuAssets,
    UiButtonState,
    button_draw,
    button_update,
    button_width,
    cursor_draw,
    draw_ui_text,
    load_perk_menu_assets,
)


UI_BASE_WIDTH = 640.0
UI_BASE_HEIGHT = 480.0


def ui_scale(screen_w: float, screen_h: float) -> float:
    # Matches the classic UI-space helpers we use elsewhere: render in 640x480 pixel space.
    return 1.0


def ui_origin(screen_w: float, screen_h: float, scale: float) -> tuple[float, float]:
    return 0.0, 0.0


GAME_OVER_PANEL_X = -45.0
GAME_OVER_PANEL_Y = 210.0
GAME_OVER_PANEL_W = 512.0
GAME_OVER_PANEL_H = 256.0

GAME_OVER_PANEL_OFFSET_X = 20.0
GAME_OVER_PANEL_OFFSET_Y = -82.0

TEXTURE_TOP_BANNER_W = 256.0
TEXTURE_TOP_BANNER_H = 64.0

INPUT_BOX_W = 166.0  # `_DAT_0048259c = 0xa6` before `ui_text_input_update`
INPUT_BOX_H = 18.0

COLOR_TEXT = rl.Color(255, 255, 255, 255)
COLOR_TEXT_MUTED = rl.Color(255, 255, 255, int(255 * 0.8))
COLOR_SCORE_LABEL = rl.Color(230, 230, 230, 255)
COLOR_SCORE_VALUE = rl.Color(230, 230, 255, 255)


def _format_ordinal(value_1_based: int) -> str:
    value = int(value_1_based)
    if value % 100 in (11, 12, 13):
        suffix = "th"
    elif value % 10 == 1:
        suffix = "st"
    elif value % 10 == 2:
        suffix = "nd"
    elif value % 10 == 3:
        suffix = "rd"
    else:
        suffix = "th"
    return f"{value}{suffix}"


def _format_time_mm_ss(ms: int) -> str:
    total_s = max(0, int(ms)) // 1000
    minutes = total_s // 60
    seconds = total_s % 60
    return f"{minutes}:{seconds:02d}"


def _weapon_icon_src(texture: rl.Texture, weapon_id_native: int) -> rl.Rectangle | None:
    # High score records store native (1-based) weapon ids; the rewrite uses 0-based ids.
    weapon_id_native = int(weapon_id_native)
    weapon_id = 0 if weapon_id_native <= 0 else weapon_id_native - 1
    entry = WEAPON_BY_ID.get(int(weapon_id))
    icon_index = entry.icon_index if entry is not None else None
    if icon_index is None or icon_index < 0 or icon_index > 31:
        return None
    grid = 8
    cell_w = float(texture.width) / grid
    cell_h = float(texture.height) / grid
    frame = int(icon_index) * 2
    col = frame % grid
    row = frame // grid
    return rl.Rectangle(float(col * cell_w), float(row * cell_h), float(cell_w * 2), float(cell_h))


@dataclass(slots=True)
class GameOverAssets:
    menu_panel: rl.Texture | None
    text_reaper: rl.Texture | None
    text_well_done: rl.Texture | None
    perk_menu_assets: PerkMenuAssets
    missing: list[str]


def load_game_over_assets(assets_root: Path) -> GameOverAssets:
    perk_menu_assets = load_perk_menu_assets(assets_root)
    loader = TextureLoader.from_assets_root(assets_root)
    menu_panel = loader.get(name="ui_menuPanel", paq_rel="ui/ui_menuPanel.jaz", fs_rel="ui/ui_menuPanel.png")
    text_reaper = loader.get(name="ui_textReaper", paq_rel="ui/ui_textReaper.jaz", fs_rel="ui/ui_textReaper.png")
    text_well_done = loader.get(
        name="ui_textWellDone",
        paq_rel="ui/ui_textWellDone.jaz",
        fs_rel="ui/ui_textWellDone.png",
    )
    missing: list[str] = list(perk_menu_assets.missing)
    missing.extend(loader.missing)
    return GameOverAssets(
        menu_panel=menu_panel,
        text_reaper=text_reaper,
        text_well_done=text_well_done,
        perk_menu_assets=perk_menu_assets,
        missing=missing,
    )


def _draw_texture_centered(tex: rl.Texture, x: float, y: float, w: float, h: float, alpha: float) -> None:
    src = rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height))
    dst = rl.Rectangle(float(x), float(y), float(w), float(h))
    tint = rl.Color(255, 255, 255, int(255 * max(0.0, min(1.0, alpha))))
    rl.draw_texture_pro(tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)


def _poll_text_input(max_len: int, *, allow_space: bool = True) -> str:
    out = ""
    while True:
        value = rl.get_char_pressed()
        if value == 0:
            break
        if value < 0x20 or value > 0xFF:
            continue
        if not allow_space and value == 0x20:
            continue
        if len(out) >= max_len:
            continue
        out += chr(int(value))
    return out


@dataclass(slots=True)
class GameOverUi:
    assets_root: Path
    base_dir: Path

    config: object  # CrimsonConfig-like

    assets: GameOverAssets | None = None
    font: SmallFontData | None = None
    missing_assets: list[str] = None  # type: ignore[assignment]

    input_text: str = ""
    input_caret: int = 0
    phase: int = -1  # -1 init, 0 name entry (if qualifies), 1 results/buttons
    rank: int = TABLE_MAX
    _candidate_record: HighScoreRecord | None = None
    _saved: bool = False
    _dt: float = 0.0

    _hover_weapon: float = 0.0
    _hover_time: float = 0.0
    _hover_hit_ratio: float = 0.0

    # Buttons (rendered via existing ui_button implementation)
    _ok_button: UiButtonState = field(default_factory=lambda: UiButtonState("OK", force_wide=False))
    _play_again_button: UiButtonState = field(default_factory=lambda: UiButtonState("Play Again", force_wide=True))
    _high_scores_button: UiButtonState = field(default_factory=lambda: UiButtonState("High scores", force_wide=True))
    _main_menu_button: UiButtonState = field(default_factory=lambda: UiButtonState("Main Menu", force_wide=True))

    _consume_enter: bool = False

    def open(self) -> None:
        self.close()
        self.missing_assets = []
        try:
            self.font = load_small_font(self.assets_root, self.missing_assets)
        except Exception:
            self.font = None
        self.assets = load_game_over_assets(self.assets_root)
        if self.assets.missing:
            self.missing_assets.extend(self.assets.missing)
        self.phase = -1
        self.rank = TABLE_MAX
        self._candidate_record = None
        self._saved = False
        self._dt = 0.0
        self._hover_weapon = 0.0
        self._hover_time = 0.0
        self._hover_hit_ratio = 0.0
        self.input_text = ""
        self.input_caret = 0
        self._consume_enter = True

    def close(self) -> None:
        if self.assets is not None:
            self.assets = None
        if self.font is not None:
            rl.unload_texture(self.font.texture)
            self.font = None

    def consume_enter(self) -> bool:
        if self._consume_enter:
            self._consume_enter = False
            return True
        return False

    def _text_width(self, text: str, scale: float) -> float:
        if self.font is None:
            return float(rl.measure_text(text, int(20 * scale)))
        return float(measure_small_text_width(self.font, text, scale))

    def _draw_small(self, text: str, x: float, y: float, scale: float, color: rl.Color) -> None:
        if self.font is not None:
            draw_small_text(self.font, text, x, y, scale, color)
        else:
            rl.draw_text(text, int(x), int(y), int(20 * scale), color)

    def _panel_layout(self, *, scale: float) -> tuple[rl.Rectangle, float, float]:
        # Keep consistent with the main menu panel offsets.
        panel_x = GAME_OVER_PANEL_X * scale
        panel_y = GAME_OVER_PANEL_Y * scale
        origin_x = -(GAME_OVER_PANEL_OFFSET_X * scale)
        origin_y = -(GAME_OVER_PANEL_OFFSET_Y * scale)
        left = panel_x - origin_x
        top = panel_y - origin_y
        panel = rl.Rectangle(float(left), float(top), GAME_OVER_PANEL_W * scale, GAME_OVER_PANEL_H * scale)
        return panel, left, top

    def update(
        self,
        dt: float,
        *,
        record: HighScoreRecord,
        player_name_default: str,
        mouse: rl.Vector2 | None = None,
    ) -> str | None:
        self._dt = float(min(dt, 0.1))
        dt_ms = self._dt * 1000.0
        if mouse is None:
            mouse = rl.get_mouse_position()

        if self.assets is None:
            return None
        if self._consume_enter:
            self._consume_enter = False
            rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER)
        if self.phase == -1:
            # If in the top 100, prompt for a name. Otherwise show score-too-low message and buttons.
            game_mode_id = int(getattr(self.config, "data", {}).get("game_mode", 1))
            candidate = record.copy()
            candidate.game_mode_id = game_mode_id
            self._candidate_record = candidate

            path = scores_path_for_config(self.base_dir, self.config)
            records = read_highscore_table(path, game_mode_id=game_mode_id)
            idx = rank_index(records, candidate)
            self.rank = int(idx)
            if idx < TABLE_MAX:
                self.phase = 0
                self.input_text = player_name_default[:NAME_MAX_EDIT]
                self.input_caret = len(self.input_text)
            else:
                self.phase = 1

        # Basic text input behavior for the name-entry phase.
        if self.phase == 0:
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            typed = _poll_text_input(NAME_MAX_EDIT - len(self.input_text), allow_space=True)
            if typed:
                self.input_text = (self.input_text[: self.input_caret] + typed + self.input_text[self.input_caret :])[:NAME_MAX_EDIT]
                self.input_caret = min(len(self.input_text), self.input_caret + len(typed))
            if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
                if self.input_caret > 0:
                    self.input_text = self.input_text[: self.input_caret - 1] + self.input_text[self.input_caret :]
                    self.input_caret -= 1
            if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
                self.input_caret = max(0, self.input_caret - 1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
                self.input_caret = min(len(self.input_text), self.input_caret + 1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_HOME):
                self.input_caret = 0
            if rl.is_key_pressed(rl.KeyboardKey.KEY_END):
                self.input_caret = len(self.input_text)

            screen_w = float(rl.get_screen_width())
            screen_h = float(rl.get_screen_height())
            scale = ui_scale(screen_w, screen_h)
            _panel, panel_left, panel_top = self._panel_layout(scale=scale)
            banner_x = panel_left + (GAME_OVER_PANEL_W * scale - TEXTURE_TOP_BANNER_W * scale) * 0.5
            banner_y = panel_top + 40.0 * scale
            base_x = banner_x + 8.0 * scale
            base_y = banner_y + 84.0 * scale
            input_y = base_y + 40.0 * scale
            ok_x = base_x + 170.0 * scale
            ok_y = input_y - 8.0 * scale
            ok_w = button_width(self.font, self._ok_button.label, scale=scale, force_wide=self._ok_button.force_wide)
            ok_clicked = button_update(self._ok_button, x=ok_x, y=ok_y, width=ok_w, dt_ms=dt_ms, mouse=mouse, click=click)

            if ok_clicked or rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
                if self.input_text.strip():
                    candidate = (self._candidate_record or record).copy()
                    candidate.set_name(self.input_text)
                    path = scores_path_for_config(self.base_dir, self.config)
                    if not self._saved:
                        upsert_highscore_record(path, candidate)
                        self._saved = True
                    self.phase = 1
                    return None
                # else: ignore (native plays a buzzer SFX)
        else:
            # Buttons phase: let the caller handle navigation; we just report actions.
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            screen_w = float(rl.get_screen_width())
            screen_h = float(rl.get_screen_height())
            scale = ui_scale(screen_w, screen_h)
            origin_x, origin_y = ui_origin(screen_w, screen_h, scale)
            _panel, left, top = self._panel_layout(scale=scale)
            banner_x = left + (GAME_OVER_PANEL_W * scale - TEXTURE_TOP_BANNER_W * scale) * 0.5
            banner_y = top + 40.0 * scale
            score_y = banner_y + (64.0 if self.rank < TABLE_MAX else 62.0) * scale
            x = banner_x + 52.0 * scale
            y = score_y + 146.0 * scale
            _ = origin_x, origin_y

            play_again_w = button_width(self.font, self._play_again_button.label, scale=scale, force_wide=self._play_again_button.force_wide)
            if button_update(self._play_again_button, x=x, y=y, width=play_again_w, dt_ms=dt_ms, mouse=mouse, click=click):
                return "play_again"
            y += 32.0 * scale

            high_scores_w = button_width(self.font, self._high_scores_button.label, scale=scale, force_wide=self._high_scores_button.force_wide)
            if button_update(self._high_scores_button, x=x, y=y, width=high_scores_w, dt_ms=dt_ms, mouse=mouse, click=click):
                return "high_scores"
            y += 32.0 * scale

            main_menu_w = button_width(self.font, self._main_menu_button.label, scale=scale, force_wide=self._main_menu_button.force_wide)
            if button_update(self._main_menu_button, x=x, y=y, width=main_menu_w, dt_ms=dt_ms, mouse=mouse, click=click):
                return "main_menu"
        return None

    def _draw_score_card(
        self,
        *,
        x: float,
        y: float,
        record: HighScoreRecord,
        hud_assets: HudAssets | None,
        alpha: float,
        show_weapon_row: bool,
        scale: float,
        mouse: rl.Vector2,
    ) -> None:
        dt_hover = float(self._dt) * 2.0
        label_color = rl.Color(COLOR_SCORE_LABEL.r, COLOR_SCORE_LABEL.g, COLOR_SCORE_LABEL.b, int(255 * alpha * 0.8))
        value_color = rl.Color(COLOR_SCORE_VALUE.r, COLOR_SCORE_VALUE.g, COLOR_SCORE_VALUE.b, int(255 * alpha))
        hint_color = rl.Color(COLOR_SCORE_LABEL.r, COLOR_SCORE_LABEL.g, COLOR_SCORE_LABEL.b, int(255 * alpha * 0.7))

        base_x = x + 4.0 * scale
        base_y = y

        # Left column: Score + value + Rank.
        score_label = "Score"
        score_label_w = self._text_width(score_label, 1.0 * scale)
        self._draw_small(score_label, base_x + 32.0 * scale - score_label_w * 0.5, base_y, 1.0 * scale, label_color)

        if int(record.game_mode_id) in (2, 3):
            seconds = float(int(record.survival_elapsed_ms)) * 0.001
            score_value = f"{seconds:.2f} secs"
        else:
            score_value = f"{int(record.score_xp)}"
        score_value_w = self._text_width(score_value, 1.0 * scale)
        self._draw_small(score_value, base_x + 32.0 * scale - score_value_w * 0.5, base_y + 15.0 * scale, 1.0 * scale, value_color)

        rank_value = _format_ordinal(int(self.rank) + 1)
        rank_text = f"Rank: {rank_value}"
        rank_w = self._text_width(rank_text, 1.0 * scale)
        self._draw_small(rank_text, base_x + 32.0 * scale - rank_w * 0.5, base_y + 30.0 * scale, 1.0 * scale, label_color)

        # Separator between columns (mirrors FUN_00441220 + offset adjustments).
        sep_x = base_x + 80.0 * scale
        rl.draw_line(int(sep_x), int(base_y), int(sep_x), int(base_y + 48.0 * scale), label_color)

        # Right column: Game time + gauge, or Experience in quest mode.
        col2_x = base_x + 96.0 * scale
        if int(record.game_mode_id) == 3:
            self._draw_small("Experience", col2_x, base_y, 1.0 * scale, label_color)
            xp_value = f"{int(record.score_xp)}"
            xp_w = self._text_width(xp_value, 1.0 * scale)
            self._draw_small(xp_value, col2_x + 32.0 * scale - xp_w * 0.5, base_y + 15.0 * scale, 1.0 * scale, label_color)
            self._hover_time = max(0.0, float(self._hover_time) - dt_hover)
        else:
            self._draw_small("Game time", col2_x + 6.0 * scale, base_y, 1.0 * scale, label_color)
            time_rect = rl.Rectangle(col2_x + 8.0 * scale, base_y + 16.0 * scale, 64.0 * scale, 29.0 * scale)
            hovering_time = rl.check_collision_point_rec(mouse, time_rect)
            self._hover_time = float(max(0.0, min(1.0, self._hover_time + (dt_hover if hovering_time else -dt_hover))))

            elapsed_ms = int(record.survival_elapsed_ms)
            if hud_assets is not None and hud_assets.clock_table is not None:
                src = rl.Rectangle(0.0, 0.0, float(hud_assets.clock_table.width), float(hud_assets.clock_table.height))
                dst = rl.Rectangle(col2_x + 8.0 * scale, base_y + 14.0 * scale, 32.0 * scale, 32.0 * scale)
                rl.draw_texture_pro(hud_assets.clock_table, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.Color(255, 255, 255, int(255 * alpha)))
            if hud_assets is not None and hud_assets.clock_pointer is not None:
                src = rl.Rectangle(0.0, 0.0, float(hud_assets.clock_pointer.width), float(hud_assets.clock_pointer.height))
                dst = rl.Rectangle(col2_x + 8.0 * scale, base_y + 14.0 * scale, 32.0 * scale, 32.0 * scale)
                seconds = max(0, elapsed_ms // 1000)
                rotation = float(seconds) * 6.0
                origin = rl.Vector2(16.0 * scale, 16.0 * scale)
                rl.draw_texture_pro(hud_assets.clock_pointer, src, dst, origin, rotation, rl.Color(255, 255, 255, int(255 * alpha)))

            time_text = _format_time_mm_ss(elapsed_ms)
            self._draw_small(time_text, col2_x + 40.0 * scale, base_y + 19.0 * scale, 1.0 * scale, label_color)

        # Second row: weapon icon + frags + hit ratio (suppressed while entering the name).
        row_y = base_y + 52.0 * scale
        self._hover_weapon = float(max(0.0, min(1.0, self._hover_weapon)))
        self._hover_hit_ratio = float(max(0.0, min(1.0, self._hover_hit_ratio)))
        if show_weapon_row and hud_assets is not None and hud_assets.wicons is not None:
            weapon_rect = rl.Rectangle(base_x, row_y, 64.0 * scale, 32.0 * scale)
            hovering_weapon = rl.check_collision_point_rec(mouse, weapon_rect)
            self._hover_weapon = float(max(0.0, min(1.0, self._hover_weapon + (dt_hover if hovering_weapon else -dt_hover))))

            src = _weapon_icon_src(hud_assets.wicons, int(record.most_used_weapon_id))
            if src is not None:
                dst = rl.Rectangle(base_x, row_y, 64.0 * scale, 32.0 * scale)
                rl.draw_texture_pro(hud_assets.wicons, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.Color(255, 255, 255, int(255 * alpha)))

            weapon_id_native = int(record.most_used_weapon_id)
            weapon_id = 0 if weapon_id_native <= 0 else weapon_id_native - 1
            weapon_entry = WEAPON_BY_ID.get(int(weapon_id))
            weapon_name = weapon_entry.name if weapon_entry is not None and weapon_entry.name else f"weapon_{weapon_id_native}"
            name_w = self._text_width(weapon_name, 1.0 * scale)
            name_x = base_x + max(0.0, (32.0 * scale - name_w * 0.5))
            self._draw_small(weapon_name, name_x, row_y + 32.0 * scale, 1.0 * scale, hint_color)

            frags_text = f"Frags: {int(record.creature_kill_count)}"
            self._draw_small(frags_text, base_x + 110.0 * scale, row_y + 1.0 * scale, 1.0 * scale, label_color)

            fired = max(0, int(record.shots_fired))
            hit = max(0, int(record.shots_hit))
            ratio = int((hit * 100) / fired) if fired > 0 else 0
            hit_text = f"Hit %: {ratio}%"
            self._draw_small(hit_text, base_x + 110.0 * scale, row_y + 15.0 * scale, 1.0 * scale, label_color)

            hit_rect = rl.Rectangle(base_x + 110.0 * scale, row_y + 15.0 * scale, 64.0 * scale, 17.0 * scale)
            hovering_hit = rl.check_collision_point_rec(mouse, hit_rect)
            self._hover_hit_ratio = float(max(0.0, min(1.0, self._hover_hit_ratio + (dt_hover if hovering_hit else -dt_hover))))
            tooltip_y = row_y + 48.0 * scale
        else:
            self._hover_weapon = max(0.0, float(self._hover_weapon) - dt_hover)
            self._hover_hit_ratio = 0.0
            tooltip_y = row_y

        self._hover_weapon = float(max(0.0, min(1.0, self._hover_weapon)))
        self._hover_time = float(max(0.0, min(1.0, self._hover_time)))
        self._hover_hit_ratio = float(max(0.0, min(1.0, self._hover_hit_ratio)))

        if self._hover_weapon > 0.5:
            t = (self._hover_weapon - 0.5) * 2.0
            col = rl.Color(label_color.r, label_color.g, label_color.b, int(255 * alpha * t))
            self._draw_small("Most used weapon during the game", base_x - 20.0 * scale, tooltip_y, 1.0 * scale, col)
        if self._hover_time > 0.5:
            t = (self._hover_time - 0.5) * 2.0
            col = rl.Color(label_color.r, label_color.g, label_color.b, int(255 * alpha * t))
            self._draw_small("The time the game lasted", base_x + 12.0 * scale, tooltip_y, 1.0 * scale, col)
        if self._hover_hit_ratio > 0.5:
            t = (self._hover_hit_ratio - 0.5) * 2.0
            col = rl.Color(label_color.r, label_color.g, label_color.b, int(255 * alpha * t))
            self._draw_small("The % of shot bullets hit the target", base_x - 22.0 * scale, tooltip_y, 1.0 * scale, col)

    def draw(
        self,
        *,
        record: HighScoreRecord,
        banner_kind: str,
        hud_assets: HudAssets | None,
        mouse: rl.Vector2 | None = None,
    ) -> None:
        if self.assets is None:
            return
        if mouse is None:
            mouse = rl.get_mouse_position()

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        origin_x, origin_y = ui_origin(screen_w, screen_h, scale)
        _ = origin_x, origin_y

        panel, left, top = self._panel_layout(scale=scale)

        # Panel background
        if self.assets.menu_panel is not None:
            src = rl.Rectangle(0.0, 0.0, float(self.assets.menu_panel.width), float(self.assets.menu_panel.height))
            dst = rl.Rectangle(panel.x, panel.y, panel.width, panel.height)
            rl.draw_texture_pro(self.assets.menu_panel, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        # Banner (Reaper / Well done)
        banner = self.assets.text_reaper if banner_kind == "reaper" else self.assets.text_well_done
        if banner is not None:
            x = left + (panel.width - TEXTURE_TOP_BANNER_W * scale) * 0.5
            y = top + 40.0 * scale
            _draw_texture_centered(
                banner,
                x,
                y,
                TEXTURE_TOP_BANNER_W * scale,
                TEXTURE_TOP_BANNER_H * scale,
                1.0,
            )

        banner_x = left + (panel.width - TEXTURE_TOP_BANNER_W * scale) * 0.5
        banner_y = top + 40.0 * scale

        if self.phase == 0:
            base_x = banner_x + 8.0 * scale
            base_y = banner_y + 84.0 * scale
            self._draw_small("State your name, trooper!", base_x + 42.0 * scale, base_y, 1.0 * scale, COLOR_TEXT)

            input_x = base_x
            input_y = base_y + 40.0 * scale
            rl.draw_rectangle_lines(int(input_x), int(input_y), int(INPUT_BOX_W * scale), int(INPUT_BOX_H * scale), rl.WHITE)
            rl.draw_rectangle(int(input_x + 1.0 * scale), int(input_y + 1.0 * scale), int((INPUT_BOX_W - 2.0) * scale), int((INPUT_BOX_H - 2.0) * scale), rl.Color(0, 0, 0, 255))
            draw_ui_text(self.font, self.input_text, input_x + 4.0 * scale, input_y + 2.0 * scale, scale=1.0 * scale, color=COLOR_TEXT_MUTED)
            caret_alpha = 1.0
            if math.sin(float(rl.get_time()) * 4.0) > 0.0:
                caret_alpha = 0.4
            caret_color = rl.Color(255, 255, 255, int(255 * caret_alpha))
            caret_x = input_x + 4.0 * scale + self._text_width(self.input_text[: self.input_caret], 1.0 * scale)
            rl.draw_rectangle(int(caret_x), int(input_y + 2.0 * scale), int(1.0 * scale), int(14.0 * scale), caret_color)

            ok_x = base_x + 170.0 * scale
            ok_y = input_y - 8.0 * scale
            ok_w = button_width(self.font, self._ok_button.label, scale=scale, force_wide=self._ok_button.force_wide)
            button_draw(self.assets.perk_menu_assets, self.font, self._ok_button, x=ok_x, y=ok_y, width=ok_w, scale=scale)

            score_x = base_x + 16.0 * scale
            score_y = input_y + 60.0 * scale + 16.0 * scale
            self._draw_score_card(
                x=score_x,
                y=score_y,
                record=record,
                hud_assets=hud_assets,
                alpha=1.0,
                show_weapon_row=False,
                scale=scale,
                mouse=mouse,
            )
        else:
            score_card_x = banner_x + 30.0 * scale
            text_y = banner_y + (64.0 if self.rank < TABLE_MAX else 62.0) * scale
            if self.rank >= TABLE_MAX and banner_kind == "reaper":
                self._draw_small("Score too low for top100.", banner_x + 38.0 * scale, text_y, 1.0 * scale, rl.Color(200, 200, 200, 255))
                text_y += 6.0 * scale

            self._draw_score_card(
                x=score_card_x,
                y=text_y + 16.0 * scale,
                record=record,
                hud_assets=hud_assets,
                alpha=1.0,
                show_weapon_row=True,
                scale=scale,
                mouse=mouse,
            )

        # Buttons phase rendering.
        if self.phase == 1:
            score_y = banner_y + (64.0 if self.rank < TABLE_MAX else 62.0) * scale
            button_x = banner_x + 52.0 * scale
            button_y = score_y + 146.0 * scale
            play_again_w = button_width(self.font, self._play_again_button.label, scale=scale, force_wide=self._play_again_button.force_wide)
            button_draw(self.assets.perk_menu_assets, self.font, self._play_again_button, x=button_x, y=button_y, width=play_again_w, scale=scale)
            button_y += 32.0 * scale

            high_scores_w = button_width(self.font, self._high_scores_button.label, scale=scale, force_wide=self._high_scores_button.force_wide)
            button_draw(self.assets.perk_menu_assets, self.font, self._high_scores_button, x=button_x, y=button_y, width=high_scores_w, scale=scale)
            button_y += 32.0 * scale

            main_menu_w = button_width(self.font, self._main_menu_button.label, scale=scale, force_wide=self._main_menu_button.force_wide)
            button_draw(self.assets.perk_menu_assets, self.font, self._main_menu_button, x=button_x, y=button_y, width=main_menu_w, scale=scale)

        cursor_draw(self.assets.perk_menu_assets, mouse=mouse, scale=scale)
