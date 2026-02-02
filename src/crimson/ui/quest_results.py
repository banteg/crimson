from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
import math
from pathlib import Path

import pyray as rl

from grim.assets import TextureLoader
from grim.config import CrimsonConfig
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width

from ..persistence.highscores import (
    NAME_MAX_EDIT,
    TABLE_MAX,
    HighScoreRecord,
    rank_index,
    read_highscore_table,
    scores_path_for_mode,
    upsert_highscore_record,
)
from ..quests.results import QuestFinalTime, QuestResultsBreakdownAnim, tick_quest_results_breakdown_anim
from .menu_panel import draw_classic_menu_panel
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
    # Classic UI-space: draw in backbuffer pixels.
    return 1.0


def ui_origin(screen_w: float, screen_h: float, scale: float) -> tuple[float, float]:
    return 0.0, 0.0


def _menu_widescreen_y_shift(layout_w: float) -> float:
    # ui_menu_layout_init: pos_y += (screen_width / 640.0) * 150.0 - 150.0
    return (layout_w / UI_BASE_WIDTH) * 150.0 - 150.0


# `quest_results_screen_update` base layout (Crimsonland classic UI panel).
# Values are derived from `ui_menu_assets_init` + `ui_menu_layout_init` and how
# the quest results screen composes `ui_menuPanel` geometry:
#   panel_left = geom_x0 + pos_x + slide_x
#   panel_top  = geom_y0 + pos_y
#
# Where:
# - pos_x/pos_y are `ui_element_t` position fields set to (-45, 110)
# - geom_x0/geom_y0 are the first vertex coordinates of the `ui_menuPanel` geo,
#   after `ui_menu_assets_init` transforms it into an 8-vertex 3-slice panel.
QUEST_RESULTS_PANEL_POS_X = -45.0
QUEST_RESULTS_PANEL_POS_Y = 110.0
QUEST_RESULTS_PANEL_GEOM_X0 = -63.0
QUEST_RESULTS_PANEL_GEOM_Y0 = -81.0

QUEST_RESULTS_PANEL_W = 510.0
QUEST_RESULTS_PANEL_H = 378.0

TEXTURE_TOP_BANNER_W = 256.0
TEXTURE_TOP_BANNER_H = 64.0

INPUT_BOX_W = 166.0
INPUT_BOX_H = 18.0

# Capture (1024x768) shows the quest results panel uses the same ui_element
# timeline pattern as other screens: fully hidden until 100ms, then slides in
# over 300ms (end=100, start=400).
PANEL_SLIDE_START_MS = 400.0
PANEL_SLIDE_END_MS = 100.0

COLOR_TEXT = rl.Color(255, 255, 255, 255)
COLOR_TEXT_MUTED = rl.Color(255, 255, 255, int(255 * 0.8))
COLOR_TEXT_SUBTLE = rl.Color(255, 255, 255, int(255 * 0.7))
COLOR_GREEN = rl.Color(25, 200, 25, 255)


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


@dataclass(slots=True)
class QuestResultsAssets:
    menu_panel: rl.Texture | None
    text_well_done: rl.Texture | None
    perk_menu_assets: PerkMenuAssets
    missing: list[str]


def load_quest_results_assets(assets_root: Path) -> QuestResultsAssets:
    perk_menu_assets = load_perk_menu_assets(assets_root)
    loader = TextureLoader.from_assets_root(assets_root)
    text_well_done = loader.get(
        name="ui_textWellDone",
        paq_rel="ui/ui_textWellDone.jaz",
        fs_rel="ui/ui_textWellDone.png",
    )
    missing: list[str] = list(perk_menu_assets.missing)
    missing.extend(loader.missing)
    return QuestResultsAssets(
        menu_panel=perk_menu_assets.menu_panel,
        text_well_done=text_well_done,
        perk_menu_assets=perk_menu_assets,
        missing=missing,
    )


@dataclass(slots=True)
class QuestResultsUi:
    assets_root: Path
    base_dir: Path
    config: CrimsonConfig

    assets: QuestResultsAssets | None = None
    font: SmallFontData | None = None
    missing_assets: list[str] = None  # type: ignore[assignment]

    phase: int = -1  # -1 init, 0 breakdown, 1 name entry (if qualifies), 2 results/buttons
    rank: int = TABLE_MAX
    highlight_rank: int | None = None

    quest_level: str = ""
    quest_title: str = ""
    quest_stage_major: int = 0
    quest_stage_minor: int = 0
    unlock_weapon_name: str = ""
    unlock_perk_name: str = ""

    record: HighScoreRecord | None = None
    breakdown: QuestFinalTime | None = None
    _breakdown_anim: QuestResultsBreakdownAnim | None = None
    _scores_path: Path | None = None

    input_text: str = ""
    input_caret: int = 0
    _saved: bool = False

    _intro_ms: float = 0.0
    _panel_open_sfx_played: bool = False
    _closing: bool = False
    _close_action: str | None = None
    _consume_enter: bool = False

    _ok_button: UiButtonState = field(default_factory=lambda: UiButtonState("OK", force_wide=False))
    _play_next_button: UiButtonState = field(default_factory=lambda: UiButtonState("Play Next", force_wide=True))
    _play_again_button: UiButtonState = field(default_factory=lambda: UiButtonState("Play Again", force_wide=True))
    _high_scores_button: UiButtonState = field(default_factory=lambda: UiButtonState("High scores", force_wide=True))
    _main_menu_button: UiButtonState = field(default_factory=lambda: UiButtonState("Main Menu", force_wide=True))

    def open(
        self,
        *,
        record: HighScoreRecord,
        breakdown: QuestFinalTime,
        quest_level: str,
        quest_title: str,
        quest_stage_major: int,
        quest_stage_minor: int,
        unlock_weapon_name: str,
        unlock_perk_name: str,
        player_name_default: str,
    ) -> None:
        self.close()
        self.missing_assets = []
        try:
            self.font = load_small_font(self.assets_root, self.missing_assets)
        except Exception:
            self.font = None
        self.assets = load_quest_results_assets(self.assets_root)
        if self.assets.missing:
            self.missing_assets.extend(self.assets.missing)

        self.phase = -1
        self.rank = TABLE_MAX
        self.highlight_rank = None
        self.quest_level = str(quest_level or "")
        self.quest_title = str(quest_title or "")
        self.quest_stage_major = int(quest_stage_major)
        self.quest_stage_minor = int(quest_stage_minor)
        self.unlock_weapon_name = str(unlock_weapon_name or "")
        self.unlock_perk_name = str(unlock_perk_name or "")
        self.record = record.copy()
        self.breakdown = breakdown
        self._breakdown_anim = QuestResultsBreakdownAnim.start()
        self._saved = False

        # Native behavior: the final quest replaces "Play Next" with "Show End Note".
        if int(self.quest_stage_major) == 5 and int(self.quest_stage_minor) == 10:
            self._play_next_button.label = "Show End Note"
        else:
            self._play_next_button.label = "Play Next"

        hardcore = bool(int(self.config.data.get("hardcore_flag", 0) or 0))
        self._scores_path = scores_path_for_mode(
            self.base_dir,
            3,
            hardcore=hardcore,
            quest_stage_major=int(self.quest_stage_major),
            quest_stage_minor=int(self.quest_stage_minor),
        )

        try:
            records = read_highscore_table(self._scores_path, game_mode_id=3)
            self.rank = int(rank_index(records, self.record))
        except Exception:
            self.rank = TABLE_MAX

        self.input_text = str(player_name_default or "")[:NAME_MAX_EDIT]
        self.input_caret = len(self.input_text)

        self._intro_ms = 0.0
        self._panel_open_sfx_played = False
        self._closing = False
        self._close_action = None
        self._consume_enter = True
        self.phase = 0

    def close(self) -> None:
        if self.assets is not None:
            self.assets = None
        if self.font is not None:
            rl.unload_texture(self.font.texture)
            self.font = None

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

    def _text_width(self, text: str, scale: float) -> float:
        if self.font is None:
            return float(rl.measure_text(text, int(20 * scale)))
        return float(measure_small_text_width(self.font, text, scale))

    def _draw_small(self, text: str, x: float, y: float, scale: float, color: rl.Color) -> None:
        if self.font is not None:
            draw_small_text(self.font, text, x, y, scale, color)
        else:
            rl.draw_text(text, int(x), int(y), int(20 * scale), color)

    def _panel_layout(self, *, screen_w: float, scale: float) -> tuple[rl.Rectangle, float, float]:
        # Match MenuView._ui_element_anim offset math (linear, with a 100ms hold hidden).
        t_ms = float(self._intro_ms)
        if t_ms < PANEL_SLIDE_END_MS:
            panel_slide_x = -QUEST_RESULTS_PANEL_W
        elif t_ms < PANEL_SLIDE_START_MS:
            span = float(PANEL_SLIDE_START_MS - PANEL_SLIDE_END_MS)
            p = (t_ms - PANEL_SLIDE_END_MS) / span if span > 1e-6 else 1.0
            panel_slide_x = -((1.0 - p) * QUEST_RESULTS_PANEL_W)
        else:
            panel_slide_x = 0.0

        left = (QUEST_RESULTS_PANEL_GEOM_X0 + QUEST_RESULTS_PANEL_POS_X + panel_slide_x) * scale
        layout_w = screen_w / scale if scale else screen_w
        widescreen_shift_y = _menu_widescreen_y_shift(layout_w)
        top = (QUEST_RESULTS_PANEL_GEOM_Y0 + QUEST_RESULTS_PANEL_POS_Y + widescreen_shift_y) * scale
        panel = rl.Rectangle(float(left), float(top), QUEST_RESULTS_PANEL_W * scale, QUEST_RESULTS_PANEL_H * scale)
        return panel, left, top

    def update(
        self,
        dt: float,
        *,
        play_sfx: Callable[[str], None] | None = None,
        rand: Callable[[], int] | None = None,
        mouse: rl.Vector2 | None = None,
    ) -> str | None:
        dt_s = float(min(dt, 0.1))
        dt_ms = dt_s * 1000.0
        if mouse is None:
            mouse = rl.get_mouse_position()
        if rand is None:
            def rand() -> int:
                return 0

        if self.assets is None or self.record is None or self.breakdown is None:
            return None

        if self._closing:
            self._intro_ms = max(0.0, float(self._intro_ms) - dt_ms)
            if self._intro_ms <= 1e-3 and self._close_action is not None:
                action = self._close_action
                self._close_action = None
                self._closing = False
                return action
            return None

        self._intro_ms = min(PANEL_SLIDE_START_MS, self._intro_ms + dt_ms)
        if (not self._panel_open_sfx_played) and play_sfx is not None and self._intro_ms >= PANEL_SLIDE_START_MS - 1e-3:
            play_sfx("sfx_ui_panelclick")
            self._panel_open_sfx_played = True
        if self._consume_enter:
            self._consume_enter = False
            rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            if play_sfx is not None:
                play_sfx("sfx_ui_buttonclick")
            self._begin_close_transition("main_menu")
            return None

        qualifies = int(self.rank) < TABLE_MAX

        if self.phase == 0:
            anim = self._breakdown_anim
            if anim is None:
                self._breakdown_anim = QuestResultsBreakdownAnim.start()
                anim = self._breakdown_anim

            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE) or click:
                anim.set_final(self.breakdown)
                self.phase = 1 if qualifies else 2
                return None

            clinks = tick_quest_results_breakdown_anim(
                anim,
                frame_dt_ms=int(dt_s * 1000.0),
                target=self.breakdown,
            )
            if clinks > 0 and play_sfx is not None:
                play_sfx("sfx_ui_clink_01")
            if anim.done:
                self.phase = 1 if qualifies else 2
            return None

        if self.phase == 1:
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            typed = _poll_text_input(NAME_MAX_EDIT - len(self.input_text), allow_space=True)
            if typed:
                self.input_text = (self.input_text[: self.input_caret] + typed + self.input_text[self.input_caret :])[:NAME_MAX_EDIT]
                self.input_caret = min(len(self.input_text), self.input_caret + len(typed))
                if play_sfx is not None:
                    play_sfx("sfx_ui_typeclick_01" if (int(rand()) & 1) == 0 else "sfx_ui_typeclick_02")
            if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
                if self.input_caret > 0:
                    self.input_text = self.input_text[: self.input_caret - 1] + self.input_text[self.input_caret :]
                    self.input_caret -= 1
                    if play_sfx is not None:
                        play_sfx("sfx_ui_typeclick_01" if (int(rand()) & 1) == 0 else "sfx_ui_typeclick_02")
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
            _panel, panel_left, panel_top = self._panel_layout(screen_w=screen_w, scale=scale)
            anchor_x = panel_left + 40.0 * scale
            input_y = panel_top + 150.0 * scale
            ok_x = anchor_x + 170.0 * scale
            ok_y = input_y - 8.0 * scale
            ok_w = button_width(self.font, self._ok_button.label, scale=scale, force_wide=self._ok_button.force_wide)
            ok_clicked = button_update(self._ok_button, x=ok_x, y=ok_y, width=ok_w, dt_ms=dt_ms, mouse=mouse, click=click)

            if ok_clicked or rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
                if self.input_text.strip():
                    if play_sfx is not None:
                        play_sfx("sfx_ui_typeenter")
                    if (not self._saved) and self._scores_path is not None:
                        candidate = self.record.copy()
                        candidate.set_name(self.input_text)
                        try:
                            _table, idx = upsert_highscore_record(self._scores_path, candidate)
                            self.highlight_rank = int(idx) if int(idx) < TABLE_MAX else None
                            if int(idx) < TABLE_MAX:
                                self.rank = int(idx)
                        except Exception:
                            self.highlight_rank = None
                        self._saved = True
                    self.phase = 2
                    return None
                if play_sfx is not None:
                    play_sfx("sfx_shock_hit_01")
            return None

        if self.phase == 2:
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
                if play_sfx is not None:
                    play_sfx("sfx_ui_buttonclick")
                self._begin_close_transition("play_again")
                return None
            if rl.is_key_pressed(rl.KeyboardKey.KEY_N):
                if play_sfx is not None:
                    play_sfx("sfx_ui_buttonclick")
                self._begin_close_transition("play_next")
                return None
            if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
                if play_sfx is not None:
                    play_sfx("sfx_ui_buttonclick")
                self._begin_close_transition("high_scores")
                return None

            screen_w = float(rl.get_screen_width())
            screen_h = float(rl.get_screen_height())
            scale = ui_scale(screen_w, screen_h)
            _origin_x, _origin_y = ui_origin(screen_w, screen_h, scale)
            _panel, left, top = self._panel_layout(screen_w=screen_w, scale=scale)
            qualifies = int(self.rank) < TABLE_MAX
            score_card_x = left + 70.0 * scale

            var_c_12 = top + (96.0 if qualifies else 108.0) * scale
            var_c_14 = var_c_12 + 84.0 * scale
            if self.unlock_weapon_name:
                var_c_14 += 30.0 * scale
            if self.unlock_perk_name:
                var_c_14 += 30.0 * scale

            button_x = score_card_x + 20.0 * scale
            button_y = var_c_14 + 6.0 * scale

            play_next_w = button_width(self.font, self._play_next_button.label, scale=scale, force_wide=self._play_next_button.force_wide)
            if button_update(self._play_next_button, x=button_x, y=button_y, width=play_next_w, dt_ms=dt_ms, mouse=mouse, click=click):
                if play_sfx is not None:
                    play_sfx("sfx_ui_buttonclick")
                self._begin_close_transition("play_next")
                return None
            button_y += 32.0 * scale

            play_again_w = button_width(self.font, self._play_again_button.label, scale=scale, force_wide=self._play_again_button.force_wide)
            if button_update(self._play_again_button, x=button_x, y=button_y, width=play_again_w, dt_ms=dt_ms, mouse=mouse, click=click):
                if play_sfx is not None:
                    play_sfx("sfx_ui_buttonclick")
                self._begin_close_transition("play_again")
                return None
            button_y += 32.0 * scale

            high_scores_w = button_width(self.font, self._high_scores_button.label, scale=scale, force_wide=self._high_scores_button.force_wide)
            if button_update(self._high_scores_button, x=button_x, y=button_y, width=high_scores_w, dt_ms=dt_ms, mouse=mouse, click=click):
                if play_sfx is not None:
                    play_sfx("sfx_ui_buttonclick")
                self._begin_close_transition("high_scores")
                return None
            button_y += 32.0 * scale

            main_menu_w = button_width(self.font, self._main_menu_button.label, scale=scale, force_wide=self._main_menu_button.force_wide)
            if button_update(self._main_menu_button, x=button_x, y=button_y, width=main_menu_w, dt_ms=dt_ms, mouse=mouse, click=click):
                if play_sfx is not None:
                    play_sfx("sfx_ui_buttonclick")
                self._begin_close_transition("main_menu")
                return None
            return None

        return None

    def draw(self, *, mouse: rl.Vector2 | None = None) -> None:
        if self.assets is None or self.record is None or self.breakdown is None:
            return
        if mouse is None:
            mouse = rl.get_mouse_position()

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        scale = ui_scale(screen_w, screen_h)
        _origin_x, _origin_y = ui_origin(screen_w, screen_h, scale)
        _ = _origin_x, _origin_y

        panel, left, top = self._panel_layout(screen_w=screen_w, scale=scale)

        if self.assets.menu_panel is not None:
            fx_detail = bool(int(self.config.data.get("fx_detail_0", 0) or 0))
            draw_classic_menu_panel(self.assets.menu_panel, dst=panel, tint=rl.WHITE, shadow=fx_detail)

        banner_x = left + 22.0 * scale
        banner_y = top + 36.0 * scale
        if self.assets.text_well_done is not None:
            src = rl.Rectangle(0.0, 0.0, float(self.assets.text_well_done.width), float(self.assets.text_well_done.height))
            dst = rl.Rectangle(banner_x, banner_y, TEXTURE_TOP_BANNER_W * scale, TEXTURE_TOP_BANNER_H * scale)
            rl.draw_texture_pro(self.assets.text_well_done, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        qualifies = int(self.rank) < TABLE_MAX

        if self.phase == 0:
            anchor_x = left + 40.0 * scale
            label_x = anchor_x + 32.0 * scale
            value_x = label_x + 132.0 * scale

            anim = self._breakdown_anim
            step = 4
            highlight_alpha = 1.0
            base_time_ms = int(self.breakdown.base_time_ms)
            life_bonus_ms = int(self.breakdown.life_bonus_ms)
            perk_bonus_ms = int(self.breakdown.unpicked_perk_bonus_ms)
            final_time_ms = int(self.breakdown.final_time_ms)
            if anim is not None and not anim.done:
                step = int(anim.step)
                highlight_alpha = float(anim.highlight_alpha())
                base_time_ms = int(anim.base_time_ms)
                life_bonus_ms = int(anim.life_bonus_ms)
                perk_bonus_ms = int(anim.unpicked_perk_bonus_s) * 1000
                final_time_ms = int(anim.final_time_ms)

            def _row_color(idx: int, *, final: bool = False) -> rl.Color:
                if anim is None or anim.done:
                    return COLOR_TEXT
                alpha = 0.2
                if idx < step:
                    alpha = 0.4
                elif idx == step:
                    alpha = 1.0
                    if final:
                        alpha *= highlight_alpha
                rgb = (255, 255, 255)
                if idx == step:
                    rgb = (COLOR_GREEN.r, COLOR_GREEN.g, COLOR_GREEN.b)
                return rl.Color(rgb[0], rgb[1], rgb[2], int(255 * max(0.0, min(1.0, alpha))))

            y = top + 156.0 * scale
            base_value = _format_time_mm_ss(base_time_ms)
            life_value = _format_time_mm_ss(life_bonus_ms)
            perk_value = _format_time_mm_ss(perk_bonus_ms)
            final_value = _format_time_mm_ss(final_time_ms)

            self._draw_small("Base Time:", label_x, y, 1.0 * scale, _row_color(0))
            self._draw_small(base_value, value_x, y, 1.0 * scale, _row_color(0))
            y += 20.0 * scale

            self._draw_small("Life Bonus:", label_x, y, 1.0 * scale, _row_color(1))
            self._draw_small(life_value, value_x, y, 1.0 * scale, _row_color(1))
            y += 20.0 * scale

            self._draw_small("Unpicked Perk Bonus:", label_x, y, 1.0 * scale, _row_color(2))
            self._draw_small(perk_value, value_x, y, 1.0 * scale, _row_color(2))
            y += 20.0 * scale

            # Final time underline + row (matches the extra quad draw in native).
            line_y = y + 1.0 * scale
            line_color = rl.Color(255, 255, 255, _row_color(3, final=True).a)
            rl.draw_rectangle(int(label_x - 4.0 * scale), int(line_y), int(168.0 * scale), int(1.0 * scale), line_color)

            y += 8.0 * scale
            self._draw_small("Final Time:", label_x, y, 1.0 * scale, _row_color(3, final=True))
            self._draw_small(final_value, value_x, y, 1.0 * scale, _row_color(3, final=True))

        elif self.phase == 1:
            anchor_x = left + 40.0 * scale
            text_y = top + 118.0 * scale
            self._draw_small("State your name trooper!", anchor_x + 42.0 * scale, text_y, 1.0 * scale, COLOR_TEXT)

            input_x = anchor_x
            input_y = top + 150.0 * scale
            rl.draw_rectangle_lines(int(input_x), int(input_y), int(INPUT_BOX_W * scale), int(INPUT_BOX_H * scale), rl.WHITE)
            rl.draw_rectangle(
                int(input_x + 1.0 * scale),
                int(input_y + 1.0 * scale),
                int((INPUT_BOX_W - 2.0) * scale),
                int((INPUT_BOX_H - 2.0) * scale),
                rl.Color(0, 0, 0, 255),
            )
            draw_ui_text(self.font, self.input_text, input_x + 4.0 * scale, input_y + 2.0 * scale, scale=1.0 * scale, color=COLOR_TEXT_MUTED)
            caret_alpha = 1.0
            if math.sin(float(rl.get_time()) * 4.0) > 0.0:
                caret_alpha = 0.4
            caret_color = rl.Color(255, 255, 255, int(255 * caret_alpha))
            caret_x = input_x + 4.0 * scale + self._text_width(self.input_text[: self.input_caret], 1.0 * scale)
            rl.draw_rectangle(int(caret_x), int(input_y + 2.0 * scale), int(1.0 * scale), int(14.0 * scale), caret_color)

            ok_x = anchor_x + 170.0 * scale
            ok_y = input_y - 8.0 * scale
            ok_w = button_width(self.font, self._ok_button.label, scale=scale, force_wide=self._ok_button.force_wide)
            button_draw(self.assets.perk_menu_assets, self.font, self._ok_button, x=ok_x, y=ok_y, width=ok_w, scale=scale)

        else:
            score_card_x = left + 70.0 * scale
            var_c_12 = top + (96.0 if qualifies else 108.0) * scale
            if (not qualifies) and self.font is not None:
                self._draw_small(
                    "Score too low for top100.",
                    score_card_x + 8.0 * scale,
                    top + 102.0 * scale,
                    1.0 * scale,
                    rl.Color(200, 200, 200, 255),
                )

            seconds = float(int(self.record.survival_elapsed_ms)) * 0.001
            score_value = f"{seconds:.2f} secs"
            xp_value = f"{int(self.record.score_xp)}"
            rank_text = _format_ordinal(int(self.rank) + 1) if qualifies else "--"

            col_label = rl.Color(230, 230, 230, 255)
            col_value = rl.Color(230, 230, 255, 255)
            card_y = var_c_12 + 16.0 * scale
            self._draw_small("Score", score_card_x + 32.0 * scale, card_y, 1.0 * scale, col_label)
            self._draw_small(score_value, score_card_x + 32.0 * scale, card_y + 15.0 * scale, 1.0 * scale, col_value)
            self._draw_small(f"Rank: {rank_text}", score_card_x + 32.0 * scale, card_y + 30.0 * scale, 1.0 * scale, col_label)
            self._draw_small("Experience", score_card_x + 140.0 * scale, card_y, 1.0 * scale, col_label)
            self._draw_small(xp_value, score_card_x + 140.0 * scale, card_y + 15.0 * scale, 1.0 * scale, col_value)

            # Unlock lines (their presence shifts the buttons down in native).
            var_c_14 = var_c_12 + 84.0 * scale
            if self.unlock_weapon_name:
                self._draw_small("Weapon unlocked:", score_card_x, var_c_14 + 1.0 * scale, 1.0 * scale, COLOR_TEXT_SUBTLE)
                self._draw_small(self.unlock_weapon_name, score_card_x, var_c_14 + 14.0 * scale, 1.0 * scale, COLOR_TEXT)
                var_c_14 += 30.0 * scale
            if self.unlock_perk_name:
                self._draw_small("Perk unlocked:", score_card_x, var_c_14 + 1.0 * scale, 1.0 * scale, COLOR_TEXT_SUBTLE)
                self._draw_small(self.unlock_perk_name, score_card_x, var_c_14 + 14.0 * scale, 1.0 * scale, COLOR_TEXT)
                var_c_14 += 30.0 * scale

            # Buttons
            button_x = score_card_x + 20.0 * scale
            button_y = var_c_14 + 6.0 * scale
            play_next_w = button_width(self.font, self._play_next_button.label, scale=scale, force_wide=self._play_next_button.force_wide)
            button_draw(self.assets.perk_menu_assets, self.font, self._play_next_button, x=button_x, y=button_y, width=play_next_w, scale=scale)
            button_y += 32.0 * scale
            play_again_w = button_width(self.font, self._play_again_button.label, scale=scale, force_wide=self._play_again_button.force_wide)
            button_draw(self.assets.perk_menu_assets, self.font, self._play_again_button, x=button_x, y=button_y, width=play_again_w, scale=scale)
            button_y += 32.0 * scale
            high_scores_w = button_width(self.font, self._high_scores_button.label, scale=scale, force_wide=self._high_scores_button.force_wide)
            button_draw(self.assets.perk_menu_assets, self.font, self._high_scores_button, x=button_x, y=button_y, width=high_scores_w, scale=scale)
            button_y += 32.0 * scale
            main_menu_w = button_width(self.font, self._main_menu_button.label, scale=scale, force_wide=self._main_menu_button.force_wide)
            button_draw(self.assets.perk_menu_assets, self.font, self._main_menu_button, x=button_x, y=button_y, width=main_menu_w, scale=scale)

        cursor_draw(self.assets.perk_menu_assets, mouse=mouse, scale=scale)
