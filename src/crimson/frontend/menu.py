from __future__ import annotations

from dataclasses import dataclass
import math
import os
from typing import Protocol

import pyray as rl

from grim.audio import play_music, play_sfx, stop_music, update_audio
from grim.geom import Rect, Vec2
from grim.terrain_render import GroundRenderer

from ..terrain_assets import terrain_texture_by_id
from ..ui.cursor import draw_menu_cursor
from ..ui.shadow import UI_SHADOW_OFFSET, UI_SHADOW_TINT, draw_ui_quad_shadow  # noqa: F401
from .assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from .transitions import _draw_screen_fade

from .types import GameState


MENU_LABEL_WIDTH = 122.0
MENU_LABEL_HEIGHT = 28.0
MENU_LABEL_ROW_HEIGHT = 32.0
MENU_LABEL_ROW_PLAY_GAME = 1
MENU_LABEL_ROW_OPTIONS = 2
MENU_LABEL_ROW_STATISTICS = 3
MENU_LABEL_ROW_MODS = 4
MENU_LABEL_ROW_OTHER_GAMES = 5
MENU_LABEL_ROW_QUIT = 6
MENU_LABEL_ROW_BACK = 7
MENU_LABEL_BASE_X = -60.0
MENU_LABEL_BASE_Y = 210.0
MENU_LABEL_OFFSET_X = 271.0
MENU_LABEL_OFFSET_Y = -37.0
MENU_LABEL_STEP = 60.0
MENU_ITEM_OFFSET_X = -71.0
MENU_ITEM_OFFSET_Y = -59.0
MENU_PANEL_WIDTH = 510.0
MENU_PANEL_HEIGHT = 254.0
# Measured from ui_render_trace at 1024x768 (stable timeline):
# panel top-left is (pos_x + 21, pos_y - 81) and size is 510x254, plus a shadow pass at +7,+7.
MENU_PANEL_OFFSET_X = 21.0
MENU_PANEL_OFFSET_Y = -81.0
MENU_PANEL_BASE_X = -45.0
MENU_PANEL_BASE_Y = 210.0
MENU_SCALE_SMALL_THRESHOLD = 640
MENU_SCALE_LARGE_MIN = 801
MENU_SCALE_LARGE_MAX = 1024
MENU_SCALE_SMALL = 0.8
MENU_SCALE_LARGE = 1.2
MENU_SCALE_SHIFT = 10.0

MENU_SIGN_WIDTH = 571.44
MENU_SIGN_HEIGHT = 141.36
MENU_SIGN_OFFSET_X = -576.44
MENU_SIGN_OFFSET_Y = -61.0
MENU_SIGN_POS_Y = 70.0
MENU_SIGN_POS_Y_SMALL = 60.0
MENU_SIGN_POS_X_PAD = 4.0

# Measured in the shareware/demo attract loop trace:
# {"event":"demo_mode_start","dt_since_start_ms":23024,"game_state_id":0,"demo_mode_active":0,...}
MENU_DEMO_IDLE_START_MS = 23_000
MENU_DEFAULT_TERRAIN_IDS = (0, 1, 0)
MENU_UNLOCK_TERRAIN_RULES: tuple[tuple[int, tuple[int, int, int]], ...] = (
    (0x28, (6, 7, 6)),
    (0x1E, (4, 5, 4)),
    (0x14, (2, 3, 2)),
)


class _TimelineView(Protocol):
    _timeline_ms: int


def menu_ground_camera(state: GameState) -> Vec2:
    camera = state.menu_ground_camera
    if isinstance(camera, Vec2):
        return camera
    return Vec2()


def _menu_unlock_index(state: GameState) -> int:
    status = state.status
    if status is None:
        return 0
    try:
        return int(status.quest_unlock_index)
    except (TypeError, ValueError):
        return 0


def _choose_menu_terrain_ids(state: GameState) -> tuple[int, int, int]:
    unlock_index = _menu_unlock_index(state)
    for threshold, ids in MENU_UNLOCK_TERRAIN_RULES:
        if unlock_index >= threshold and (state.rng.randrange(0, 8) & 7) == 3:
            return ids
    return MENU_DEFAULT_TERRAIN_IDS


def _menu_terrain_texture(state: GameState, terrain_id: int) -> rl.Texture | None:
    cache = state.texture_cache
    if cache is None:
        return None
    terrain = terrain_texture_by_id(int(terrain_id))
    if terrain is None:
        return None

    key, rel_path = terrain
    texture = cache.texture(key)
    if texture is not None:
        return texture
    return cache.get_or_load(key, rel_path).texture


def ensure_menu_ground(state: GameState, *, regenerate: bool = False) -> GroundRenderer | None:
    cache = state.texture_cache
    if cache is None:
        return None

    ground = state.menu_ground
    screen_width = float(state.config.screen_width)
    screen_height = float(state.config.screen_height)
    texture_scale = state.config.texture_scale
    explicit_regenerate = bool(regenerate)
    should_select_layers = ground is None or explicit_regenerate
    scale_changed = False
    if ground is not None:
        scale_changed = abs(float(ground.texture_scale) - texture_scale) > 1e-6

    base: rl.Texture | None = ground.texture if ground is not None else None
    overlay: rl.Texture | None = ground.overlay if ground is not None else None
    detail: rl.Texture | None = ground.overlay_detail if ground is not None else None

    if should_select_layers:
        base_id, overlay_id, detail_id = _choose_menu_terrain_ids(state)
        selected_base = _menu_terrain_texture(state, base_id)
        if selected_base is None and (base_id, overlay_id, detail_id) != MENU_DEFAULT_TERRAIN_IDS:
            base_id, overlay_id, detail_id = MENU_DEFAULT_TERRAIN_IDS
            selected_base = _menu_terrain_texture(state, base_id)
        if selected_base is not None:
            base = selected_base
            overlay = _menu_terrain_texture(state, overlay_id)
            detail = _menu_terrain_texture(state, detail_id)

    if ground is None:
        if base is None:
            return None
        if detail is None:
            detail = overlay or base
        ground = GroundRenderer(
            texture=base,
            overlay=overlay,
            overlay_detail=detail,
            width=1024,
            height=1024,
            texture_scale=texture_scale,
            screen_width=screen_width,
            screen_height=screen_height,
        )
        state.menu_ground = ground
        regenerate = True
    else:
        if base is not None:
            ground.texture = base
        ground.overlay = overlay
        ground.overlay_detail = detail or overlay or ground.texture
        ground.texture_scale = texture_scale
        ground.screen_width = screen_width
        ground.screen_height = screen_height
        if scale_changed:
            regenerate = True
    if regenerate:
        ground.schedule_generate(seed=state.rng.randrange(0, 10_000), layers=3)
        state.menu_ground_camera = None
    return ground


def _draw_menu_cursor(state: GameState, *, pulse_time: float) -> None:
    cache = _ensure_texture_cache(state)
    particles = cache.get_or_load("particles", "game/particles.jaz").texture
    cursor_tex = cache.get_or_load("ui_cursor", "ui/ui_cursor.jaz").texture

    mouse = rl.get_mouse_position()
    draw_menu_cursor(particles, cursor_tex, pos=Vec2.from_xy(mouse), pulse_time=float(pulse_time))


@dataclass(slots=True)
class MenuEntry:
    slot: int
    row: int
    y: float
    hover_amount: int = 0
    ready_timer_ms: int = 0x100


class MenuView:
    def __init__(self, state: GameState) -> None:
        self.state = state
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._menu_entries: list[MenuEntry] = []
        self._selected_index = 0
        self._focus_timer_ms = 0
        self._hovered_index: int | None = None
        self._full_version = False
        self._timeline_ms = 0
        self._timeline_max_ms = 0
        self._idle_ms = 0
        self._last_mouse_pos = Vec2()
        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._menu_screen_width = 0
        self._closing = False
        self._close_action: str | None = None
        self._pending_action: str | None = None
        self._panel_open_sfx_played = False

    def open(self) -> None:
        layout_w = float(self.state.config.screen_width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = self._menu_widescreen_y_shift(layout_w)
        self._assets = load_menu_assets(self.state)
        # Shareware gating is controlled by the --demo flag (see GameState.demo_enabled),
        # not by a persisted config byte.
        self._full_version = not self.state.demo_enabled
        self._menu_entries = self._menu_entries_for_flags(
            full_version=self._full_version,
            mods_available=self._mods_available(),
            other_games=self._other_games_enabled(),
        )
        self._selected_index = 0 if self._menu_entries else -1
        self._focus_timer_ms = 0
        self._hovered_index = None
        self._timeline_ms = 0
        self._idle_ms = 0
        self._cursor_pulse_time = 0.0
        mouse = rl.get_mouse_position()
        self._last_mouse_pos = Vec2.from_xy(mouse)
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._panel_open_sfx_played = False
        self._timeline_max_ms = self._menu_max_timeline_ms(
            full_version=self._full_version,
            mods_available=self._mods_available(),
            other_games=self._other_games_enabled(),
        )
        self._init_ground()
        if self.state.audio is not None:
            theme = "crimsonquest" if self.state.demo_enabled else "crimson_theme"
            if self.state.audio.music.active_track != theme:
                stop_music(self.state.audio)
            play_music(self.state.audio, theme)

    def close(self) -> None:
        self._ground = None

    def update(self, dt: float) -> None:
        if self.state.audio is not None:
            if not self._closing:
                theme = "crimsonquest" if self.state.demo_enabled else "crimson_theme"
                play_music(self.state.audio, theme)
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1
        dt_ms = int(min(dt, 0.1) * 1000.0)
        if self._closing:
            if dt_ms > 0 and self._pending_action is None:
                self._timeline_ms -= dt_ms
                self._focus_timer_ms = max(0, self._focus_timer_ms - dt_ms)
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._pending_action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            mouse = rl.get_mouse_position()
            mouse_pos = Vec2.from_xy(mouse)
            mouse_moved = mouse_pos != self._last_mouse_pos
            if mouse_moved:
                self._last_mouse_pos = mouse_pos

            any_key = rl.get_key_pressed() != 0
            any_click = (
                rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
                or rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_RIGHT)
                or rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_MIDDLE)
            )

            if any_key or any_click or mouse_moved:
                self._idle_ms = 0
            else:
                self._idle_ms += dt_ms

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, self._timeline_ms + dt_ms)
            self._focus_timer_ms = max(0, self._focus_timer_ms - dt_ms)
            if self._timeline_ms >= self._timeline_max_ms:
                self.state.menu_sign_locked = True
                if (not self._panel_open_sfx_played) and (self.state.audio is not None):
                    play_sfx(self.state.audio, "sfx_ui_panelclick", rng=self.state.rng)
                    self._panel_open_sfx_played = True
        if not self._menu_entries:
            return

        self._hovered_index = self._hovered_entry_index()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            reverse = rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT)
            delta = -1 if reverse else 1
            self._selected_index = (self._selected_index + delta) % len(self._menu_entries)
            self._focus_timer_ms = 1000

        activated_index: int | None = None
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) and 0 <= self._selected_index < len(self._menu_entries):
            entry = self._menu_entries[self._selected_index]
            if self._menu_entry_enabled(entry):
                activated_index = self._selected_index

        if activated_index is None and self._hovered_index is not None:
            if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
                hovered = self._hovered_index
                entry = self._menu_entries[hovered]
                if self._menu_entry_enabled(entry):
                    self._selected_index = hovered
                    self._focus_timer_ms = 1000
                    activated_index = hovered

        if activated_index is not None:
            self._activate_menu_entry(activated_index)
        if (
            (not self._closing)
            and self._pending_action is None
            and self.state.demo_enabled
            and self._timeline_ms >= self._timeline_max_ms
            and self._idle_ms >= MENU_DEMO_IDLE_START_MS
        ):
            self._begin_close_transition("start_demo")
        self._update_ready_timers(dt_ms)
        self._update_hover_amounts(dt_ms)

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(menu_ground_camera(self.state))
        _draw_screen_fade(self.state)
        assets = self._assets
        if assets is None:
            return
        self._draw_menu_items()
        self._draw_menu_sign()
        _draw_menu_cursor(self.state, pulse_time=self._cursor_pulse_time)

    def take_action(self) -> str | None:
        action = self._pending_action
        self._pending_action = None
        return action

    def _activate_menu_entry(self, index: int) -> None:
        if not (0 <= index < len(self._menu_entries)):
            return
        entry = self._menu_entries[index]
        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
        self.state.console.log.log(f"menu select: {index} (row {entry.row})")
        self.state.console.log.flush()
        if entry.row == MENU_LABEL_ROW_QUIT:
            self._begin_quit_transition()
        elif entry.row == MENU_LABEL_ROW_PLAY_GAME:
            self._begin_close_transition("open_play_game")
        elif entry.row == MENU_LABEL_ROW_OPTIONS:
            self._begin_close_transition("open_options")
        elif entry.row == MENU_LABEL_ROW_STATISTICS:
            self._begin_close_transition("open_statistics")
        elif entry.row == MENU_LABEL_ROW_MODS:
            self._begin_close_transition("open_mods")
        elif entry.row == MENU_LABEL_ROW_OTHER_GAMES:
            self._begin_close_transition("open_other_games")

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

    def _begin_quit_transition(self) -> None:
        self.state.menu_sign_locked = False
        self._begin_close_transition("quit_after_demo" if self.state.demo_enabled else "quit_app")

    def _init_ground(self) -> None:
        self._ground = ensure_menu_ground(self.state)

    def _menu_entries_for_flags(
        self,
        full_version: bool,
        mods_available: bool,
        other_games: bool,
    ) -> list[MenuEntry]:
        rows = self._menu_label_rows(full_version, other_games)
        slot_ys = self._menu_slot_ys(other_games, self._widescreen_y_shift)
        active = self._menu_slot_active(full_version, mods_available, other_games)
        entries: list[MenuEntry] = []
        for slot, (row, y, enabled) in enumerate(zip(rows, slot_ys, active, strict=False)):
            if not enabled:
                continue
            entries.append(MenuEntry(slot=slot, row=row, y=y))
        return entries

    @staticmethod
    def _menu_label_rows(_full_version: bool, other_games: bool) -> list[int]:
        # Label atlas rows in ui_itemTexts.jaz:
        #   0 BUY NOW (unused in rewrite), 1 PLAY GAME, 2 OPTIONS, 3 STATISTICS, 4 MODS,
        #   5 OTHER GAMES, 6 QUIT, 7 BACK
        top = 4
        if other_games:
            return [top, 1, 2, 3, 5, 6]
        # ui_menu_layout_init swaps table idx 6/7 depending on config var 100:
        # when empty, QUIT becomes idx 6 and the idx 7 element is inactive.
        return [top, 1, 2, 3, 6, 7]

    @staticmethod
    def _menu_slot_ys(_other_games: bool, y_shift: float) -> list[float]:
        ys = [
            MENU_LABEL_BASE_Y,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 2.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 3.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 4.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 5.0,
        ]
        return [y + y_shift for y in ys]

    @staticmethod
    def _menu_slot_active(
        _full_version: bool,
        mods_available: bool,
        other_games: bool,
    ) -> list[bool]:
        show_top = mods_available
        if other_games:
            return [show_top, True, True, True, True, True]
        return [show_top, True, True, True, True, False]

    def _draw_menu_items(self) -> None:
        assets = self._assets
        if assets is None or assets.labels is None or not self._menu_entries:
            return
        item = assets.item
        if item is None:
            return
        label_tex = assets.labels
        item_w = float(item.width)
        item_h = float(item.height)
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        # Matches ui_elements_update_and_render reverse table iteration:
        # later entries draw first, earlier entries draw last (on top).
        for idx in range(len(self._menu_entries) - 1, -1, -1):
            entry = self._menu_entries[idx]
            pos = Vec2(self._menu_slot_pos_x(entry.slot), entry.y)
            angle_rad, slide_x = self._ui_element_anim(
                index=entry.slot + 2,
                start_ms=self._menu_slot_start_ms(entry.slot),
                end_ms=self._menu_slot_end_ms(entry.slot),
                width=item_w,
            )
            _ = slide_x  # slide is ignored for render_mode==0 (transform) elements
            item_scale, local_y_shift = self._menu_item_scale(entry.slot)
            offset_x = MENU_ITEM_OFFSET_X * item_scale
            offset_y = MENU_ITEM_OFFSET_Y * item_scale - local_y_shift
            dst = rl.Rectangle(
                pos.x,
                pos.y,
                item_w * item_scale,
                item_h * item_scale,
            )
            origin = rl.Vector2(-offset_x, -offset_y)
            rotation_deg = math.degrees(angle_rad)
            if fx_detail:
                self._draw_ui_quad_shadow(
                    texture=item,
                    src=rl.Rectangle(0.0, 0.0, item_w, item_h),
                    dst=rl.Rectangle(dst.x + UI_SHADOW_OFFSET, dst.y + UI_SHADOW_OFFSET, dst.width, dst.height),
                    origin=origin,
                    rotation_deg=rotation_deg,
                )
            self._draw_ui_quad(
                texture=item,
                src=rl.Rectangle(0.0, 0.0, item_w, item_h),
                dst=dst,
                origin=origin,
                rotation_deg=rotation_deg,
                tint=rl.WHITE,
            )
            counter_value = entry.hover_amount
            if idx == self._selected_index and self._focus_timer_ms > 0:
                counter_value = self._focus_timer_ms
            alpha = self._label_alpha(counter_value)
            tint = rl.Color(255, 255, 255, alpha)
            src = rl.Rectangle(
                0.0,
                float(entry.row) * MENU_LABEL_ROW_HEIGHT,
                MENU_LABEL_WIDTH,
                MENU_LABEL_ROW_HEIGHT,
            )
            label_offset_x = MENU_LABEL_OFFSET_X * item_scale
            label_offset_y = MENU_LABEL_OFFSET_Y * item_scale - local_y_shift
            label_dst = rl.Rectangle(
                pos.x,
                pos.y,
                MENU_LABEL_WIDTH * item_scale,
                MENU_LABEL_HEIGHT * item_scale,
            )
            label_origin = rl.Vector2(-label_offset_x, -label_offset_y)
            self._draw_ui_quad(
                texture=label_tex,
                src=src,
                dst=label_dst,
                origin=label_origin,
                rotation_deg=rotation_deg,
                tint=tint,
            )
            if self._menu_entry_enabled(entry):
                glow_alpha = alpha
                if 0 <= entry.ready_timer_ms < 0x100:
                    glow_alpha = 0xFF - (entry.ready_timer_ms // 2)
                rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
                self._draw_ui_quad(
                    texture=label_tex,
                    src=src,
                    dst=label_dst,
                    origin=label_origin,
                    rotation_deg=rotation_deg,
                    tint=rl.Color(255, 255, 255, glow_alpha),
                )
                rl.end_blend_mode()

    def _mods_available(self) -> bool:
        mods_dir = self.state.base_dir / "mods"
        if not mods_dir.exists():
            return False
        return any(mods_dir.glob("*.dll"))

    def _other_games_enabled(self) -> bool:
        # Original game checks a config string via grim_get_config_var(100).
        # Our config-var system is not implemented yet; allow a simple env opt-in.
        return os.getenv("CRIMSON_GRIM_CONFIG_VAR_100", "").strip() != ""

    def _hovered_entry_index(self) -> int | None:
        if not self._menu_entries:
            return None
        mouse = rl.get_mouse_position()
        mouse_pos = Vec2.from_xy(mouse)
        for idx, entry in enumerate(self._menu_entries):
            if not self._menu_entry_enabled(entry):
                continue
            if self._menu_item_bounds(entry).contains(mouse_pos):
                return idx
        return None

    def _update_ready_timers(self, dt_ms: int) -> None:
        for entry in self._menu_entries:
            if entry.ready_timer_ms < 0x100:
                entry.ready_timer_ms = min(0x100, entry.ready_timer_ms + dt_ms)

    def _update_hover_amounts(self, dt_ms: int) -> None:
        hovered_index = self._hovered_index
        for idx, entry in enumerate(self._menu_entries):
            hover = hovered_index is not None and idx == hovered_index
            if hover:
                entry.hover_amount += dt_ms * 6
            else:
                entry.hover_amount -= dt_ms * 2
            entry.hover_amount = max(0, min(1000, entry.hover_amount))

    @staticmethod
    def _label_alpha(counter_value: int) -> int:
        # ui_element_render: alpha = 100 + floor(counter_value * 155 / 1000)
        return 100 + (counter_value * 155) // 1000

    def _menu_entry_enabled(self, entry: MenuEntry) -> bool:
        return self._timeline_ms >= self._menu_slot_start_ms(entry.slot)

    @staticmethod
    def _menu_widescreen_y_shift(screen_w: float) -> float:
        # ((screen_width / 640.0) * 150.0) - 150.0
        return (screen_w * 0.0015625 * 150.0) - 150.0

    def _menu_item_scale(self, slot: int) -> tuple[float, float]:
        if self._menu_screen_width < 641:
            return 0.9, float(slot) * 11.0
        return 1.0, 0.0

    def _menu_item_bounds(self, entry: MenuEntry) -> Rect:
        # FUN_0044fb50: inset bounds derived from quad0 v0/v2 and pos_x/pos_y.
        assets = self._assets
        if assets is None or assets.item is None:
            return Rect()
        item_w = float(assets.item.width)
        item_h = float(assets.item.height)
        item_scale, local_y_shift = self._menu_item_scale(entry.slot)
        offset_min = Vec2(
            MENU_ITEM_OFFSET_X * item_scale,
            MENU_ITEM_OFFSET_Y * item_scale - local_y_shift,
        )
        offset_max = Vec2(
            (MENU_ITEM_OFFSET_X + item_w) * item_scale,
            (MENU_ITEM_OFFSET_Y + item_h) * item_scale - local_y_shift,
        )
        size = offset_max - offset_min
        pos = Vec2(self._menu_slot_pos_x(entry.slot), entry.y)
        top_left = pos + Vec2(offset_min.x + size.x * 0.54, offset_min.y + size.y * 0.28)
        bottom_right = pos + Vec2(offset_max.x - size.x * 0.05, offset_max.y - size.y * 0.10)
        return Rect.from_pos_size(top_left, bottom_right - top_left)

    @staticmethod
    def _menu_slot_pos_x(slot: int) -> float:
        # ui_menu_layout_init: subtract 20, 40, ... from later menu items
        return MENU_LABEL_BASE_X - float(slot * 20)

    @staticmethod
    def _menu_slot_start_ms(slot: int) -> int:
        # ui_menu_layout_init: start_time_ms is the fully-visible time.
        return (slot + 2) * 100 + 300

    @classmethod
    def _menu_slot_end_ms(cls, slot: int) -> int:
        # ui_menu_layout_init: end_time_ms is the fully-hidden time.
        return (slot + 2) * 100

    @staticmethod
    def _menu_max_timeline_ms(full_version: bool, mods_available: bool, other_games: bool) -> int:
        del full_version
        max_ms = 300  # sign element at index 0
        show_top = mods_available
        slot_active = [show_top, True, True, True, True, other_games]
        for slot, active in enumerate(slot_active):
            if not active:
                continue
            max_ms = max(max_ms, (slot + 2) * 100 + 300)
        return max_ms

    def _ui_element_anim(
        self: _TimelineView,
        *,
        index: int,
        start_ms: int,
        end_ms: int,
        width: float,
        direction_flag: int = 0,
    ) -> tuple[float, float]:
        # Matches ui_element_update: angle lerps pi/2 -> 0 over [end_ms, start_ms].
        # direction_flag=0 slides from left  (-width -> 0)
        # direction_flag=1 slides from right (+width -> 0)
        if start_ms <= end_ms or width <= 0.0:
            return 0.0, 0.0
        dir_sign = 1.0 if int(direction_flag) else -1.0
        t = int(self._timeline_ms)
        if t < end_ms:
            angle = 1.5707964
            offset_x = dir_sign * abs(width)
        elif t < start_ms:
            elapsed = t - end_ms
            span = float(start_ms - end_ms)
            p = float(elapsed) / span
            angle = 1.5707964 * (1.0 - p)
            offset_x = dir_sign * ((1.0 - p) * abs(width))
        else:
            angle = 0.0
            offset_x = 0.0
        if index == 0:
            angle = -abs(angle)
        return angle, offset_x

    @staticmethod
    def _draw_ui_quad(
        *,
        texture: rl.Texture,
        src: rl.Rectangle,
        dst: rl.Rectangle,
        origin: rl.Vector2,
        rotation_deg: float,
        tint: rl.Color,
    ) -> None:
        rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)

    @staticmethod
    def _draw_ui_quad_shadow(
        *,
        texture: rl.Texture,
        src: rl.Rectangle,
        dst: rl.Rectangle,
        origin: rl.Vector2,
        rotation_deg: float,
    ) -> None:
        draw_ui_quad_shadow(texture=texture, src=src, dst=dst, origin=origin, rotation_deg=rotation_deg)

    def _draw_menu_sign(self) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
            return
        screen_w = float(self.state.config.screen_width)
        scale, shift_x = self._sign_layout_scale(int(screen_w))
        sign_pos = Vec2(
            screen_w + MENU_SIGN_POS_X_PAD,
            MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL,
        )
        sign_w = MENU_SIGN_WIDTH * scale
        sign_h = MENU_SIGN_HEIGHT * scale
        offset_x = MENU_SIGN_OFFSET_X * scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * scale
        rotation_deg = 0.0
        if not self.state.menu_sign_locked:
            angle_rad, slide_x = self._ui_element_anim(
                index=0,
                start_ms=300,
                end_ms=0,
                width=sign_w,
            )
            _ = slide_x  # slide is ignored for render_mode==0 (transform) elements
            rotation_deg = math.degrees(angle_rad)
        sign = assets.sign
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        if fx_detail:
            self._draw_ui_quad_shadow(
                texture=sign,
                src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
                dst=rl.Rectangle(sign_pos.x + UI_SHADOW_OFFSET, sign_pos.y + UI_SHADOW_OFFSET, sign_w, sign_h),
                origin=rl.Vector2(-offset_x, -offset_y),
                rotation_deg=rotation_deg,
            )
        self._draw_ui_quad(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(sign_pos.x, sign_pos.y, sign_w, sign_h),
            origin=rl.Vector2(-offset_x, -offset_y),
            rotation_deg=rotation_deg,
            tint=rl.WHITE,
        )

    @staticmethod
    def _sign_layout_scale(width: int) -> tuple[float, float]:
        if width <= MENU_SCALE_SMALL_THRESHOLD:
            return MENU_SCALE_SMALL, MENU_SCALE_SHIFT
        if MENU_SCALE_LARGE_MIN <= width <= MENU_SCALE_LARGE_MAX:
            return MENU_SCALE_LARGE, MENU_SCALE_SHIFT
        return 1.0, 0.0
