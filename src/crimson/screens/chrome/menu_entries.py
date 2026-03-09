from __future__ import annotations

from grim.assets import RuntimeResources, TextureId
from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ...game.types import GameState
from ..assets import require_runtime_resources
from .controls import MenuEntry, MenuEntryController, MenuListController, MenuListState
from .geometry import (
    MENU_ITEM_OFFSET_X,
    MENU_ITEM_OFFSET_Y,
    MENU_LABEL_HEIGHT,
    MENU_LABEL_OFFSET_X,
    MENU_LABEL_OFFSET_Y,
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_WIDTH,
    menu_item_scale,
    menu_slot_end_ms,
    menu_slot_pos_x,
    menu_slot_start_ms,
    ui_element_anim,
)
from .runtime import ChromeSpec, draw_ui_quad, draw_ui_quad_shadow
from .view import ChromeScreenView


def menu_entry_bounds(
    resources: RuntimeResources,
    *,
    screen_width: float,
    entry: MenuEntry,
    pos: Vec2,
    small_scale: float,
) -> Rect:
    item = resources.texture(TextureId.UI_MENU_ITEM)
    item_w = float(item.width)
    item_h = float(item.height)
    item_scale_value, local_y_shift = menu_item_scale(screen_width, int(entry.slot), small_scale=small_scale)
    offset_min = Vec2(
        MENU_ITEM_OFFSET_X * item_scale_value,
        MENU_ITEM_OFFSET_Y * item_scale_value - local_y_shift,
    )
    offset_max = Vec2(
        (MENU_ITEM_OFFSET_X + item_w) * item_scale_value,
        (MENU_ITEM_OFFSET_Y + item_h) * item_scale_value - local_y_shift,
    )
    size = offset_max - offset_min
    top_left = pos + Vec2(offset_min.x + size.x * 0.54, offset_min.y + size.y * 0.28)
    bottom_right = pos + Vec2(offset_max.x - size.x * 0.05, offset_max.y - size.y * 0.10)
    return Rect.from_pos_size(top_left, bottom_right - top_left)


def draw_menu_entry(
    resources: RuntimeResources,
    *,
    screen_width: float,
    entry: MenuEntry,
    pos: Vec2,
    small_scale: float,
    rotation_deg: float,
    label_alpha: int,
    glow_alpha: int | None,
    shadow_offset: float,
    fx_detail: bool,
) -> None:
    item = resources.texture(TextureId.UI_MENU_ITEM)
    label_tex = resources.texture(TextureId.UI_ITEM_TEXTS)
    item_w = float(item.width)
    item_h = float(item.height)
    item_scale_value, local_y_shift = menu_item_scale(screen_width, int(entry.slot), small_scale=small_scale)
    offset_x = MENU_ITEM_OFFSET_X * item_scale_value
    offset_y = MENU_ITEM_OFFSET_Y * item_scale_value - local_y_shift
    dst = rl.Rectangle(
        pos.x,
        pos.y,
        item_w * item_scale_value,
        item_h * item_scale_value,
    )
    origin = rl.Vector2(-offset_x, -offset_y)
    if fx_detail:
        draw_ui_quad_shadow(
            texture=item,
            src=rl.Rectangle(0.0, 0.0, item_w, item_h),
            dst=rl.Rectangle(dst.x + shadow_offset, dst.y + shadow_offset, dst.width, dst.height),
            origin=origin,
            rotation_deg=rotation_deg,
        )
    draw_ui_quad(
        texture=item,
        src=rl.Rectangle(0.0, 0.0, item_w, item_h),
        dst=dst,
        origin=origin,
        rotation_deg=rotation_deg,
        tint=rl.WHITE,
    )
    tint = rl.Color(255, 255, 255, int(label_alpha))
    src = rl.Rectangle(
        0.0,
        float(entry.row) * MENU_LABEL_ROW_HEIGHT,
        MENU_LABEL_WIDTH,
        MENU_LABEL_ROW_HEIGHT,
    )
    label_offset_x = MENU_LABEL_OFFSET_X * item_scale_value
    label_offset_y = MENU_LABEL_OFFSET_Y * item_scale_value - local_y_shift
    label_dst = rl.Rectangle(
        pos.x,
        pos.y,
        MENU_LABEL_WIDTH * item_scale_value,
        MENU_LABEL_HEIGHT * item_scale_value,
    )
    label_origin = rl.Vector2(-label_offset_x, -label_offset_y)
    draw_ui_quad(
        texture=label_tex,
        src=src,
        dst=label_dst,
        origin=label_origin,
        rotation_deg=rotation_deg,
        tint=tint,
    )
    if glow_alpha is not None:
        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
        draw_ui_quad(
            texture=label_tex,
            src=src,
            dst=label_dst,
            origin=label_origin,
            rotation_deg=rotation_deg,
            tint=rl.Color(255, 255, 255, int(glow_alpha)),
        )
        rl.end_blend_mode()


class _MenuEntriesScreenView(ChromeScreenView):
    def __init__(self, state: GameState, *, chrome_spec: ChromeSpec) -> None:
        super().__init__(state, chrome_spec=chrome_spec)
        self._menu_entries: list[MenuEntry] = []
        self._list_state = MenuListState()

    def open(self) -> None:
        super().open()
        self._menu_entries = self._build_menu_entries()
        MenuListController.open_state(
            self._list_state,
            entry_count=len(self._menu_entries),
        )
        self._on_open()

    def close(self) -> None:
        super().close()
        self._menu_entries = []

    def update(self, dt: float) -> None:
        self._assert_open()
        tick = self._update_chrome(dt)
        mouse = Vec2.from_xy(rl.get_mouse_position())
        self._before_menu_step(tick_dt_ms=tick.dt_ms, mouse_pos=mouse)
        if self._chrome_state.closing:
            return
        if not self._menu_entries:
            return

        hovered_index = self._hovered_entry_index()
        activated_index = MenuListController.step(
            self._list_state,
            self._menu_entries,
            dt_ms=tick.dt_ms,
            hovered_index=hovered_index,
            is_enabled=self._menu_entry_enabled,
            enter_enabled=self._enter_enabled(),
            escape_index=self._escape_entry_index(),
        )
        if activated_index is not None:
            self._activate_menu_entry(activated_index)
        self._after_menu_update(tick_dt_ms=tick.dt_ms, interactive=tick.interactive)

    def draw(self) -> None:
        self._assert_open()
        self._draw_background()
        self._draw_fade()
        self._draw_menu_items()
        self._draw_menu_sign()
        self._draw_cursor()

    def _on_open(self) -> None:
        return

    def _build_menu_entries(self) -> list[MenuEntry]:
        raise NotImplementedError

    def _activate_menu_entry(self, index: int) -> None:
        raise NotImplementedError

    def _escape_entry_index(self) -> int | None:
        return None

    def _enter_enabled(self) -> bool:
        return True

    def _before_menu_step(self, *, tick_dt_ms: int, mouse_pos: Vec2) -> None:
        del tick_dt_ms
        del mouse_pos

    def _after_menu_update(self, *, tick_dt_ms: int, interactive: bool) -> None:
        del tick_dt_ms
        del interactive

    def _menu_entry_enabled(self, entry: MenuEntry) -> bool:
        return self._chrome_state.timeline_ms >= menu_slot_start_ms(entry.slot)

    def _menu_item_scale(self, slot: int) -> tuple[float, float]:
        return menu_item_scale(float(self._chrome_state.screen_width), int(slot), small_scale=0.9)

    def _menu_item_pos(self, entry: MenuEntry) -> Vec2:
        return Vec2(menu_slot_pos_x(entry.slot), entry.y)

    def _menu_item_bounds(self, entry: MenuEntry, resources: RuntimeResources) -> Rect:
        return menu_entry_bounds(
            resources,
            screen_width=float(self._chrome_state.screen_width),
            entry=entry,
            pos=self._menu_item_pos(entry),
            small_scale=0.9,
        )

    def _hovered_entry_index(self) -> int | None:
        resources = require_runtime_resources(self.state)
        return MenuListController.hovered_index(
            self._menu_entries,
            is_enabled=self._menu_entry_enabled,
            contains_mouse=lambda entry: self._menu_item_bounds(entry, resources).contains(Vec2.from_xy(rl.get_mouse_position())),
        )

    def _draw_menu_items(self) -> None:
        if not self._menu_entries:
            return
        resources = require_runtime_resources(self.state)
        item = resources.texture(TextureId.UI_MENU_ITEM)
        item_w = float(item.width)
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        screen_width = float(self._chrome_state.screen_width)
        for idx in range(len(self._menu_entries) - 1, -1, -1):
            entry = self._menu_entries[idx]
            pos = self._menu_item_pos(entry)
            angle_rad, _slide_x = ui_element_anim(
                self._chrome_state.timeline_ms,
                index=entry.slot + 2,
                start_ms=menu_slot_start_ms(entry.slot),
                end_ms=menu_slot_end_ms(entry.slot),
                width=item_w,
            )
            alpha = MenuEntryController.alpha_for_entry(entry=entry, index=idx, list_state=self._list_state)
            glow_alpha: int | None = None
            if self._menu_entry_enabled(entry):
                glow_alpha = alpha
                if 0 <= entry.ready_timer_ms < 0x100:
                    glow_alpha = 0xFF - (entry.ready_timer_ms // 2)
            draw_menu_entry(
                resources,
                screen_width=screen_width,
                entry=entry,
                pos=pos,
                small_scale=0.9,
                rotation_deg=float(angle_rad) * 57.2957795,
                label_alpha=alpha,
                glow_alpha=glow_alpha,
                shadow_offset=7.0,
                fx_detail=fx_detail,
            )

    def _draw_menu_sign(self) -> None:
        self._draw_sign()


__all__ = [
    "draw_menu_entry",
    "menu_entry_bounds",
    "_MenuEntriesScreenView",
]
