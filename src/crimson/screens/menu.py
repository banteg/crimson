from __future__ import annotations

import os

from grim.assets import RuntimeResources, TextureId
from grim.audio import play_sfx
from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ..game.types import GameState
from .assets import require_runtime_resources
from .chrome import (
    MENU_DEMO_IDLE_START_MS,
    MENU_ITEM_OFFSET_X,
    MENU_ITEM_OFFSET_Y,
    MENU_LABEL_BASE_Y,
    MENU_LABEL_HEIGHT,
    MENU_LABEL_OFFSET_X,
    MENU_LABEL_OFFSET_Y,
    MENU_LABEL_ROW_BACK,
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_ROW_MODS,
    MENU_LABEL_ROW_OPTIONS,
    MENU_LABEL_ROW_OTHER_GAMES,
    MENU_LABEL_ROW_PLAY_GAME,
    MENU_LABEL_ROW_QUIT,
    MENU_LABEL_ROW_STATISTICS,
    MENU_LABEL_STEP,
    MENU_LABEL_WIDTH,
    ActionDispatchPolicy,
    BackdropPolicy,
    ChromeRuntime,
    ChromeSpec,
    MenuEntry,
    MenuEntryController,
    MenuListController,
    MenuListState,
    MusicPolicy,
    SignPolicy,
    draw_ui_quad,
    draw_ui_quad_shadow,
    menu_item_scale,
    menu_max_timeline_ms,
    menu_slot_end_ms,
    menu_slot_pos_x,
    menu_slot_start_ms,
    ui_element_anim,
)


class _MenuEntriesViewBase:
    def __init__(self, state: GameState, *, chrome_spec: ChromeSpec) -> None:
        self.state = state
        self._chrome = ChromeRuntime(state, spec=chrome_spec)
        self._menu_entries: list[MenuEntry] = []
        self._list_state = MenuListState()

    def open(self) -> None:
        self._chrome.open()
        self._menu_entries = self._build_menu_entries()
        mouse = rl.get_mouse_position()
        MenuListController.open_state(
            self._list_state,
            entry_count=len(self._menu_entries),
            mouse_pos=Vec2.from_xy(mouse),
        )
        self._on_open()

    def close(self) -> None:
        self._chrome.close()
        self._menu_entries = []

    def update(self, dt: float) -> None:
        self._assert_open()
        tick = self._chrome.update(dt)
        mouse = Vec2.from_xy(rl.get_mouse_position())
        if tick.dt_ms > 0 and self._uses_idle_timer():
            MenuListController.update_idle_timer(self._list_state, dt_ms=tick.dt_ms, mouse_pos=mouse)
        if self._chrome.chrome.closing:
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
        self._chrome.draw_fade()
        resources = require_runtime_resources(self.state)
        self._draw_menu_items()
        self._draw_menu_sign()
        self._chrome.draw_cursor(resources=resources)

    def take_action(self) -> str | None:
        self._assert_open()
        return self._chrome.take_action()

    def _assert_open(self) -> None:
        assert self._chrome.is_open, f"{self.__class__.__name__} must be opened before use"

    def _draw_background(self) -> None:
        self._chrome.draw_background()

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

    def _uses_idle_timer(self) -> bool:
        return False

    def _after_menu_update(self, *, tick_dt_ms: int, interactive: bool) -> None:
        del tick_dt_ms
        del interactive

    def _begin_close_transition(self, action: str) -> None:
        self._chrome.begin_close_transition(action)

    def _menu_entry_enabled(self, entry: MenuEntry) -> bool:
        return self._chrome.chrome.timeline_ms >= menu_slot_start_ms(entry.slot)

    def _menu_item_scale(self, slot: int) -> tuple[float, float]:
        return menu_item_scale(float(self._chrome.chrome.screen_width), int(slot), small_scale=0.9)

    def _menu_item_bounds(self, entry: MenuEntry, resources: RuntimeResources) -> Rect:
        item = resources.texture(TextureId.UI_MENU_ITEM)
        item_w = float(item.width)
        item_h = float(item.height)
        item_scale_value, local_y_shift = self._menu_item_scale(entry.slot)
        offset_min = Vec2(
            MENU_ITEM_OFFSET_X * item_scale_value,
            MENU_ITEM_OFFSET_Y * item_scale_value - local_y_shift,
        )
        offset_max = Vec2(
            (MENU_ITEM_OFFSET_X + item_w) * item_scale_value,
            (MENU_ITEM_OFFSET_Y + item_h) * item_scale_value - local_y_shift,
        )
        size = offset_max - offset_min
        pos = Vec2(menu_slot_pos_x(entry.slot), entry.y)
        top_left = pos + Vec2(offset_min.x + size.x * 0.54, offset_min.y + size.y * 0.28)
        bottom_right = pos + Vec2(offset_max.x - size.x * 0.05, offset_max.y - size.y * 0.10)
        return Rect.from_pos_size(top_left, bottom_right - top_left)

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
        label_tex = resources.texture(TextureId.UI_ITEM_TEXTS)
        item_w = float(item.width)
        item_h = float(item.height)
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        for idx in range(len(self._menu_entries) - 1, -1, -1):
            entry = self._menu_entries[idx]
            pos = Vec2(menu_slot_pos_x(entry.slot), entry.y)
            angle_rad, _slide_x = ui_element_anim(
                self._chrome.chrome.timeline_ms,
                index=entry.slot + 2,
                start_ms=menu_slot_start_ms(entry.slot),
                end_ms=menu_slot_end_ms(entry.slot),
                width=item_w,
            )
            item_scale_value, local_y_shift = self._menu_item_scale(entry.slot)
            offset_x = MENU_ITEM_OFFSET_X * item_scale_value
            offset_y = MENU_ITEM_OFFSET_Y * item_scale_value - local_y_shift
            dst = rl.Rectangle(
                pos.x,
                pos.y,
                item_w * item_scale_value,
                item_h * item_scale_value,
            )
            origin = rl.Vector2(-offset_x, -offset_y)
            rotation_deg = float(angle_rad) * 57.2957795
            if fx_detail:
                draw_ui_quad_shadow(
                    texture=item,
                    src=rl.Rectangle(0.0, 0.0, item_w, item_h),
                    dst=rl.Rectangle(dst.x + 7.0, dst.y + 7.0, dst.width, dst.height),
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
            alpha = MenuEntryController.alpha_for_entry(entry=entry, index=idx, list_state=self._list_state)
            tint = rl.Color(255, 255, 255, alpha)
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
            if self._menu_entry_enabled(entry):
                glow_alpha = alpha
                if 0 <= entry.ready_timer_ms < 0x100:
                    glow_alpha = 0xFF - (entry.ready_timer_ms // 2)
                rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
                draw_ui_quad(
                    texture=label_tex,
                    src=src,
                    dst=label_dst,
                    origin=label_origin,
                    rotation_deg=rotation_deg,
                    tint=rl.Color(255, 255, 255, glow_alpha),
                )
                rl.end_blend_mode()

    def _draw_menu_sign(self) -> None:
        self._chrome.draw_sign(resources=require_runtime_resources(self.state))


class MenuView(_MenuEntriesViewBase):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            chrome_spec=ChromeSpec(
                backdrop=BackdropPolicy(allow_pause_background=False),
                music=MusicPolicy(
                    primary_track="crimson_theme",
                    demo_track="crimsonquest",
                    refresh_while_open=True,
                    stop_if_track_mismatch=True,
                ),
                sign=SignPolicy(
                    animated=True,
                    lock_on_fully_open=True,
                    unlock_on_actions=("quit_after_demo", "quit_app"),
                ),
                dispatch=ActionDispatchPolicy(mode="pending_once"),
                open_sfx="sfx_ui_panelclick",
                open_sfx_mode="on_fully_open",
                close_sfx=None,
            ),
        )
        self._full_version = False

    def open(self) -> None:
        self._full_version = not self.state.demo_enabled
        super().open()
        self._chrome.chrome.timeline_max_ms = menu_max_timeline_ms(
            full_version=self._full_version,
            mods_available=self._mods_available(),
            other_games=self._other_games_enabled(),
        )

    def _build_menu_entries(self) -> list[MenuEntry]:
        return self._menu_entries_for_flags(
            full_version=self._full_version,
            mods_available=self._mods_available(),
            other_games=self._other_games_enabled(),
        )

    def _uses_idle_timer(self) -> bool:
        return True

    def _after_menu_update(self, *, tick_dt_ms: int, interactive: bool) -> None:
        del tick_dt_ms
        if (
            (not self._chrome.chrome.closing)
            and self._chrome.chrome.pending_action is None
            and self.state.demo_enabled
            and interactive
            and self._list_state.idle_ms >= MENU_DEMO_IDLE_START_MS
        ):
            self._begin_close_transition("start_demo")

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

    def _begin_quit_transition(self) -> None:
        self._begin_close_transition("quit_after_demo" if self.state.demo_enabled else "quit_app")

    def _menu_entries_for_flags(
        self,
        *,
        full_version: bool,
        mods_available: bool,
        other_games: bool,
    ) -> list[MenuEntry]:
        rows = self._menu_label_rows(full_version, other_games)
        slot_ys = self._menu_slot_ys(other_games, self._chrome.chrome.widescreen_y_shift)
        active = self._menu_slot_active(full_version, mods_available, other_games)
        entries: list[MenuEntry] = []
        for slot, (row, y, enabled) in enumerate(zip(rows, slot_ys, active, strict=False)):
            if enabled:
                entries.append(MenuEntry(slot=slot, row=row, y=y))
        return entries

    @staticmethod
    def _menu_label_rows(_full_version: bool, other_games: bool) -> list[int]:
        top = MENU_LABEL_ROW_MODS
        if other_games:
            return [top, MENU_LABEL_ROW_PLAY_GAME, MENU_LABEL_ROW_OPTIONS, MENU_LABEL_ROW_STATISTICS, MENU_LABEL_ROW_OTHER_GAMES, MENU_LABEL_ROW_QUIT]
        return [top, MENU_LABEL_ROW_PLAY_GAME, MENU_LABEL_ROW_OPTIONS, MENU_LABEL_ROW_STATISTICS, MENU_LABEL_ROW_QUIT, MENU_LABEL_ROW_BACK]

    @staticmethod
    def _menu_slot_ys(_other_games: bool, y_shift: float) -> list[float]:
        return [MENU_LABEL_BASE_Y + MENU_LABEL_STEP * float(slot) + y_shift for slot in range(6)]

    @staticmethod
    def _menu_slot_active(_full_version: bool, mods_available: bool, other_games: bool) -> list[bool]:
        if other_games:
            return [mods_available, True, True, True, True, True]
        return [mods_available, True, True, True, True, False]

    def _mods_available(self) -> bool:
        mods_dir = self.state.base_dir / "mods"
        if not mods_dir.exists():
            return False
        return any(mods_dir.glob("*.dll"))

    def _other_games_enabled(self) -> bool:
        return os.getenv("CRIMSON_GRIM_CONFIG_VAR_100", "").strip() != ""


__all__ = ["MenuView"]
