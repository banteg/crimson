from __future__ import annotations

from grim.assets import TextureId
from grim.fonts.small import SmallFontData
from grim.geom import Vec2
from grim.raylib_api import rl

from ...game.types import GameState
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_draw, button_update, button_width
from ..assets import require_runtime_resources
from ..chrome import (
    ActionDispatchPolicy,
    BackdropPolicy,
    ChromeSpec,
    SignPolicy,
    split_panel_frame,
)
from ..high_scores_layout import hs_left_panel_pos_x, hs_right_panel_pos_x
from .base import _ChromePanelView

# Shared panel layout (state_14/15/16 in the oracle): tall left panel + short right panel.
LEFT_PANEL_POS_Y = 185.0
LEFT_PANEL_HEIGHT = 378.0
RIGHT_PANEL_POS_Y = 200.0
RIGHT_PANEL_HEIGHT = 254.0


class _DatabaseBaseView(_ChromePanelView):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            chrome_spec=ChromeSpec(
                backdrop=BackdropPolicy(),
                sign=SignPolicy(),
                dispatch=ActionDispatchPolicy(mode="pending_rearm"),
                open_sfx="sfx_ui_panelclick",
                open_sfx_mode="on_open",
                close_sfx="sfx_ui_buttonclick",
            ),
        )
        self._back_button = UiButtonState("Back", force_wide=False)

    def _reset_view_state(self) -> None:
        self._back_button = UiButtonState("Back", force_wide=False)

    def _split_frame(self):
        screen_width = float(self.state.config.screen_width)
        return split_panel_frame(
            self._timeline_ms,
            left_panel_pos=Vec2(hs_left_panel_pos_x(screen_width), LEFT_PANEL_POS_Y),
            left_panel_height=LEFT_PANEL_HEIGHT,
            right_panel_pos=Vec2(hs_right_panel_pos_x(screen_width), RIGHT_PANEL_POS_Y),
            right_panel_height=RIGHT_PANEL_HEIGHT,
            screen_width=screen_width,
            widescreen_y_shift=self._widescreen_y_shift,
            small_scale=1.0,
        )

    def update(self, dt: float) -> None:
        self._assert_open()
        tick = self._chrome.update(dt)
        if self._closing:
            return
        if not tick.interactive:
            return

        frame = self._split_frame()
        resources = require_runtime_resources(self.state)
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._begin_close_transition("back_to_previous")
            return

        self._update_content_interaction(left_top_left=frame.left_top_left, scale=frame.scale, mouse=mouse)

        back_pos = self._back_button_pos()
        back_w = button_width(resources, self._back_button.label, scale=frame.scale, force_wide=self._back_button.force_wide)
        if button_update(
            self._back_button,
            pos=frame.left_top_left + back_pos * frame.scale,
            width=back_w,
            dt_ms=float(tick.dt_ms),
            mouse=mouse,
            click=bool(click),
        ):
            self._begin_close_transition("back_to_previous")

    def draw(self) -> None:
        self._assert_open()
        self._draw_background()
        self._chrome.draw_fade()

        frame = self._split_frame()
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        resources = require_runtime_resources(self.state)
        panel = resources.texture(TextureId.UI_MENU_PANEL)

        draw_classic_menu_panel(
            panel,
            dst=rl.Rectangle(frame.left_top_left.x, frame.left_top_left.y, frame.panel_width, frame.left_panel_height),
            tint=rl.WHITE,
            shadow=fx_detail,
        )
        draw_classic_menu_panel(
            panel,
            dst=rl.Rectangle(frame.right_top_left.x, frame.right_top_left.y, frame.panel_width, frame.right_panel_height),
            tint=rl.WHITE,
            shadow=fx_detail,
            flip_x=True,
        )

        self._draw_contents(frame.left_top_left, frame.right_top_left, scale=frame.scale, font=resources.small_font)

        back_pos = self._back_button_pos()
        back_w = button_width(resources, self._back_button.label, scale=frame.scale, force_wide=self._back_button.force_wide)
        button_draw(
            resources,
            self._back_button,
            pos=frame.left_top_left + back_pos * frame.scale,
            width=back_w,
            scale=frame.scale,
        )

        self._draw_sign()
        self._draw_cursor()

    def _back_button_pos(self) -> Vec2:
        raise NotImplementedError

    def _draw_contents(
        self,
        left_top_left: Vec2,
        right_top_left: Vec2,
        *,
        scale: float,
        font: SmallFontData,
    ) -> None:
        raise NotImplementedError

    def _update_content_interaction(self, *, left_top_left: Vec2, scale: float, mouse: rl.Vector2) -> None:
        return
