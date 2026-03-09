from __future__ import annotations

from ...game.types import GameState
from ..chrome.runtime import (
    BackdropPolicy,
    ChromeSpec,
    ChromeTick,
    CloseTimelineEntityAlpha,
    NoOpenSfx,
    OpaqueEntityAlpha,
    OpenSfxPolicy,
    PendingOnceDispatch,
    SignPolicy,
)
from ..chrome.view import ChromeScreenView


class _QuestChromeViewBase(ChromeScreenView):
    def __init__(
        self,
        state: GameState,
        *,
        allow_pause_background: bool = True,
        show_sign: bool = False,
        lock_sign_on_open: bool = False,
        open_sfx: OpenSfxPolicy = NoOpenSfx(),
        close_sfx: str | None = "sfx_ui_buttonclick",
        fade_actions: frozenset[str] = frozenset(),
        pause_background_close_alpha: CloseTimelineEntityAlpha | None = None,
    ) -> None:
        backdrop = BackdropPolicy(
            allow_pause_background=allow_pause_background,
            entity_alpha=OpaqueEntityAlpha() if pause_background_close_alpha is None else pause_background_close_alpha,
        )
        super().__init__(
            state,
            chrome_spec=ChromeSpec(
                backdrop=backdrop,
                sign=SignPolicy(lock_on_fully_open=lock_sign_on_open),
                dispatch=PendingOnceDispatch(),
                open_sfx=open_sfx,
                close_sfx=close_sfx,
                fade_to_game_actions=fade_actions,
            ),
        )
        self._quest_show_sign = bool(show_sign)

    def _tick_chrome(self, dt: float) -> ChromeTick:
        return self._update_chrome(dt)

    def _draw_chrome(
        self,
        *,
        draw_sign: bool | None = None,
        entity_alpha: float | None = None,
    ) -> None:
        self._draw_background(entity_alpha=entity_alpha)
        self._draw_fade()
        if self._quest_show_sign if draw_sign is None else bool(draw_sign):
            self._draw_sign()


__all__ = ["_QuestChromeViewBase"]
