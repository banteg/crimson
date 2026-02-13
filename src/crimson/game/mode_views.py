from __future__ import annotations

from typing import TYPE_CHECKING, Any

from grim.audio import stop_music
from grim.view import ViewContext

from .types import GameState, HighScoresRequest

if TYPE_CHECKING:
    from grim.geom import Vec2
    from grim.terrain_render import GroundRenderer


def _mode_view_context(state: GameState) -> ViewContext:
    return ViewContext(assets_dir=state.assets_dir, preserve_bugs=state.preserve_bugs)


class _BaseModeGameView:
    def __init__(self, state: GameState, mode: Any) -> None:
        self.state = state
        self._mode = mode
        self._action: str | None = None

    def open(self) -> None:
        self._action = None
        if self.state.screen_fade_ramp:
            self.state.screen_fade_alpha = 1.0
        self.state.screen_fade_ramp = False
        self._on_open_begin()
        if self.state.audio is not None:
            # Original game: entering gameplay cuts the menu theme; in-game tunes
            # start later on the first creature hit.
            stop_music(self.state.audio)
        self._configure_lan_runtime()
        self._mode.bind_status(self.state.status)
        self._mode.bind_audio(self.state.audio, self.state.rng)
        self._mode.bind_screen_fade(self.state)
        self._mode.open()
        self._on_open_end()

    def _on_open_begin(self) -> None:
        return

    def _on_open_end(self) -> None:
        return

    def _configure_lan_runtime(self) -> None:
        set_lan_runtime = getattr(self._mode, "set_lan_runtime", None)
        if not callable(set_lan_runtime):
            return

        pending = self.state.pending_lan_session
        if (not bool(self.state.lan_in_lobby)) or pending is None:
            set_lan_runtime(
                enabled=False,
                role="",
                expected_players=1,
                connected_players=1,
                waiting_for_players=False,
            )
            return

        expected_players = max(1, min(4, int(getattr(self.state, "lan_expected_players", 1))))
        connected_players = max(0, min(expected_players, int(getattr(self.state, "lan_connected_players", 1))))
        waiting_for_players = bool(getattr(self.state, "lan_waiting_for_players", False))
        set_lan_runtime(
            enabled=True,
            role=str(pending.role),
            expected_players=int(expected_players),
            connected_players=int(connected_players),
            waiting_for_players=bool(waiting_for_players),
        )

    def close(self) -> None:
        if self.state.audio is not None:
            stop_music(self.state.audio)
        self._mode.close()

    def update(self, dt: float) -> None:
        self._mode.update(dt)
        mode_action = self._mode.take_action()
        if self._handle_mode_action(mode_action):
            return
        if self._mode.close_requested:
            self._handle_close_requested()

    def _handle_mode_action(self, mode_action: str | None) -> bool:
        if mode_action == "open_pause_menu":
            self._action = "open_pause_menu"
            return True
        return False

    def _handle_close_requested(self) -> None:
        self._action = "back_to_menu"
        self._clear_close_requested()

    def _clear_close_requested(self) -> None:
        self._mode.close_requested = False

    def draw(self) -> None:
        self._mode.draw()

    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
        self._mode.draw_pause_background(entity_alpha=entity_alpha)

    def steal_ground_for_menu(self) -> GroundRenderer | None:
        return self._mode.steal_ground_for_menu()

    def menu_ground_camera(self) -> Vec2:
        return self._mode.menu_ground_camera()

    def console_elapsed_ms(self) -> float:
        elapsed_ms = getattr(self._mode, "console_elapsed_ms", None)
        if callable(elapsed_ms):
            return float(elapsed_ms())
        return 0.0

    def regenerate_terrain_for_console(self) -> None:
        regenerate = getattr(self._mode, "regenerate_terrain_for_console", None)
        if callable(regenerate):
            regenerate()

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action


class _ArcadeModeGameView(_BaseModeGameView):
    def __init__(self, state: GameState, mode: Any, *, game_mode_id: int) -> None:
        super().__init__(state, mode)
        self._game_mode_id = game_mode_id

    def _handle_mode_action(self, mode_action: str | None) -> bool:
        if super()._handle_mode_action(mode_action):
            return True
        if mode_action == "open_high_scores":
            self.state.pending_high_scores = HighScoresRequest(game_mode_id=self._game_mode_id)
            self._action = "open_high_scores"
            return True
        if mode_action == "back_to_menu":
            self._action = "back_to_menu"
            self._clear_close_requested()
            return True
        return False


class SurvivalGameView(_ArcadeModeGameView):
    """Gameplay view wrapper that adapts SurvivalMode into `crimson game`."""

    def __init__(self, state: GameState) -> None:
        from ..modes.survival_mode import SurvivalMode

        mode = SurvivalMode(
            _mode_view_context(state),
            texture_cache=state.texture_cache,
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
        )
        super().__init__(state, mode, game_mode_id=1)

    def adopt_menu_ground(self, ground: GroundRenderer | None) -> None:
        self._mode.adopt_ground_from_menu(ground)


class RushGameView(_ArcadeModeGameView):
    """Gameplay view wrapper that adapts RushMode into `crimson game`."""

    def __init__(self, state: GameState) -> None:
        from ..modes.rush_mode import RushMode

        mode = RushMode(
            _mode_view_context(state),
            texture_cache=state.texture_cache,
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
        )
        super().__init__(state, mode, game_mode_id=2)

    def adopt_menu_ground(self, ground: GroundRenderer | None) -> None:
        self._mode.adopt_ground_from_menu(ground)


class TypoShooterGameView(_ArcadeModeGameView):
    """Gameplay view wrapper that adapts TypoShooterMode into `crimson game`."""

    def __init__(self, state: GameState) -> None:
        from ..modes.typo_mode import TypoShooterMode

        mode = TypoShooterMode(
            _mode_view_context(state),
            texture_cache=state.texture_cache,
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
        )
        super().__init__(state, mode, game_mode_id=4)


class TutorialGameView(_BaseModeGameView):
    """Gameplay view wrapper that adapts TutorialMode into `crimson game`."""

    def __init__(self, state: GameState) -> None:
        from ..modes.tutorial_mode import TutorialMode

        mode = TutorialMode(
            _mode_view_context(state),
            texture_cache=state.texture_cache,
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
            demo_mode_active=state.demo_enabled,
        )
        super().__init__(state, mode)


class QuestGameView(_BaseModeGameView):
    """Gameplay view wrapper that adapts QuestMode into `crimson game`."""

    def __init__(self, state: GameState) -> None:
        from ..modes.quest_mode import QuestMode

        mode = QuestMode(
            _mode_view_context(state),
            texture_cache=state.texture_cache,
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
            demo_mode_active=state.demo_enabled,
        )
        super().__init__(state, mode)

    def _on_open_begin(self) -> None:
        self.state.quest_outcome = None

    def _on_open_end(self) -> None:
        level = self.state.pending_quest_level
        if level is not None:
            self._mode.prepare_new_run(level, status=self.state.status)

    def _handle_close_requested(self) -> None:
        outcome = self._mode.consume_outcome()
        if outcome is not None:
            self.state.quest_outcome = outcome
            if outcome.kind == "completed":
                self._action = "quest_results"
            elif outcome.kind == "failed":
                self._action = "quest_failed"
            else:
                self._action = "back_to_menu"
        else:
            self._action = "back_to_menu"
        self._clear_close_requested()


__all__ = [
    "QuestGameView",
    "RushGameView",
    "SurvivalGameView",
    "TutorialGameView",
    "TypoShooterGameView",
]
