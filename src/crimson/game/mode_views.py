from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, cast

from crimson.quest_level import QuestLevel
from grim.audio import stop_music
from grim.view import ViewContext

from ..game_modes import GameMode
from ..render.rtx.mode import RtxRenderMode
from .types import GameState, HighScoresRequest

if TYPE_CHECKING:
    from grim.geom import Vec2
    from grim.terrain_render import GroundRenderer

    from .types import QuestRunOutcome


class _ModeRuntime(Protocol):
    close_requested: bool

    def set_lan_runtime(
        self,
        *,
        enabled: bool,
        role: str,
        expected_players: int,
        connected_players: int,
        waiting_for_players: bool,
    ) -> None: ...

    def bind_lan_runtime(self, runtime: object | None) -> None: ...

    def set_lan_match_start(
        self, *, seed: int, start_tick: int = 0, status_snapshot: object | None = None,
    ) -> None: ...

    def bind_status(self, status: object) -> None: ...

    def bind_audio(self, audio: object | None, rng: object) -> None: ...

    def set_rtx_mode(self, mode: RtxRenderMode) -> None: ...

    def bind_screen_fade(self, state: GameState) -> None: ...

    def open(self) -> None: ...

    def close(self) -> None: ...

    def update(self, dt: float) -> None: ...

    def draw(self) -> None: ...

    def take_action(self) -> str | None: ...

    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None: ...

    def steal_ground_for_menu(self) -> GroundRenderer | None: ...

    def menu_ground_camera(self) -> Vec2: ...

    def console_elapsed_ms(self) -> float: ...

    def regenerate_terrain_for_console(self) -> None: ...


class _ModeSupportsAdoptGround(Protocol):
    def adopt_ground_from_menu(self, ground: GroundRenderer | None) -> None: ...


class _QuestModeRuntime(_ModeRuntime, Protocol):
    def prepare_new_run(self, level: str, *, status: object) -> None: ...

    def consume_outcome(self) -> QuestRunOutcome | None: ...


def _mode_view_context(state: GameState) -> ViewContext:
    preserve_bugs = bool(state.preserve_bugs)
    if bool(state.network_in_lobby):
        # Network multiplayer must keep simulation rules deterministic across peers.
        preserve_bugs = False
    return ViewContext(assets_dir=state.assets_dir, preserve_bugs=preserve_bugs)


class _BaseModeGameView:
    def __init__(self, state: GameState, mode: _ModeRuntime) -> None:
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
        self._mode.set_rtx_mode(self.state.rtx_mode)
        self._mode.bind_screen_fade(self.state)
        self._mode.open()
        self._on_open_end()

    def _on_open_begin(self) -> None:
        return

    def _on_open_end(self) -> None:
        return

    def _configure_lan_runtime(self) -> None:
        pending = self.state.pending_network_session
        in_lobby = bool(self.state.network_in_lobby)
        if (not in_lobby) or pending is None:
            self._mode.set_lan_runtime(
                enabled=False,
                role="",
                expected_players=1,
                connected_players=1,
                waiting_for_players=False,
            )
            self._mode.bind_lan_runtime(runtime=None)
            return

        expected_players = max(
            1,
            min(
                4,
                int(self.state.network_expected_players),
            ),
        )
        connected_players = max(
            0,
            min(
                expected_players,
                int(self.state.network_connected_players),
            ),
        )
        waiting_for_players = bool(self.state.network_waiting_for_players)
        self._mode.set_lan_runtime(
            enabled=True,
            role=str(pending.role),
            expected_players=int(expected_players),
            connected_players=int(connected_players),
            waiting_for_players=bool(waiting_for_players),
        )
        runtime = self.state.network_runtime
        self._mode.bind_lan_runtime(runtime=runtime)
        if runtime is not None:
            match_start = runtime.match_start
            if match_start is not None:
                event = match_start()
                if event is not None:
                    self._mode.set_lan_match_start(
                        seed=int(event.seed),
                        start_tick=int(event.start_tick),
                        status_snapshot=event.status_snapshot,
                    )

    def close(self) -> None:
        if self.state.audio is not None:
            stop_music(self.state.audio)
        self._mode.close()

    def update(self, dt: float) -> None:
        self._configure_lan_runtime()
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
        return float(self._mode.console_elapsed_ms())

    def regenerate_terrain_for_console(self) -> None:
        self._mode.regenerate_terrain_for_console()

    def set_rtx_mode(self, mode: RtxRenderMode) -> None:
        self._mode.set_rtx_mode(mode)

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action


class _ArcadeModeGameView(_BaseModeGameView):
    def __init__(self, state: GameState, mode: _ModeRuntime, *, game_mode_id: GameMode) -> None:
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
        super().__init__(state, cast(_ModeRuntime, mode), game_mode_id=GameMode.SURVIVAL)

    def adopt_menu_ground(self, ground: GroundRenderer | None) -> None:
        cast(_ModeSupportsAdoptGround, self._mode).adopt_ground_from_menu(ground)


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
        super().__init__(state, cast(_ModeRuntime, mode), game_mode_id=GameMode.RUSH)

    def adopt_menu_ground(self, ground: GroundRenderer | None) -> None:
        cast(_ModeSupportsAdoptGround, self._mode).adopt_ground_from_menu(ground)


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
        super().__init__(state, cast(_ModeRuntime, mode), game_mode_id=GameMode.TYPO)


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
        super().__init__(state, cast(_ModeRuntime, mode))


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
        super().__init__(state, cast(_ModeRuntime, mode))

    def _on_open_begin(self) -> None:
        self.state.quest_outcome = None

    def _on_open_end(self) -> None:
        level = self.state.pending_quest_level
        if level is None:
            return
        parsed = QuestLevel.parse(level)
        normalized = parsed.to_string()
        self.state.pending_quest_level = normalized
        cast(_QuestModeRuntime, self._mode).prepare_new_run(normalized, status=self.state.status)

    def _handle_close_requested(self) -> None:
        outcome = cast(_QuestModeRuntime, self._mode).consume_outcome()
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
