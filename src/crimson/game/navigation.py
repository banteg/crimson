from __future__ import annotations

from functools import partial

from crimson.screens.chrome import ensure_menu_ground
from grim.audio import stop_music
from grim.view import ViewContext

from ..demo import DemoView
from ..game_modes import GameMode
from ..modes.base_gameplay_mode import BaseGameplayMode
from ..modes.quest_mode import QuestMode
from ..modes.rush_mode import RushMode
from ..modes.survival_mode import SurvivalMode
from ..modes.tutorial_mode import TutorialMode
from ..modes.typo_mode import TypoShooterMode
from ..screens.actions import Route, ScreenAction, ShowQuestOutcome, ShowScores, StartRun
from ..screens.boot import BootView
from ..screens.high_scores_view import HighScoresView
from ..screens.menu import MenuView
from ..screens.panels.alien_zookeeper import AlienZooKeeperView
from ..screens.panels.base import PanelMenuView
from ..screens.panels.controls import ControlsMenuView
from ..screens.panels.credits import CreditsView
from ..screens.panels.databases import UnlockedPerksDatabaseView, UnlockedWeaponsDatabaseView
from ..screens.panels.mods import ModsMenuView
from ..screens.panels.options import OptionsMenuView
from ..screens.panels.play_game import PlayGameMenuView
from ..screens.panels.stats import StatisticsMenuView
from ..screens.pause_menu import PauseMenuView
from ..screens.quest_views import EndNoteView, QuestFailedView, QuestResultsView, QuestsMenuView
from ..screens.stack import ScreenEntry
from .types import GameState


class ScreenNavigator:
    def __init__(self, state: GameState) -> None:
        self.state = state
        # Instantiate on first entry, retaining each mode's RNG progression across runs.
        self._modes: dict[GameMode, BaseGameplayMode] = {}
        self._panels: dict[Route, ScreenEntry] = {}

    def open(self) -> None:
        self.state.screens.push(ScreenEntry(BootView(self.state)))

    def navigate(self, action: ScreenAction) -> None:
        screens = self.state.screens
        match action:
            case StartRun():
                self._start_run(action)
            case ShowScores():
                screens.push(ScreenEntry(HighScoresView(self.state, action)))
            case ShowQuestOutcome(outcome=outcome):
                if outcome.kind == "completed":
                    view = QuestResultsView(self.state, outcome)
                    screens.push(ScreenEntry(view, resume=view.resume))
                else:
                    screens.push(ScreenEntry(QuestFailedView(self.state, outcome)))
            case Route.BACK:
                if not screens.back():
                    self._main_menu()
            case Route.MENU:
                self._main_menu()
            case Route.QUIT:
                self.state.quit_requested = True
            case Route.DEMO | Route.QUIT_AFTER_DEMO:
                screens.reset(ScreenEntry(DemoView(self.state, quit_after=action is Route.QUIT_AFTER_DEMO)))
            case Route.PAUSE:
                assert screens.active_gameplay is not None
                screens.push(self._panel(action))
            case Route.PLAY_GAME:
                if screens.gameplay is not None:
                    self.capture_ground()
                    screens.close()
                screens.push(self._panel(action))
            case Route.QUESTS:
                if screens.gameplay is not None:
                    self.navigate(Route.PLAY_GAME)
                screens.push(self._panel(action))
            case Route.ALIEN_ZOOKEEPER | Route.END_NOTE:
                screens.replace(self._panel(action))
            case (
                Route.OPTIONS
                | Route.CONTROLS
                | Route.STATISTICS
                | Route.WEAPONS
                | Route.PERKS
                | Route.CREDITS
                | Route.MODS
                | Route.OTHER_GAMES
            ):
                screens.push(self._panel(action))

    def _panel(self, route: Route) -> ScreenEntry:
        entry = self._panels.get(route)
        if entry is not None:
            return entry
        if route is Route.OTHER_GAMES:
            view = PanelMenuView(self.state, title="Other games", body="This menu is out of scope for the rewrite.")
        else:
            view_type = {
                Route.MENU: MenuView,
                Route.PAUSE: PauseMenuView,
                Route.PLAY_GAME: PlayGameMenuView,
                Route.QUESTS: QuestsMenuView,
                Route.OPTIONS: OptionsMenuView,
                Route.CONTROLS: ControlsMenuView,
                Route.STATISTICS: StatisticsMenuView,
                Route.WEAPONS: UnlockedWeaponsDatabaseView,
                Route.PERKS: UnlockedPerksDatabaseView,
                Route.CREDITS: CreditsView,
                Route.ALIEN_ZOOKEEPER: AlienZooKeeperView,
                Route.MODS: ModsMenuView,
                Route.END_NOTE: EndNoteView,
            }[route]
            view = view_type(self.state)
        resume = view.resume if isinstance(view, (MenuView, PanelMenuView, PauseMenuView, StatisticsMenuView)) else None
        entry = ScreenEntry(view, resume=resume)
        self._panels[route] = entry
        return entry

    def _main_menu(self) -> None:
        screens = self.state.screens
        from_demo = isinstance(screens.active, DemoView)
        self.capture_ground()
        screens.close()
        if from_demo:
            ensure_menu_ground(self.state, regenerate=True)
        screens.push(self._panel(Route.MENU))

    def _mode(self, mode_id: GameMode) -> BaseGameplayMode:
        mode = self._modes.get(mode_id)
        if mode is not None:
            return mode
        ctx = ViewContext(assets_dir=self.state.assets_dir, preserve_bugs=self.state.preserve_bugs)
        mode_type = {
            GameMode.QUESTS: partial(QuestMode, demo_mode_active=self.state.demo_enabled),
            GameMode.SURVIVAL: SurvivalMode,
            GameMode.RUSH: RushMode,
            GameMode.TYPO: TypoShooterMode,
            GameMode.TUTORIAL: partial(TutorialMode, demo_mode_active=self.state.demo_enabled),
        }[mode_id]
        mode = mode_type(
            ctx,
            config=self.state.config,
            console=self.state.console,
            audio=self.state.audio,
            audio_rng=self.state.rng,
        )
        self._modes[mode_id] = mode
        return mode

    def _start_run(self, request: StartRun) -> None:
        config = self.state.config
        config.gameplay.mode = request.mode
        config.gameplay.player_count = request.player_count
        config.gameplay.hardcore = request.hardcore
        if request.mode == GameMode.QUESTS:
            assert request.quest_level is not None
            unlock = (
                self.state.status.quest_unlock_index_full if request.hardcore else self.state.status.quest_unlock_index
            )
            assert request.quest_level.global_index <= unlock, "cannot launch a locked quest"
            config.gameplay.quest_level = request.quest_level
        if request.mode in {GameMode.SURVIVAL, GameMode.RUSH, GameMode.TYPO}:
            self.state.status.increment_mode_play_count_for_mode(request.mode)
        if self.state.screen_fade_ramp:
            self.state.screen_fade_alpha = 1.0
        self.state.screen_fade_ramp = False
        stop_music(self.state.audio)
        self.state.screens.close()
        gameplay = self._mode(request.mode)
        gameplay.bind_status(self.state.status)
        gameplay.bind_audio(self.state.audio, self.state.rng)
        gameplay.set_rtx_mode(self.state.rtx_mode)
        gameplay.bind_screen_fade(self.state)
        self.state.screens.push(ScreenEntry(gameplay, resume=gameplay.resume, gameplay=gameplay))
        if isinstance(gameplay, QuestMode):
            assert request.quest_level is not None
            gameplay.quest_fail_retry_count = self.state.quest_fail_retry_count
            gameplay.start_run(request.quest_level, status=self.state.status)

    def capture_ground(self) -> None:
        gameplay = self.state.screens.gameplay
        if gameplay is None:
            return
        camera = gameplay.menu_ground_camera()
        ground = gameplay.steal_ground_for_menu()
        if ground is None:
            return
        previous = self.state.menu_ground
        if previous is not ground and previous is not None:
            previous.close()
        self.state.menu_ground = ground
        self.state.menu_ground_camera = camera
