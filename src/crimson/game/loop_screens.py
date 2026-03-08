from __future__ import annotations

from grim.view import ViewContext

from ..demo import DemoView
from ..modes.quest_mode import QuestMode
from ..modes.rush_mode import RushMode
from ..modes.survival_mode import SurvivalMode
from ..modes.tutorial_mode import TutorialMode
from ..modes.typo_mode import TypoShooterMode
from ..screens.high_scores_view import HighScoresView
from ..screens.panels.alien_zookeeper import AlienZooKeeperView
from ..screens.panels.controls import ControlsMenuView
from ..screens.panels.credits import CreditsView
from ..screens.panels.databases import UnlockedPerksDatabaseView, UnlockedWeaponsDatabaseView
from ..screens.panels.mods import ModsMenuView
from ..screens.panels.network_lobby import NetworkLobbyPanelView
from ..screens.panels.network_session import NetworkSessionPanelView
from ..screens.panels.options import OptionsMenuView
from ..screens.panels.play_game import PlayGameMenuView
from ..screens.panels.stats import StatisticsMenuView
from ..screens.pause_menu import PauseMenuView
from ..screens.quest_views import EndNoteView, QuestFailedView, QuestResultsView, QuestsMenuView
from .loop_actions import ModeId, OpenScreenAction, ScreenId, StartModeAction
from .types import GameplayScreen, GameState, Screen


def _mode_view_context(state: GameState) -> ViewContext:
    preserve_bugs = bool(state.preserve_bugs)
    if bool(state.network_in_lobby):
        preserve_bugs = False
    return ViewContext(assets_dir=state.assets_dir, preserve_bugs=preserve_bugs)


class LoopScreenFactory:
    def __init__(self, state: GameState) -> None:
        ctx = _mode_view_context(state)
        self._screens: dict[ScreenId, Screen] = {
            ScreenId.PLAY_GAME: PlayGameMenuView(state),
            ScreenId.LAN_SESSION: NetworkSessionPanelView(state),
            ScreenId.LAN_LOBBY: NetworkLobbyPanelView(state),
            ScreenId.QUESTS: QuestsMenuView(state),
            ScreenId.PAUSE_MENU: PauseMenuView(state),
            ScreenId.QUEST_RESULTS: QuestResultsView(state),
            ScreenId.QUEST_FAILED: QuestFailedView(state),
            ScreenId.END_NOTE: EndNoteView(state),
            ScreenId.HIGH_SCORES: HighScoresView(state),
            ScreenId.OPTIONS: OptionsMenuView(state),
            ScreenId.CONTROLS: ControlsMenuView(state),
            ScreenId.STATISTICS: StatisticsMenuView(state),
            ScreenId.WEAPON_DATABASE: UnlockedWeaponsDatabaseView(state),
            ScreenId.PERK_DATABASE: UnlockedPerksDatabaseView(state),
            ScreenId.CREDITS: CreditsView(state),
            ScreenId.ALIEN_ZOOKEEPER: AlienZooKeeperView(state),
            ScreenId.MODS: ModsMenuView(state),
            ScreenId.OTHER_GAMES: self._build_other_games_panel(state),
        }
        self._modes: dict[ModeId, GameplayScreen] = {
            ModeId.QUEST: QuestMode(
                ctx,
                config=state.config,
                console=state.console,
                audio=state.audio,
                audio_rng=state.rng,
                demo_mode_active=state.demo_enabled,
            ),
            ModeId.SURVIVAL: SurvivalMode(
                ctx,
                config=state.config,
                console=state.console,
                audio=state.audio,
                audio_rng=state.rng,
            ),
            ModeId.RUSH: RushMode(
                ctx,
                config=state.config,
                console=state.console,
                audio=state.audio,
                audio_rng=state.rng,
            ),
            ModeId.TYPO: TypoShooterMode(
                ctx,
                config=state.config,
                console=state.console,
                audio=state.audio,
                audio_rng=state.rng,
            ),
            ModeId.TUTORIAL: TutorialMode(
                ctx,
                config=state.config,
                console=state.console,
                audio=state.audio,
                audio_rng=state.rng,
                demo_mode_active=state.demo_enabled,
            ),
        }
        self.demo = DemoView(state)

    @staticmethod
    def _build_other_games_panel(state: GameState) -> Screen:
        from ..screens.panels.base import PanelMenuView

        return PanelMenuView(
            state,
            title="Other games",
            body="This menu is out of scope for the rewrite.",
        )

    def screen(self, screen_id: ScreenId) -> Screen:
        return self._screens[screen_id]

    def gameplay(self, mode_id: ModeId) -> GameplayScreen:
        return self._modes[mode_id]

    def resolve(self, action: OpenScreenAction | StartModeAction) -> Screen:
        if isinstance(action, OpenScreenAction):
            return self.screen(action.screen)
        return self.gameplay(action.mode)


__all__ = ["LoopScreenFactory"]
