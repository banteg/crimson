from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, TypeAlias


class ScreenId(StrEnum):
    PLAY_GAME = "play_game"
    LAN_SESSION = "lan_session"
    LAN_LOBBY = "lan_lobby"
    QUESTS = "quests"
    PAUSE_MENU = "pause_menu"
    QUEST_RESULTS = "quest_results"
    QUEST_FAILED = "quest_failed"
    END_NOTE = "end_note"
    HIGH_SCORES = "high_scores"
    OPTIONS = "options"
    CONTROLS = "controls"
    STATISTICS = "statistics"
    WEAPON_DATABASE = "weapon_database"
    PERK_DATABASE = "perk_database"
    CREDITS = "credits"
    ALIEN_ZOOKEEPER = "alien_zookeeper"
    MODS = "mods"
    OTHER_GAMES = "other_games"


class ModeId(StrEnum):
    SURVIVAL = "survival"
    RUSH = "rush"
    TYPO = "typo"
    TUTORIAL = "tutorial"
    QUEST = "quest"


LanModeId = Literal["survival", "rush", "quests"]
BackTarget = Literal["menu", "previous"]


@dataclass(frozen=True, slots=True)
class OpenScreenAction:
    screen: ScreenId


@dataclass(frozen=True, slots=True)
class StartModeAction:
    mode: ModeId


@dataclass(frozen=True, slots=True)
class StartLanModeAction:
    mode: LanModeId


@dataclass(frozen=True, slots=True)
class NavigateAction:
    target: BackTarget


@dataclass(frozen=True, slots=True)
class QuitAppAction:
    pass


@dataclass(frozen=True, slots=True)
class StartDemoAction:
    pass


@dataclass(frozen=True, slots=True)
class QuitAfterDemoAction:
    pass


@dataclass(frozen=True, slots=True)
class RestartModeAction:
    pass


ViewAction: TypeAlias = (
    OpenScreenAction
    | StartModeAction
    | StartLanModeAction
    | NavigateAction
    | QuitAppAction
    | StartDemoAction
    | QuitAfterDemoAction
    | RestartModeAction
)


BACK_TO_MENU = NavigateAction("menu")
BACK_TO_PREVIOUS = NavigateAction("previous")
OPEN_PLAY_GAME = OpenScreenAction(ScreenId.PLAY_GAME)
OPEN_LAN_SESSION = OpenScreenAction(ScreenId.LAN_SESSION)
OPEN_LAN_LOBBY = OpenScreenAction(ScreenId.LAN_LOBBY)
OPEN_QUESTS = OpenScreenAction(ScreenId.QUESTS)
OPEN_PAUSE_MENU = OpenScreenAction(ScreenId.PAUSE_MENU)
OPEN_QUEST_RESULTS = OpenScreenAction(ScreenId.QUEST_RESULTS)
OPEN_QUEST_FAILED = OpenScreenAction(ScreenId.QUEST_FAILED)
OPEN_END_NOTE = OpenScreenAction(ScreenId.END_NOTE)
OPEN_HIGH_SCORES = OpenScreenAction(ScreenId.HIGH_SCORES)
OPEN_OPTIONS = OpenScreenAction(ScreenId.OPTIONS)
OPEN_CONTROLS = OpenScreenAction(ScreenId.CONTROLS)
OPEN_STATISTICS = OpenScreenAction(ScreenId.STATISTICS)
OPEN_WEAPON_DATABASE = OpenScreenAction(ScreenId.WEAPON_DATABASE)
OPEN_PERK_DATABASE = OpenScreenAction(ScreenId.PERK_DATABASE)
OPEN_CREDITS = OpenScreenAction(ScreenId.CREDITS)
OPEN_ALIEN_ZOOKEEPER = OpenScreenAction(ScreenId.ALIEN_ZOOKEEPER)
OPEN_MODS = OpenScreenAction(ScreenId.MODS)
OPEN_OTHER_GAMES = OpenScreenAction(ScreenId.OTHER_GAMES)
START_SURVIVAL = StartModeAction(ModeId.SURVIVAL)
START_RUSH = StartModeAction(ModeId.RUSH)
START_TYPO = StartModeAction(ModeId.TYPO)
START_TUTORIAL = StartModeAction(ModeId.TUTORIAL)
START_QUEST = StartModeAction(ModeId.QUEST)
START_SURVIVAL_LAN = StartLanModeAction("survival")
START_RUSH_LAN = StartLanModeAction("rush")
START_QUEST_LAN = StartLanModeAction("quests")
QUIT_APP = QuitAppAction()
START_DEMO = StartDemoAction()
QUIT_AFTER_DEMO = QuitAfterDemoAction()
RESTART_MODE = RestartModeAction()


def action_fades_to_game(action: ViewAction) -> bool:
    return isinstance(action, StartModeAction)


def action_label(action: ViewAction) -> str:
    if isinstance(action, OpenScreenAction):
        return f"open:{action.screen.value}"
    if isinstance(action, StartModeAction):
        return f"start:{action.mode.value}"
    if isinstance(action, StartLanModeAction):
        return f"start_lan:{action.mode}"
    if isinstance(action, NavigateAction):
        return f"back:{action.target}"
    if isinstance(action, QuitAppAction):
        return "quit_app"
    if isinstance(action, StartDemoAction):
        return "start_demo"
    if isinstance(action, QuitAfterDemoAction):
        return "quit_after_demo"
    if isinstance(action, RestartModeAction):
        return "restart_mode"
    raise TypeError(f"Unsupported action: {action!r}")


__all__ = [
    "BACK_TO_MENU",
    "BACK_TO_PREVIOUS",
    "LanModeId",
    "ModeId",
    "OPEN_ALIEN_ZOOKEEPER",
    "OPEN_CONTROLS",
    "OPEN_CREDITS",
    "OPEN_END_NOTE",
    "OPEN_HIGH_SCORES",
    "OPEN_LAN_LOBBY",
    "OPEN_LAN_SESSION",
    "OPEN_MODS",
    "OPEN_OPTIONS",
    "OPEN_OTHER_GAMES",
    "OPEN_PAUSE_MENU",
    "OPEN_PERK_DATABASE",
    "OPEN_PLAY_GAME",
    "OPEN_QUEST_FAILED",
    "OPEN_QUEST_RESULTS",
    "OPEN_QUESTS",
    "OPEN_STATISTICS",
    "OPEN_WEAPON_DATABASE",
    "OpenScreenAction",
    "NavigateAction",
    "QUIT_AFTER_DEMO",
    "QUIT_APP",
    "QuitAfterDemoAction",
    "QuitAppAction",
    "RESTART_MODE",
    "RestartModeAction",
    "START_DEMO",
    "START_QUEST",
    "START_QUEST_LAN",
    "START_RUSH",
    "START_RUSH_LAN",
    "START_SURVIVAL",
    "START_SURVIVAL_LAN",
    "START_TUTORIAL",
    "START_TYPO",
    "ScreenId",
    "StartDemoAction",
    "StartLanModeAction",
    "StartModeAction",
    "ViewAction",
    "action_fades_to_game",
    "action_label",
]
