from __future__ import annotations

from enum import IntEnum


class GameStateId(IntEnum):
    """Native `game_state_id` values (`game_state_set`)."""

    MAIN_MENU = 0x00
    PLAY_GAME_MENU = 0x01
    OPTIONS_MENU = 0x02
    CONTROLS_MENU = 0x03
    STATISTICS_MENU = 0x04
    PAUSE_MENU = 0x05
    PERK_SELECTION = 0x06
    GAME_OVER = 0x07
    QUEST_RESULTS = 0x08
    GAMEPLAY = 0x09
    QUIT_TRANSITION = 0x0A
    QUEST_SELECT = 0x0B
    QUEST_FAILED = 0x0C
    HIGHSCORE_LEGACY = 0x0D
    HIGHSCORES = 0x0E
    WEAPON_DATABASE = 0x0F
    PERK_DATABASE = 0x10
    CREDITS = 0x11
    TYPO_GAMEPLAY = 0x12
    MENU_LEGACY_VARIANT = 0x13
    MODS_MENU = 0x14
    FINAL_QUEST_END_NOTE = 0x15
    PLUGIN_RUNTIME = 0x16
    DEMO_UPSELL_GAMEPLAY = 0x18
    PENDING_IDLE_SENTINEL = 0x19
    CREDITS_SECRET = 0x1A
