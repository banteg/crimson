from __future__ import annotations

from typing import Annotated

import msgspec

type TypoChar = Annotated[str, msgspec.Meta(min_length=1, max_length=1)]


class PerkMenuOpenCommand(msgspec.Struct, tag="perk_menu_open", frozen=True, forbid_unknown_fields=True):
    player_index: int


class PerkPickCommand(msgspec.Struct, tag="perk_pick", frozen=True, forbid_unknown_fields=True):
    player_index: int
    choice_index: int


class TypoCharCommand(msgspec.Struct, tag="typo_char", frozen=True, forbid_unknown_fields=True):
    player_index: int
    ch: TypoChar


class TypoBackspaceCommand(msgspec.Struct, tag="typo_backspace", frozen=True, forbid_unknown_fields=True):
    player_index: int


class TypoSubmitCommand(msgspec.Struct, tag="typo_submit", frozen=True, forbid_unknown_fields=True):
    player_index: int


type GameCommand = PerkMenuOpenCommand | PerkPickCommand | TypoCharCommand | TypoBackspaceCommand | TypoSubmitCommand
