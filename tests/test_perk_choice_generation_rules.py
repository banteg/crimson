from __future__ import annotations

from grim.geom import Vec2

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState, PlayerState, perk_generate_choices, perks_rebuild_available
from crimson.persistence import save_status
from crimson.perks import PerkId


class _SeqRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(v) for v in values] or [0]
        self._idx = 0

    def rand(self) -> int:
        if self._idx >= len(self._values):
            return int(self._values[-1])
        value = int(self._values[self._idx])
        self._idx += 1
        return value


def _status_default() -> save_status.GameStatus:
    return save_status.GameStatus(path=Path("game.cfg"), data=save_status.default_status_data(), dirty=False)


def test_perks_rebuild_available_unlocks_base_and_quest_perks() -> None:
    status = _status_default()
    status.quest_unlock_index = 0
    state = GameplayState()
    state.status = status
    perks_rebuild_available(state)

    assert state.perk_available[int(PerkId.BONUS_MAGNET)]
    assert not state.perk_available[int(PerkId.URANIUM_FILLED_BULLETS)]

    status.quest_unlock_index = 3  # includes quest 1.3 unlock_perk_id=URANIUM_FILLED_BULLETS
    perks_rebuild_available(state)
    assert state.perk_available[int(PerkId.URANIUM_FILLED_BULLETS)]


def test_perk_generate_choices_inserts_monster_vision_on_quest_1_7() -> None:
    # `perk_generate_choices` always fills a 7-entry list; provide enough entropy to avoid
    # degenerately selecting the same perk forever.
    state = GameplayState(rng=_SeqRng([0, 1, 2, 3, 4, 5, 6]))
    state.quest_stage_major = 1
    state.quest_stage_minor = 7
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))

    choices = perk_generate_choices(state, player, game_mode=int(GameMode.QUESTS), player_count=1)
    assert choices and choices[0] == PerkId.MONSTER_VISION


def test_perk_generate_choices_rejects_pyromaniac_without_flamethrower() -> None:
    state = GameplayState(rng=_SeqRng([38, 1, 2, 3, 4, 5, 6, 7]))
    state._perk_available_unlock_index = 0
    for perk_id in (PerkId.PYROMANIAC, PerkId.SHARPSHOOTER, PerkId.FASTLOADER, PerkId.LEAN_MEAN_EXP_MACHINE, PerkId.LONG_DISTANCE_RUNNER, PerkId.PYROKINETIC, PerkId.INSTANT_WINNER, PerkId.GRIM_DEAL):
        state.perk_available[int(perk_id)] = True

    player = PlayerState(index=0, pos=Vec2(0.0, 0.0), weapon_id=1)
    choices = perk_generate_choices(state, player, game_mode=int(GameMode.SURVIVAL), player_count=1)
    assert PerkId.PYROMANIAC not in choices


def test_perk_generate_choices_blocks_perks_when_death_clock_active() -> None:
    state = GameplayState(rng=_SeqRng([41, 1, 2, 3, 4, 5, 6, 9]))
    perks_rebuild_available(state)
    state.perk_available[int(PerkId.JINXED)] = True

    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.perk_counts[int(PerkId.DEATH_CLOCK)] = 1

    choices = perk_generate_choices(state, player, game_mode=int(GameMode.SURVIVAL), player_count=1)
    assert PerkId.JINXED not in choices


def test_perk_generate_choices_applies_rarity_gate() -> None:
    # Anxious Loader is in the global rarity gate; when (rand & 3) == 1 it is rejected.
    state = GameplayState(rng=_SeqRng([17, 1, 1, 2, 3, 4, 5, 6, 7]))
    state._perk_available_unlock_index = 0
    for perk_id in (PerkId.ANXIOUS_LOADER, PerkId.SHARPSHOOTER, PerkId.FASTLOADER, PerkId.LEAN_MEAN_EXP_MACHINE, PerkId.LONG_DISTANCE_RUNNER, PerkId.PYROKINETIC, PerkId.INSTANT_WINNER, PerkId.GRIM_DEAL):
        state.perk_available[int(perk_id)] = True

    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    choices = perk_generate_choices(state, player, game_mode=int(GameMode.SURVIVAL), player_count=1)
    assert PerkId.ANXIOUS_LOADER not in choices
