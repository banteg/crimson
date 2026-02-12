from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from ..game_modes import GameMode
from ..perks import PerkId
from ..perks.helpers import perk_active
from .ids import BONUS_BY_ID, BonusId

if TYPE_CHECKING:
    from .pool import BonusPool
    from ..gameplay import GameplayState, PlayerState
    from grim.rand import Crand


def _bonus_enabled(bonus_id: int) -> bool:
    meta = BONUS_BY_ID.get(int(bonus_id))
    if meta is None:
        return False
    return meta.bonus_id != BonusId.UNUSED


def _bonus_id_from_roll(roll: int, rng: Crand) -> int:
    # Mirrors `bonus_pick_random_type` (0x412470) mapping:
    # - roll = rand() % 162 + 1  (1..162)
    # - Points: roll 1..13
    # - Energizer: roll 14 with (rand & 0x3F) == 0, else Weapon
    # - Bucketed ids 3..14 via a 10-step loop; if it would exceed 14, returns 0
    #   to force a reroll (matching the `goto LABEL_18` path leaving `v3 == 0`).
    if roll < 1 or roll > 162:
        return 0

    if roll <= 13:
        return int(BonusId.POINTS)

    if roll == 14:
        if (rng.rand() & 0x3F) == 0:
            return int(BonusId.ENERGIZER)
        return int(BonusId.WEAPON)

    v5 = roll - 14
    v6 = int(BonusId.WEAPON)
    while v5 > 10:
        v5 -= 10
        v6 += 1
        if v6 >= 15:
            return 0
    return int(v6)


@dataclass(slots=True)
class _BonusPickCtx:
    pool: BonusPool
    state: GameplayState
    players: list[PlayerState]
    bonus_id: int
    has_fire_bullets_drop: bool


_BonusPickSuppressRule = Callable[[_BonusPickCtx], bool]


def _bonus_pick_suppress_active_shock_chain(ctx: _BonusPickCtx) -> bool:
    return ctx.state.shock_chain_links_left > 0 and int(ctx.bonus_id) == int(BonusId.SHOCK_CHAIN)


def _bonus_pick_suppress_quest_minor10_nuke(ctx: _BonusPickCtx) -> bool:
    if not (int(ctx.state.game_mode) == int(GameMode.QUESTS) and int(ctx.state.quest_stage_minor) == 10):
        return False
    if int(ctx.bonus_id) != int(BonusId.NUKE):
        return False
    major = int(ctx.state.quest_stage_major)
    if major in (2, 4, 5):
        return True
    return bool(ctx.state.hardcore) and major == 3


def _bonus_pick_suppress_quest_minor10_freeze(ctx: _BonusPickCtx) -> bool:
    if not (int(ctx.state.game_mode) == int(GameMode.QUESTS) and int(ctx.state.quest_stage_minor) == 10):
        return False
    if int(ctx.bonus_id) != int(BonusId.FREEZE):
        return False
    major = int(ctx.state.quest_stage_major)
    return major == 4 or (bool(ctx.state.hardcore) and major == 2)


def _bonus_pick_suppress_freeze_active(ctx: _BonusPickCtx) -> bool:
    return int(ctx.bonus_id) == int(BonusId.FREEZE) and float(ctx.state.bonuses.freeze) > 0.0


def _bonus_pick_suppress_shield_active(ctx: _BonusPickCtx) -> bool:
    if int(ctx.bonus_id) != int(BonusId.SHIELD):
        return False
    return any(player.shield_timer > 0.0 for player in ctx.players)


def _bonus_pick_suppress_weapon_when_fire_bullets_drop(ctx: _BonusPickCtx) -> bool:
    return int(ctx.bonus_id) == int(BonusId.WEAPON) and bool(ctx.has_fire_bullets_drop)


def _bonus_pick_suppress_weapon_when_favourite_weapon(ctx: _BonusPickCtx) -> bool:
    if int(ctx.bonus_id) != int(BonusId.WEAPON):
        return False
    return any(perk_active(player, PerkId.MY_FAVOURITE_WEAPON) for player in ctx.players)


def _bonus_pick_suppress_medikit_when_death_clock(ctx: _BonusPickCtx) -> bool:
    if int(ctx.bonus_id) != int(BonusId.MEDIKIT):
        return False
    return any(perk_active(player, PerkId.DEATH_CLOCK) for player in ctx.players)


def _bonus_pick_suppress_disabled(ctx: _BonusPickCtx) -> bool:
    return not _bonus_enabled(int(ctx.bonus_id))


_BONUS_PICK_SUPPRESS_RULES: tuple[_BonusPickSuppressRule, ...] = (
    _bonus_pick_suppress_active_shock_chain,
    _bonus_pick_suppress_quest_minor10_nuke,
    _bonus_pick_suppress_quest_minor10_freeze,
    _bonus_pick_suppress_freeze_active,
    _bonus_pick_suppress_shield_active,
    _bonus_pick_suppress_weapon_when_fire_bullets_drop,
    _bonus_pick_suppress_weapon_when_favourite_weapon,
    _bonus_pick_suppress_medikit_when_death_clock,
    _bonus_pick_suppress_disabled,
)


def bonus_pick_random_type(pool: BonusPool, state: GameplayState, players: list[PlayerState]) -> int:
    has_fire_bullets_drop = any(
        entry.bonus_id == int(BonusId.FIRE_BULLETS) and not entry.picked for entry in pool.entries
    )

    for _ in range(101):
        roll = int(state.rng.rand()) % 162 + 1
        bonus_id = _bonus_id_from_roll(roll, state.rng)
        if bonus_id <= 0:
            continue
        ctx = _BonusPickCtx(
            pool=pool,
            state=state,
            players=players,
            bonus_id=int(bonus_id),
            has_fire_bullets_drop=bool(has_fire_bullets_drop),
        )
        suppressed = False
        for rule in _BONUS_PICK_SUPPRESS_RULES:
            if rule(ctx):
                suppressed = True
                break
        if suppressed:
            continue
        return bonus_id
    return int(BonusId.POINTS)
