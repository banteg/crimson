from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from grim.geom import Vec2

from ..creatures.spawn import CreatureFlags


class CreatureForPerks(Protocol):
    active: bool
    pos: Vec2
    hp: float
    flags: CreatureFlags
    hitbox_size: float
    collision_timer: float
    reward_value: float
    size: float


@dataclass(slots=True)
class PerkEffectIntervals:
    """Global thresholds used by perk timers in `player_update`.

    These are global (not per-player) in crimsonland.exe: `flt_473310`,
    `flt_473314`, and `flt_473318`.
    """

    man_bomb: float = 4.0
    fire_cough: float = 2.0
    hot_tempered: float = 2.0


@dataclass(slots=True)
class PerkSelectionState:
    pending_count: int = 0
    choices: list[int] = field(default_factory=list)
    choices_dirty: bool = True
    capture_player_perk_counts_known: bool = True
