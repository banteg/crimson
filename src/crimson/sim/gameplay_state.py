from __future__ import annotations

from typing import TYPE_CHECKING, cast

import msgspec

from grim.geom import Vec2
from grim.rand import Crand, CrandLike
from grim.sfx_map import SfxId

from ..bonuses.hud import BonusHudState
from ..bonuses.pool import BonusPool
from ..effects import EffectPool, ParticlePool, SpriteEffectPool
from ..game_modes import GameMode
from ..perks.state import PerkEffectIntervals, PerkSelectionState
from ..projectiles.runtime import ProjectilePool, SecondaryProjectilePool
from ..quests.level import QuestLevel
from ..tutorial.state import TutorialOverlayState, TutorialState
from ..typo.state import TypoState
from ..weapons import WEAPON_TABLE, WeaponId
from .state_types import PERK_COUNT_SIZE

if TYPE_CHECKING:
    from ..persistence.save_status import GameStatus

WEAPON_COUNT_SIZE = max(int(entry.weapon_id) for entry in WEAPON_TABLE) + 1

WEAPON_USAGE_TIME_SLOT_COUNT = 64

class BonusTimers(msgspec.Struct):
    weapon_power_up: float = 0.0
    reflex_boost: float = 0.0
    energizer: float = 0.0
    double_experience: float = 0.0
    freeze: float = 0.0

class GameplayState(msgspec.Struct):
    rng: CrandLike = msgspec.field(default_factory=lambda: Crand(0xBEEF))
    effects: EffectPool = msgspec.field(default_factory=EffectPool)
    particles: ParticlePool = cast(ParticlePool, None)
    sprite_effects: SpriteEffectPool = cast(SpriteEffectPool, None)
    projectiles: ProjectilePool = msgspec.field(default_factory=ProjectilePool)
    secondary_projectiles: SecondaryProjectilePool = msgspec.field(default_factory=SecondaryProjectilePool)
    bonuses: BonusTimers = msgspec.field(default_factory=BonusTimers)
    time_scale_active: bool = False
    perk_intervals: PerkEffectIntervals = msgspec.field(default_factory=PerkEffectIntervals)
    lean_mean_exp_timer: float = 0.25
    jinxed_timer: float = 0.0
    plaguebearer_infection_count: int = 0
    perk_selection: PerkSelectionState = msgspec.field(default_factory=PerkSelectionState)
    sfx_queue: list[SfxId] = msgspec.field(default_factory=list)
    game_mode: GameMode = GameMode.SURVIVAL
    demo_mode_active: bool = False
    hardcore: bool = False
    preserve_bugs: bool = False
    status: GameStatus | None = None
    quest_level: QuestLevel | None = None
    tutorial: TutorialState = msgspec.field(default_factory=TutorialState)
    tutorial_overlay: TutorialOverlayState = msgspec.field(default_factory=TutorialOverlayState)
    typo: TypoState = msgspec.field(default_factory=TypoState)
    perk_available: list[bool] = msgspec.field(default_factory=lambda: [False] * PERK_COUNT_SIZE)
    weapon_available: list[bool] = msgspec.field(default_factory=lambda: [False] * WEAPON_COUNT_SIZE)
    friendly_fire_enabled: bool = False
    bonus_spawn_guard: bool = False
    player_alt_weapon_swap_cooldown_ms: int = 0
    bonus_hud: BonusHudState = msgspec.field(default_factory=BonusHudState)
    bonus_pool: BonusPool = msgspec.field(default_factory=BonusPool)
    shock_chain_links_left: int = 0
    shock_chain_projectile_id: int = -1
    survival_reward_weapon_guard_id: WeaponId = WeaponId.PISTOL
    survival_reward_handout_enabled: bool = True
    survival_reward_fire_seen: bool = False
    survival_reward_damage_seen: bool = False
    survival_recent_death_pos: list[Vec2] = msgspec.field(default_factory=lambda: [Vec2(), Vec2(), Vec2()])
    survival_recent_death_count: int = 0
    camera_shake_offset: Vec2 = Vec2()
    camera_shake_timer: float = 0.0
    camera_shake_pulses: int = 0
    shots_fired: list[int] = msgspec.field(default_factory=lambda: [0] * 4)
    shots_fired_total: int = 0
    shots_hit: list[int] = msgspec.field(default_factory=lambda: [0] * 4)
    player_spread_damping_scalar: float = 1.0
    player_spread_damping_gate: float = 0.0
    weapon_shots_fired: list[list[int]] = msgspec.field(
        default_factory=lambda: [[0] * WEAPON_COUNT_SIZE for _ in range(4)],
    )
    weapon_usage_time: list[int] = msgspec.field(default_factory=lambda: [0] * WEAPON_USAGE_TIME_SLOT_COUNT)
    highscore_score_xp: int = 0
    debug_god_mode: bool = False

    def __post_init__(self) -> None:
        self.particles = ParticlePool(rng=self.rng)
        self.sprite_effects = SpriteEffectPool(rng=self.rng)
