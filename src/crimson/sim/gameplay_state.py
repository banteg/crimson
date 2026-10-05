from __future__ import annotations

from typing import cast

import msgspec

from grim.geom import Vec2
from grim.rand import Crand, CrandLike
from grim.sfx_types import SfxRequest

from ..bonuses.hud import BonusHudState
from ..bonuses.pool import BonusPool
from ..effects import EffectPool, ParticlePool, SpriteEffectPool
from ..game_modes import GameMode
from ..perks.state import PerkEffectIntervals, PerkSelectionState
from ..persistence.save_status import GameStatus, GameStatusData
from ..projectiles.runtime import ProjectilePool, SecondaryProjectilePool
from ..quests.level import QuestLevel
from ..tutorial.state import TutorialOverlayState, TutorialState
from ..typo.state import TypoState
from ..weapons import WEAPON_TABLE, WeaponId
from .state_types import PERK_COUNT_SIZE, PerkCounts, PlayerState

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
    # Native `run_active`: the death transition clears it, so the run-down skips
    # `bonus_update`, the quest timeline and Reflex Boosted.
    run_active: bool = True
    # Native `player_state_table[1]` in a one-player run: creatures turn on it once player 0 is dead.
    dormant_player: PlayerState = msgspec.field(default_factory=lambda: PlayerState(index=1, pos=Vec2()))
    perk_intervals: PerkEffectIntervals = msgspec.field(default_factory=PerkEffectIntervals)
    # Native `perk_lean_mean_exp_tick_timer_s`: a fresh game starts it at 0, so it fires on the first tick.
    lean_mean_exp_timer: float = 0.0
    jinxed_timer: float = 0.0
    plaguebearer_infection_count: int = 0
    perks: PerkCounts = msgspec.field(default_factory=PerkCounts)
    perk_selection: PerkSelectionState = msgspec.field(default_factory=PerkSelectionState)
    sfx_queue: list[SfxRequest] = msgspec.field(default_factory=list)
    game_mode: GameMode = GameMode.SURVIVAL
    detail_preset: int = 5
    violence_disabled: int = 0
    # Native `music_playlist_randomized_latch`: the first projectile hit has started the game tune.
    game_tune_started: bool = False
    hardcore: bool = False
    # The global quest retry counter; hardcore creature spawns clear it.
    quest_fail_retry_count: int = 0
    preserve_bugs: bool = False
    status: GameStatus = msgspec.field(default_factory=lambda: GameStatus.detached(GameStatusData()))
    quest_level: QuestLevel | None = None
    tutorial: TutorialState = msgspec.field(default_factory=TutorialState)
    tutorial_overlay: TutorialOverlayState = msgspec.field(default_factory=TutorialOverlayState)
    typo: TypoState = msgspec.field(default_factory=TypoState)
    perk_available: list[bool] = msgspec.field(default_factory=lambda: [False] * PERK_COUNT_SIZE)
    weapon_available: list[bool] = msgspec.field(default_factory=lambda: [False] * WEAPON_COUNT_SIZE)
    friendly_fire_enabled: bool = False
    scripted_burst_active: bool = False
    player_alt_weapon_swap_cooldown_ms: int = 0
    bonus_hud: BonusHudState = msgspec.field(default_factory=BonusHudState)
    bonus_pool: BonusPool = msgspec.field(default_factory=BonusPool)
    shock_chain_links_left: int = 0
    shock_chain_projectile_id: int = -1
    survival_reward_weapon_guard_id: WeaponId = WeaponId.PISTOL
    survival_shrinkifier_handout_enabled: bool = True
    survival_reward_fire_seen: bool = False
    survival_reward_damage_seen: bool = False
    survival_first_kill_pos: list[Vec2] = msgspec.field(default_factory=lambda: [Vec2(), Vec2(), Vec2()])
    survival_first_kill_count: int = 0
    camera_shake_offset: Vec2 = Vec2()
    camera_shake_timer: float = 0.0
    camera_shake_pulses: int = 0
    # Native `highscore_record_shots_fired` / `_hit`: one count for every player.
    shots_fired: int = 0
    shots_hit: int = 0
    player_spread_damping_scalar: float = 1.0
    player_spread_damping_gate: float = 0.0
    weapon_shots_fired: list[list[int]] = msgspec.field(
        default_factory=lambda: [[0] * WEAPON_COUNT_SIZE for _ in range(4)],
    )
    weapon_usage_time: list[int] = msgspec.field(default_factory=lambda: [0] * WEAPON_USAGE_TIME_SLOT_COUNT)
    highscore_score_xp: int = 0
    debug_god_mode: bool = False

    def __post_init__(self) -> None:
        self.particles = ParticlePool()
        self.sprite_effects = SpriteEffectPool()
