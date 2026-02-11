from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import TYPE_CHECKING, Callable, Protocol, Sequence

from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand
from .bonuses import BONUS_BY_ID, BonusId
from .bonuses.freeze import DeferredFreezeCorpseFx
from .bonuses.hud import BonusHudState
from .bonuses.pool import BonusPool
from .creatures.spawn import CreatureFlags
from .effects import EffectPool, FxQueue, ParticlePool, SpriteEffectPool
from .game_modes import GameMode
from .math_parity import f32
from .perks import PerkFlags, PerkId, PERK_BY_ID, PERK_TABLE
from .projectiles import (
    Damageable,
    ProjectilePool,
    ProjectileTypeId,
    SecondaryProjectilePool,
    SecondaryProjectileTypeId,
)
from .weapons import (
    WEAPON_BY_ID,
    WEAPON_TABLE,
    Weapon,
    WeaponId,
    projectile_type_id_from_weapon_id,
    weapon_entry_for_projectile_type_id,
)
from .sim.input import PlayerInput
from .sim.state_types import PERK_COUNT_SIZE, PlayerState

if TYPE_CHECKING:
    from .persistence.save_status import GameStatus


class _HasPos(Protocol):
    pos: Vec2


class _CreatureForPerks(Protocol):
    active: bool
    pos: Vec2
    hp: float
    flags: CreatureFlags
    hitbox_size: float
    collision_timer: float
    reward_value: float
    size: float


PERK_ID_MAX = max(int(meta.perk_id) for meta in PERK_TABLE)
WEAPON_COUNT_SIZE = max(int(entry.weapon_id) for entry in WEAPON_TABLE) + 1


@dataclass(slots=True)
class BonusTimers:
    weapon_power_up: float = 0.0
    reflex_boost: float = 0.0
    energizer: float = 0.0
    double_experience: float = 0.0
    freeze: float = 0.0


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


WEAPON_DROP_ID_COUNT = 0x21  # weapon ids 1..33


@dataclass(slots=True)
class GameplayState:
    rng: Crand = field(default_factory=lambda: Crand(0xBEEF))
    effects: EffectPool = field(default_factory=EffectPool)
    particles: ParticlePool = field(init=False)
    sprite_effects: SpriteEffectPool = field(init=False)
    projectiles: ProjectilePool = field(default_factory=ProjectilePool)
    secondary_projectiles: SecondaryProjectilePool = field(default_factory=SecondaryProjectilePool)
    bonuses: BonusTimers = field(default_factory=BonusTimers)
    time_scale_active: bool = False
    perk_intervals: PerkEffectIntervals = field(default_factory=PerkEffectIntervals)
    lean_mean_exp_timer: float = 0.25
    jinxed_timer: float = 0.0
    plaguebearer_infection_count: int = 0
    perk_selection: PerkSelectionState = field(default_factory=PerkSelectionState)
    sfx_queue: list[str] = field(default_factory=list)
    game_mode: int = int(GameMode.SURVIVAL)
    demo_mode_active: bool = False
    hardcore: bool = False
    preserve_bugs: bool = False
    status: GameStatus | None = None
    quest_stage_major: int = 0
    quest_stage_minor: int = 0
    perk_available: list[bool] = field(default_factory=lambda: [False] * PERK_COUNT_SIZE)
    _perk_available_unlock_index: int = -1
    weapon_available: list[bool] = field(default_factory=lambda: [False] * WEAPON_COUNT_SIZE)
    _weapon_available_game_mode: int = -1
    _weapon_available_unlock_index: int = -1
    _weapon_available_unlock_index_full: int = -1
    friendly_fire_enabled: bool = False
    bonus_spawn_guard: bool = False
    bonus_hud: BonusHudState = field(default_factory=BonusHudState)
    bonus_pool: BonusPool = field(default_factory=BonusPool)
    deferred_freeze_corpse_fx: list[DeferredFreezeCorpseFx] = field(default_factory=list)
    shock_chain_links_left: int = 0
    shock_chain_projectile_id: int = -1
    camera_shake_offset: Vec2 = field(default_factory=Vec2)
    camera_shake_timer: float = 0.0
    camera_shake_pulses: int = 0
    shots_fired: list[int] = field(default_factory=lambda: [0] * 4)
    shots_hit: list[int] = field(default_factory=lambda: [0] * 4)
    weapon_shots_fired: list[list[int]] = field(default_factory=lambda: [[0] * WEAPON_COUNT_SIZE for _ in range(4)])
    debug_god_mode: bool = False

    def __post_init__(self) -> None:
        rand = self.rng.rand
        self.particles = ParticlePool(rand=rand)
        self.sprite_effects = SpriteEffectPool(rand=rand)


def build_gameplay_state() -> GameplayState:
    return GameplayState()


def perk_count_get(player: PlayerState, perk_id: PerkId) -> int:
    idx = int(perk_id)
    if idx < 0:
        return 0
    if idx >= len(player.perk_counts):
        return 0
    return int(player.perk_counts[idx])


def perk_active(player: PlayerState, perk_id: PerkId) -> bool:
    return perk_count_get(player, perk_id) > 0


def _creature_find_in_radius(creatures: Sequence[_CreatureForPerks], *, pos: Vec2, radius: float, start_index: int) -> int:
    """Port of `creature_find_in_radius` (0x004206a0)."""

    start_index = max(0, int(start_index))
    max_index = min(len(creatures), 0x180)
    if start_index >= max_index:
        return -1

    radius = float(radius)

    for idx in range(start_index, max_index):
        creature = creatures[idx]
        if not creature.active:
            continue

        dist = (creature.pos - pos).length() - radius
        threshold = float(creature.size) * 0.14285715 + 3.0
        if threshold < dist:
            continue
        if float(creature.hitbox_size) < 5.0:
            continue
        return idx
    return -1


@dataclass(slots=True)
class _PerksUpdateEffectsCtx:
    state: GameplayState
    players: list[PlayerState]
    dt: float
    creatures: Sequence[_CreatureForPerks] | None
    fx_queue: FxQueue | None
    _aim_target: int | None = None

    def aim_target(self) -> int:
        if self._aim_target is not None:
            return int(self._aim_target)

        target = -1
        if (
            self.players
            and self.creatures is not None
            and (perk_active(self.players[0], PerkId.PYROKINETIC) or perk_active(self.players[0], PerkId.EVIL_EYES))
        ):
            target = _creature_find_in_radius(
                self.creatures,
                pos=self.players[0].aim,
                radius=12.0,
                start_index=0,
            )
        self._aim_target = int(target)
        return int(target)


_PerksUpdateEffectsStep = Callable[[_PerksUpdateEffectsCtx], None]


def _perks_update_regeneration(ctx: _PerksUpdateEffectsCtx) -> None:
    if ctx.players and perk_active(ctx.players[0], PerkId.REGENERATION) and (ctx.state.rng.rand() & 1):
        for player in ctx.players:
            if not (0.0 < float(player.health) < 100.0):
                continue
            player.health = float(player.health) + ctx.dt
            if player.health > 100.0:
                player.health = 100.0


def _perks_update_lean_mean_exp_machine(ctx: _PerksUpdateEffectsCtx) -> None:
    ctx.state.lean_mean_exp_timer -= ctx.dt
    if ctx.state.lean_mean_exp_timer < 0.0:
        ctx.state.lean_mean_exp_timer = 0.25
        for player in ctx.players:
            perk_count = perk_count_get(player, PerkId.LEAN_MEAN_EXP_MACHINE)
            if perk_count > 0:
                player.experience += perk_count * 10


def _perks_update_death_clock(ctx: _PerksUpdateEffectsCtx) -> None:
    for player in ctx.players:
        if not perk_active(player, PerkId.DEATH_CLOCK):
            continue

        if float(player.health) <= 0.0:
            player.health = 0.0
        else:
            player.health = float(player.health) - ctx.dt * 3.3333333


def _perks_update_evil_eyes_target(ctx: _PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return

    target = ctx.aim_target()
    player0 = ctx.players[0]
    player0.evil_eyes_target_creature = target if perk_active(player0, PerkId.EVIL_EYES) else -1


def _perks_update_pyrokinetic(ctx: _PerksUpdateEffectsCtx) -> None:
    if not ctx.players:
        return
    if ctx.creatures is None:
        return
    if not perk_active(ctx.players[0], PerkId.PYROKINETIC):
        return

    target = ctx.aim_target()
    if target == -1:
        return

    creature = ctx.creatures[target]
    creature.collision_timer = float(creature.collision_timer) - ctx.dt
    if creature.collision_timer < 0.0:
        creature.collision_timer = 0.5
        for intensity in (0.8, 0.6, 0.4, 0.3, 0.2):
            angle = float(int(ctx.state.rng.rand()) % 0x274) * 0.01
            ctx.state.particles.spawn_particle(pos=creature.pos, angle=angle, intensity=float(intensity))
        if ctx.fx_queue is not None:
            ctx.fx_queue.add_random(pos=creature.pos, rand=ctx.state.rng.rand)


def _perks_update_jinxed_timer(ctx: _PerksUpdateEffectsCtx) -> None:
    if ctx.state.jinxed_timer >= 0.0:
        ctx.state.jinxed_timer -= ctx.dt


def _perks_update_jinxed(ctx: _PerksUpdateEffectsCtx) -> None:
    if ctx.state.jinxed_timer >= 0.0:
        return
    if not ctx.players:
        return
    if not perk_active(ctx.players[0], PerkId.JINXED):
        return

    player = ctx.players[0]
    if int(ctx.state.rng.rand()) % 10 == 3:
        player.health = float(player.health) - 5.0
        if ctx.fx_queue is not None:
            ctx.fx_queue.add_random(pos=player.pos, rand=ctx.state.rng.rand)
            ctx.fx_queue.add_random(pos=player.pos, rand=ctx.state.rng.rand)

    ctx.state.jinxed_timer = float(int(ctx.state.rng.rand()) % 0x14) * 0.1 + float(ctx.state.jinxed_timer) + 2.0

    if float(ctx.state.bonuses.freeze) <= 0.0 and ctx.creatures is not None:
        pool_mod = min(0x17F, len(ctx.creatures))
        if pool_mod <= 0:
            return

        idx = int(ctx.state.rng.rand()) % pool_mod
        attempts = 0
        while attempts < 10 and not ctx.creatures[idx].active:
            idx = int(ctx.state.rng.rand()) % pool_mod
            attempts += 1
        if not ctx.creatures[idx].active:
            return

        creature = ctx.creatures[idx]
        creature.hp = -1.0
        creature.hitbox_size = float(creature.hitbox_size) - ctx.dt * 20.0
        player.experience = int(float(player.experience) + float(creature.reward_value))
        ctx.state.sfx_queue.append("sfx_trooper_inpain_01")


def _perks_update_player_bonus_timers(ctx: _PerksUpdateEffectsCtx) -> None:
    # Native `perks_update_effects` decrements per-player shield/fire-bullets/speed
    # timers before `player_update` reads them for this frame.
    for player in ctx.players:
        if player.shield_timer <= 0.0:
            player.shield_timer = 0.0
        else:
            player.shield_timer = float(player.shield_timer) - float(ctx.dt)

        if player.fire_bullets_timer <= 0.0:
            player.fire_bullets_timer = 0.0
        else:
            player.fire_bullets_timer = float(player.fire_bullets_timer) - float(ctx.dt)

        if player.speed_bonus_timer <= 0.0:
            player.speed_bonus_timer = 0.0
        else:
            player.speed_bonus_timer = float(player.speed_bonus_timer) - float(ctx.dt)


_PERKS_UPDATE_EFFECT_STEPS: tuple[_PerksUpdateEffectsStep, ...] = (
    _perks_update_player_bonus_timers,
    _perks_update_regeneration,
    _perks_update_lean_mean_exp_machine,
    _perks_update_death_clock,
    _perks_update_evil_eyes_target,
    _perks_update_pyrokinetic,
    _perks_update_jinxed_timer,
    _perks_update_jinxed,
)


def perks_update_effects(
    state: GameplayState,
    players: list[PlayerState],
    dt: float,
    *,
    creatures: Sequence[_CreatureForPerks] | None = None,
    fx_queue: FxQueue | None = None,
) -> None:
    """Port subset of `perks_update_effects` (0x00406b40)."""

    dt = float(dt)
    if dt <= 0.0:
        return
    ctx = _PerksUpdateEffectsCtx(
        state=state,
        players=players,
        dt=dt,
        creatures=creatures,
        fx_queue=fx_queue,
    )
    for step in _PERKS_UPDATE_EFFECT_STEPS:
        step(ctx)


def award_experience(state: GameplayState, player: PlayerState, amount: int) -> int:
    """Grant XP while honoring active bonus multipliers."""

    xp = int(amount)
    if xp <= 0:
        return 0
    if state.bonuses.double_experience > 0.0:
        xp *= 2
    player.experience += xp
    return xp


def survival_level_threshold(level: int) -> int:
    """Return the XP threshold for advancing past the given level."""

    level = max(1, int(level))
    return int(1000.0 + (math.pow(float(level), 1.8) * 1000.0))


def survival_check_level_up(player: PlayerState, perk_state: PerkSelectionState) -> int:
    """Advance survival levels if XP exceeds thresholds, returning number of level-ups."""

    advanced = 0
    while player.experience > survival_level_threshold(player.level):
        player.level += 1
        perk_state.pending_count += 1
        perk_state.choices_dirty = True
        advanced += 1
    return advanced


def perk_choice_count(player: PlayerState) -> int:
    if perk_active(player, PerkId.PERK_MASTER):
        return 7
    if perk_active(player, PerkId.PERK_EXPERT):
        return 6
    return 5


_PERK_BASE_AVAILABLE_MAX_ID = int(PerkId.BONUS_MAGNET)  # perks_rebuild_available @ 0x0042fc30
_PERK_ALWAYS_AVAILABLE: tuple[PerkId, ...] = (
    PerkId.MAN_BOMB,
    PerkId.LIVING_FORTRESS,
    PerkId.FIRE_CAUGH,
    PerkId.TOUGH_RELOADER,
)

_DEATH_CLOCK_BLOCKED: frozenset[PerkId] = frozenset(
    (
        PerkId.JINXED,
        PerkId.BREATHING_ROOM,
        PerkId.GRIM_DEAL,
        PerkId.HIGHLANDER,
        PerkId.FATAL_LOTTERY,
        PerkId.AMMUNITION_WITHIN,
        PerkId.INFERNAL_CONTRACT,
        PerkId.REGENERATION,
        PerkId.GREATER_REGENERATION,
        PerkId.THICK_SKINNED,
        PerkId.BANDAGE,
    )
)

_PERK_RARITY_GATE: frozenset[PerkId] = frozenset(
    (
        PerkId.JINXED,
        PerkId.AMMUNITION_WITHIN,
        PerkId.ANXIOUS_LOADER,
        PerkId.MONSTER_VISION,
    )
)


def perks_rebuild_available(state: GameplayState) -> None:
    """Rebuild quest unlock driven `perk_meta_table[perk_id].available` flags.

    Port of `perks_rebuild_available` (0x0042fc30).
    """

    unlock_index = 0
    if state.status is not None:
        try:
            unlock_index = int(state.status.quest_unlock_index)
        except Exception:
            unlock_index = 0

    if int(state._perk_available_unlock_index) == unlock_index:
        return

    available = state.perk_available
    for idx in range(len(available)):
        available[idx] = False

    for perk_id in range(1, _PERK_BASE_AVAILABLE_MAX_ID + 1):
        if 0 <= perk_id < len(available):
            available[perk_id] = True

    for perk_id in _PERK_ALWAYS_AVAILABLE:
        idx = int(perk_id)
        if 0 <= idx < len(available):
            available[idx] = True

    if unlock_index > 0:
        try:
            from .quests import all_quests

            quests = all_quests()
        except Exception:
            quests = []

        for quest in quests[:unlock_index]:
            perk_id = int(getattr(quest, "unlock_perk_id", 0) or 0)
            if 0 < perk_id < len(available):
                available[perk_id] = True

    available[int(PerkId.ANTIPERK)] = False
    state._perk_available_unlock_index = unlock_index


def perk_can_offer(
    state: GameplayState, player: PlayerState, perk_id: PerkId, *, game_mode: int, player_count: int
) -> bool:
    """Return whether `perk_id` is eligible for selection.

    Used by `perk_select_random` and modeled after `perk_can_offer` (0x0042fb10).
    """

    if perk_id == PerkId.ANTIPERK:
        return False

    # Hardcore quest 2-10 blocks poison-related perks.
    if (
        int(game_mode) == int(GameMode.QUESTS)
        and state.hardcore
        and int(state.quest_stage_major) == 2
        and int(state.quest_stage_minor) == 10
        and perk_id in (PerkId.POISON_BULLETS, PerkId.VEINS_OF_POISON, PerkId.PLAGUEBEARER)
    ):
        return False

    meta = PERK_BY_ID.get(int(perk_id))
    if meta is None:
        return False

    flags = meta.flags
    # Native `perk_can_offer` treats these metadata bits as allow-lists for
    # specific runtime modes, not "only in this mode":
    # - in quest mode, offered perks must have bit 0x1 set
    # - in two-player mode, offered perks must have bit 0x2 set
    if int(game_mode) == int(GameMode.QUESTS) and (flags & PerkFlags.MODE_3_ONLY) == 0:
        return False
    if int(player_count) == 2 and (flags & PerkFlags.TWO_PLAYER_ONLY) == 0:
        return False

    if meta.prereq and any(perk_count_get(player, req) <= 0 for req in meta.prereq):
        return False

    return True


def perk_select_random(state: GameplayState, player: PlayerState, *, game_mode: int, player_count: int) -> PerkId:
    """Randomly select an eligible perk id.

    Port of `perk_select_random` (0x0042fbd0).
    """

    perks_rebuild_available(state)

    for _ in range(1000):
        perk_id = PerkId(int(state.rng.rand()) % PERK_ID_MAX + 1)
        if not (0 <= int(perk_id) < len(state.perk_available)):
            continue
        if not state.perk_available[int(perk_id)]:
            continue
        if perk_can_offer(state, player, perk_id, game_mode=game_mode, player_count=player_count):
            return perk_id

    return PerkId.INSTANT_WINNER


def _perk_offerable_mask(
    state: GameplayState,
    player: PlayerState,
    *,
    game_mode: int,
    player_count: int,
) -> list[bool]:
    """Build a cached `perk_select_random` eligibility mask for `1..PERK_ID_MAX`."""

    perks_rebuild_available(state)
    offerable: list[bool] = [False] * (PERK_ID_MAX + 1)
    max_perk_index = min(PERK_ID_MAX, len(state.perk_available) - 1)
    for perk_index in range(1, max_perk_index + 1):
        if not state.perk_available[perk_index]:
            continue
        perk_id = PerkId(perk_index)
        if perk_can_offer(state, player, perk_id, game_mode=game_mode, player_count=player_count):
            offerable[perk_index] = True
    return offerable


def perk_generate_choices(
    state: GameplayState,
    player: PlayerState,
    *,
    game_mode: int,
    player_count: int,
    count: int | None = None,
) -> list[PerkId]:
    """Generate a unique list of perk choices for the current selection."""

    if count is None:
        count = perk_choice_count(player)

    offerable_mask = _perk_offerable_mask(
        state,
        player,
        game_mode=game_mode,
        player_count=player_count,
    )
    player_perk_counts = player.perk_counts
    player_weapon_id = int(player.weapon_id)
    death_clock_active = int(player_perk_counts[int(PerkId.DEATH_CLOCK)]) > 0

    def _select_random_offer() -> PerkId:
        for _ in range(1000):
            perk_index = int(state.rng.rand()) % PERK_ID_MAX + 1
            if offerable_mask[perk_index]:
                return PerkId(perk_index)
        return PerkId.INSTANT_WINNER

    # `perks_generate_choices` always fills a fixed array of 7 entries, even if the UI
    # only shows 5/6 (Perk Expert/Master). Preserve RNG consumption by generating the
    # full list, then slicing.
    choices: list[PerkId] = [PerkId.ANTIPERK] * 7
    choice_index = 0

    # Quest 1-7 special-case: force Monster Vision as the first choice if not owned.
    if (
        int(state.quest_stage_major) == 1
        and int(state.quest_stage_minor) == 7
        and int(player_perk_counts[int(PerkId.MONSTER_VISION)]) == 0
    ):
        choices[0] = PerkId.MONSTER_VISION
        choice_index = 1

    while choice_index < 7:
        attempts = 0
        while True:
            attempts += 1
            perk_id = _select_random_offer()

            # Pyromaniac can only be offered if the current weapon is Flamethrower.
            if perk_id == PerkId.PYROMANIAC and player_weapon_id != int(WeaponId.FLAMETHROWER):
                continue

            if death_clock_active and perk_id in _DEATH_CLOCK_BLOCKED:
                continue

            # Global rarity gate: certain perks have a 25% chance to be rejected.
            if perk_id in _PERK_RARITY_GATE and (int(state.rng.rand()) & 3) == 1:
                continue

            meta = PERK_BY_ID.get(int(perk_id))
            flags = meta.flags if meta is not None else PerkFlags(0)
            stackable = (flags & PerkFlags.STACKABLE) != 0

            if attempts > 10_000 and stackable:
                break

            if perk_id in choices[:choice_index]:
                continue

            if stackable or int(player_perk_counts[int(perk_id)]) < 1 or attempts > 29_999:
                break

        choices[choice_index] = perk_id
        choice_index += 1

    if int(game_mode) == int(GameMode.TUTORIAL):
        choices = [
            PerkId.SHARPSHOOTER,
            PerkId.LONG_DISTANCE_RUNNER,
            PerkId.EVIL_EYES,
            PerkId.RADIOACTIVE,
            PerkId.FASTSHOT,
            PerkId.FASTSHOT,
            PerkId.FASTSHOT,
        ]

    return choices[: int(count)]


def _increment_perk_count(player: PlayerState, perk_id: PerkId, *, amount: int = 1) -> None:
    idx = int(perk_id)
    if 0 <= idx < len(player.perk_counts):
        player.perk_counts[idx] += int(amount)


@dataclass(slots=True)
class _PerkApplyCtx:
    state: GameplayState
    players: list[PlayerState]
    owner: PlayerState
    perk_id: PerkId
    perk_state: PerkSelectionState | None
    dt: float | None
    creatures: Sequence[_CreatureForPerks] | None

    def frame_dt(self) -> float:
        return float(self.dt) if self.dt is not None else 0.0


_PerkApplyHandler = Callable[[_PerkApplyCtx], None]


def _perk_apply_instant_winner(ctx: _PerkApplyCtx) -> None:
    ctx.owner.experience += 2500


def _perk_apply_fatal_lottery(ctx: _PerkApplyCtx) -> None:
    if ctx.state.rng.rand() & 1:
        ctx.owner.health = -1.0
    else:
        ctx.owner.experience += 10000


def _perk_apply_random_weapon(ctx: _PerkApplyCtx) -> None:
    current = int(ctx.owner.weapon_id)
    weapon_id = int(current)
    for _ in range(100):
        candidate = int(weapon_pick_random_available(ctx.state))
        weapon_id = candidate
        if candidate != int(WeaponId.PISTOL) and candidate != current:
            break
    weapon_assign_player(ctx.owner, weapon_id, state=ctx.state)


def _perk_apply_lifeline_50_50(ctx: _PerkApplyCtx) -> None:
    creatures = ctx.creatures
    if creatures is None:
        return

    kill_toggle = False
    for creature in creatures:
        if kill_toggle and creature.active and float(creature.hp) <= 500.0 and (int(creature.flags) & 0x04) == 0:
            creature.active = False
            ctx.state.effects.spawn_burst(
                pos=creature.pos,
                count=4,
                rand=ctx.state.rng.rand,
                detail_preset=5,
            )
        kill_toggle = not kill_toggle


def _perk_apply_thick_skinned(ctx: _PerkApplyCtx) -> None:
    for player in ctx.players:
        if player.health > 0.0:
            player.health = max(1.0, player.health * (2.0 / 3.0))


def _perk_apply_breathing_room(ctx: _PerkApplyCtx) -> None:
    for player in ctx.players:
        player.health -= player.health * (2.0 / 3.0)

    frame_dt = ctx.frame_dt()
    creatures = ctx.creatures
    if creatures is not None:
        for creature in creatures:
            if creature.active:
                creature.hitbox_size = float(creature.hitbox_size) - frame_dt

    ctx.state.bonus_spawn_guard = False


def _perk_apply_infernal_contract(ctx: _PerkApplyCtx) -> None:
    ctx.owner.level += 3
    if ctx.perk_state is not None:
        ctx.perk_state.pending_count += 3
        ctx.perk_state.choices_dirty = True
    for player in ctx.players:
        if player.health > 0.0:
            player.health = 0.1


def _perk_apply_grim_deal(ctx: _PerkApplyCtx) -> None:
    ctx.owner.health = -1.0
    ctx.owner.experience += int(ctx.owner.experience * 0.18)


def _perk_apply_ammo_maniac(ctx: _PerkApplyCtx) -> None:
    if len(ctx.players) > 1:
        for player in ctx.players[1:]:
            player.perk_counts[:] = ctx.owner.perk_counts
    for player in ctx.players:
        weapon_assign_player(player, int(player.weapon_id), state=ctx.state)


def _perk_apply_death_clock(ctx: _PerkApplyCtx) -> None:
    _increment_perk_count(
        ctx.owner,
        PerkId.REGENERATION,
        amount=-perk_count_get(ctx.owner, PerkId.REGENERATION),
    )
    _increment_perk_count(
        ctx.owner,
        PerkId.GREATER_REGENERATION,
        amount=-perk_count_get(ctx.owner, PerkId.GREATER_REGENERATION),
    )
    for player in ctx.players:
        if player.health > 0.0:
            player.health = 100.0


def _perk_apply_bandage(ctx: _PerkApplyCtx) -> None:
    for player in ctx.players:
        if player.health > 0.0:
            scale = float(ctx.state.rng.rand() % 50 + 1)
            player.health = min(100.0, player.health * scale)
            ctx.state.effects.spawn_burst(
                pos=player.pos,
                count=8,
                rand=ctx.state.rng.rand,
                detail_preset=5,
            )


def _perk_apply_my_favourite_weapon(ctx: _PerkApplyCtx) -> None:
    for player in ctx.players:
        player.clip_size += 2


def _perk_apply_plaguebearer(ctx: _PerkApplyCtx) -> None:
    for player in ctx.players:
        player.plaguebearer_active = True


_PERK_APPLY_HANDLERS: dict[PerkId, _PerkApplyHandler] = {
    PerkId.INSTANT_WINNER: _perk_apply_instant_winner,
    PerkId.FATAL_LOTTERY: _perk_apply_fatal_lottery,
    PerkId.RANDOM_WEAPON: _perk_apply_random_weapon,
    PerkId.LIFELINE_50_50: _perk_apply_lifeline_50_50,
    PerkId.THICK_SKINNED: _perk_apply_thick_skinned,
    PerkId.BREATHING_ROOM: _perk_apply_breathing_room,
    PerkId.INFERNAL_CONTRACT: _perk_apply_infernal_contract,
    PerkId.GRIM_DEAL: _perk_apply_grim_deal,
    PerkId.AMMO_MANIAC: _perk_apply_ammo_maniac,
    PerkId.DEATH_CLOCK: _perk_apply_death_clock,
    PerkId.BANDAGE: _perk_apply_bandage,
    PerkId.MY_FAVOURITE_WEAPON: _perk_apply_my_favourite_weapon,
    PerkId.PLAGUEBEARER: _perk_apply_plaguebearer,
}


def perk_apply(
    state: GameplayState,
    players: list[PlayerState],
    perk_id: PerkId,
    *,
    perk_state: PerkSelectionState | None = None,
    dt: float | None = None,
    creatures: Sequence[_CreatureForPerks] | None = None,
) -> None:
    """Apply immediate perk effects and increment the perk counter."""

    if not players:
        return
    owner = players[0]
    try:
        _increment_perk_count(owner, perk_id)
        handler = _PERK_APPLY_HANDLERS.get(perk_id)
        if handler is not None:
            handler(
                _PerkApplyCtx(
                    state=state,
                    players=players,
                    owner=owner,
                    perk_id=perk_id,
                    perk_state=perk_state,
                    dt=dt,
                    creatures=creatures,
                )
            )
    finally:
        if len(players) > 1:
            for player in players[1:]:
                player.perk_counts[:] = owner.perk_counts


def perk_auto_pick(
    state: GameplayState,
    players: list[PlayerState],
    perk_state: PerkSelectionState,
    *,
    game_mode: int,
    player_count: int | None = None,
    dt: float | None = None,
    creatures: Sequence[_CreatureForPerks] | None = None,
) -> list[PerkId]:
    """Resolve pending perks by auto-selecting from generated choices."""

    if not players:
        return []
    if player_count is None:
        player_count = len(players)
    picks: list[PerkId] = []
    while perk_state.pending_count > 0:
        if perk_state.choices_dirty or not perk_state.choices:
            perk_state.choices = [
                int(perk)
                for perk in perk_generate_choices(state, players[0], game_mode=game_mode, player_count=player_count)
            ]
            perk_state.choices_dirty = False
        if not perk_state.choices:
            break
        idx = int(state.rng.rand() % len(perk_state.choices))
        perk_id = PerkId(perk_state.choices[idx])
        perk_apply(state, players, perk_id, perk_state=perk_state, dt=dt, creatures=creatures)
        picks.append(perk_id)
        perk_state.pending_count -= 1
        perk_state.choices_dirty = True
    return picks


def perk_selection_current_choices(
    state: GameplayState,
    players: list[PlayerState],
    perk_state: PerkSelectionState,
    *,
    game_mode: int,
    player_count: int | None = None,
) -> list[PerkId]:
    """Return the current perk choices, generating them if needed.

    Mirrors `perk_choices_dirty` + `perks_generate_choices` before entering the
    perk selection screen (state 6).
    """

    if not players:
        return []
    if player_count is None:
        player_count = len(players)
    if perk_state.choices_dirty or not perk_state.choices:
        perk_state.choices = [
            int(perk)
            for perk in perk_generate_choices(state, players[0], game_mode=game_mode, player_count=player_count)
        ]
        perk_state.choices_dirty = False
    return [PerkId(perk_id) for perk_id in perk_state.choices]


def perk_selection_pick(
    state: GameplayState,
    players: list[PlayerState],
    perk_state: PerkSelectionState,
    choice_index: int,
    *,
    game_mode: int,
    player_count: int | None = None,
    dt: float | None = None,
    creatures: Sequence[_CreatureForPerks] | None = None,
) -> PerkId | None:
    """Pick a perk from the current choice list and apply it.

    On success, decrements `pending_count` (one perk resolved) and marks the
    choice list dirty, matching `perk_selection_screen_update`.
    """

    if perk_state.pending_count <= 0:
        return None
    choices = perk_selection_current_choices(state, players, perk_state, game_mode=game_mode, player_count=player_count)
    if not choices:
        return None
    idx = int(choice_index)
    if idx < 0 or idx >= len(choices):
        return None
    perk_id = choices[idx]
    perk_apply(state, players, perk_id, perk_state=perk_state, dt=dt, creatures=creatures)
    perk_state.pending_count = max(0, int(perk_state.pending_count) - 1)
    perk_state.choices_dirty = True
    return perk_id


def survival_progression_update(
    state: GameplayState,
    players: list[PlayerState],
    *,
    game_mode: int,
    player_count: int | None = None,
    auto_pick: bool = True,
    dt: float | None = None,
    creatures: Sequence[_CreatureForPerks] | None = None,
) -> list[PerkId]:
    """Advance survival level/perk progression and optionally auto-pick perks."""

    if not players:
        return []
    if player_count is None:
        player_count = len(players)
    survival_check_level_up(players[0], state.perk_selection)
    if auto_pick:
        return perk_auto_pick(
            state,
            players,
            state.perk_selection,
            game_mode=game_mode,
            player_count=player_count,
            dt=dt,
            creatures=creatures,
        )
    return []


def _owner_id_for_player(player_index: int) -> int:
    # crimsonland.exe uses -1/-2/-3 for players (and sometimes -100 in demo paths).
    return -1 - int(player_index)


def _owner_id_for_player_projectiles(state: "GameplayState", player_index: int) -> int:
    if not state.friendly_fire_enabled:
        return -100
    return _owner_id_for_player(player_index)


def _weapon_entry(weapon_id: int) -> Weapon | None:
    return WEAPON_BY_ID.get(int(weapon_id))


def weapon_refresh_available(state: "GameplayState") -> None:
    """Rebuild `weapon_table[weapon_id].unlocked` equivalents from quest progression.

    Port of `weapon_refresh_available` (0x00452e40).
    """

    unlock_index = 0
    unlock_index_full = 0
    status = state.status
    if status is not None:
        try:
            unlock_index = int(status.quest_unlock_index)
        except Exception:
            unlock_index = 0
        try:
            unlock_index_full = int(status.quest_unlock_index_full)
        except Exception:
            unlock_index_full = 0

    game_mode = int(state.game_mode)
    if (
        int(state._weapon_available_game_mode) == game_mode
        and int(state._weapon_available_unlock_index) == unlock_index
        and int(state._weapon_available_unlock_index_full) == unlock_index_full
    ):
        return

    # Clear unlocked flags.
    available = state.weapon_available
    for idx in range(len(available)):
        available[idx] = False

    # Pistol is always available.
    pistol_id = int(WeaponId.PISTOL)
    if 0 <= pistol_id < len(available):
        available[pistol_id] = True

    # Unlock weapons from the quest list (first `quest_unlock_index` entries).
    if unlock_index > 0:
        try:
            from .quests import all_quests

            quests = all_quests()
        except Exception:
            quests = []

        for quest in quests[:unlock_index]:
            weapon_id = int(getattr(quest, "unlock_weapon_id", 0) or 0)
            if 0 < weapon_id < len(available):
                available[weapon_id] = True

    # Survival default loadout: Assault Rifle, Shotgun, Submachine Gun.
    if game_mode == int(GameMode.SURVIVAL):
        for weapon_id in (WeaponId.ASSAULT_RIFLE, WeaponId.SHOTGUN, WeaponId.SUBMACHINE_GUN):
            idx = int(weapon_id)
            if 0 <= idx < len(available):
                available[idx] = True

    # Secret unlock: Splitter Gun (weapon id 29) becomes available once the hardcore
    # unlock track reaches stage 5 (quest_unlock_index_full >= 40).
    if (not state.demo_mode_active) and unlock_index_full >= 0x28:
        splitter_id = int(WeaponId.SPLITTER_GUN)
        if 0 <= splitter_id < len(available):
            available[splitter_id] = True

    state._weapon_available_game_mode = game_mode
    state._weapon_available_unlock_index = unlock_index
    state._weapon_available_unlock_index_full = unlock_index_full


def weapon_pick_random_available(state: "GameplayState") -> int:
    """Select a random available weapon id (1..33).

    Port of `weapon_pick_random_available` (0x00452cd0).
    """

    weapon_refresh_available(state)
    status = state.status

    for _ in range(1000):
        base_rand = int(state.rng.rand())
        weapon_id = base_rand % WEAPON_DROP_ID_COUNT + 1

        # Bias: used weapons have a 50% chance to reroll once.
        if status is not None:
            try:
                if status.weapon_usage_count(weapon_id) != 0:
                    if (int(state.rng.rand()) & 1) == 0:
                        base_rand = int(state.rng.rand())
                        weapon_id = base_rand % WEAPON_DROP_ID_COUNT + 1
            except Exception:
                pass

        if not (0 <= weapon_id < len(state.weapon_available)):
            continue
        if not state.weapon_available[weapon_id]:
            continue

        # Quest 5-10 special-case: suppress Ion Cannon.
        if (
            int(state.game_mode) == int(GameMode.QUESTS)
            and int(state.quest_stage_major) == 5
            and int(state.quest_stage_minor) == 10
            and weapon_id == int(WeaponId.ION_CANNON)
        ):
            continue

        return weapon_id

    return int(WeaponId.PISTOL)


def _projectile_meta_for_type_id(type_id: int) -> float:
    entry = weapon_entry_for_projectile_type_id(int(type_id))
    meta = entry.projectile_meta if entry is not None else None
    return float(meta if meta is not None else 45.0)


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


def bonus_pick_random_type(pool: BonusPool, state: "GameplayState", players: list["PlayerState"]) -> int:
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


@dataclass(slots=True)
class _WeaponAssignCtx:
    player: PlayerState
    clip_size: int


_WeaponAssignClipModifier = Callable[[_WeaponAssignCtx], None]


def _weapon_assign_clip_ammo_maniac(ctx: _WeaponAssignCtx) -> None:
    if perk_active(ctx.player, PerkId.AMMO_MANIAC):
        ctx.clip_size += max(1, int(float(ctx.clip_size) * 0.25))


def _weapon_assign_clip_my_favourite_weapon(ctx: _WeaponAssignCtx) -> None:
    if perk_active(ctx.player, PerkId.MY_FAVOURITE_WEAPON):
        ctx.clip_size += 2


_WEAPON_ASSIGN_CLIP_MODIFIERS: tuple[_WeaponAssignClipModifier, ...] = (
    _weapon_assign_clip_ammo_maniac,
    _weapon_assign_clip_my_favourite_weapon,
)


def weapon_assign_player(player: PlayerState, weapon_id: int, *, state: GameplayState | None = None) -> None:
    """Assign weapon and reset per-weapon runtime state (ammo/cooldowns)."""

    weapon_id = int(weapon_id)
    if state is not None and state.status is not None and not state.demo_mode_active:
        try:
            state.status.increment_weapon_usage(weapon_id)
        except Exception:
            pass

    weapon = _weapon_entry(weapon_id)
    player.weapon_id = weapon_id

    clip_size = int(weapon.clip_size) if weapon is not None and weapon.clip_size is not None else 0
    clip_ctx = _WeaponAssignCtx(player=player, clip_size=max(0, clip_size))
    for modifier in _WEAPON_ASSIGN_CLIP_MODIFIERS:
        modifier(clip_ctx)
    player.clip_size = max(0, int(clip_ctx.clip_size))
    player.ammo = float(player.clip_size)
    player.weapon_reset_latch = 0
    player.reload_active = False
    player.reload_timer = 0.0
    player.reload_timer_max = 0.0
    player.shot_cooldown = 0.0
    player.aux_timer = 2.0

    if state is not None and weapon is not None:
        from .weapon_sfx import resolve_weapon_sfx_ref

        key = resolve_weapon_sfx_ref(weapon.reload_sound)
        if key is not None:
            state.sfx_queue.append(key)


def most_used_weapon_id_for_player(state: GameplayState, *, player_index: int, fallback_weapon_id: int) -> int:
    """Return a 1-based weapon id for the player's most-used weapon."""

    idx = int(player_index)
    if 0 <= idx < len(state.weapon_shots_fired):
        counts = state.weapon_shots_fired[idx]
        if counts:
            start = 1 if len(counts) > 1 else 0
            best = max(range(start, len(counts)), key=lambda i: int(counts[i]))
            if int(counts[best]) > 0:
                return int(best)
    return int(fallback_weapon_id)


def player_swap_alt_weapon(player: PlayerState) -> bool:
    """Swap primary and alternate weapon runtime blocks (Alternate Weapon perk)."""

    if player.alt_weapon_id is None:
        return False
    (
        player.weapon_id,
        player.clip_size,
        player.reload_active,
        player.ammo,
        player.reload_timer,
        player.shot_cooldown,
        player.reload_timer_max,
        player.alt_weapon_id,
        player.alt_clip_size,
        player.alt_reload_active,
        player.alt_ammo,
        player.alt_reload_timer,
        player.alt_shot_cooldown,
        player.alt_reload_timer_max,
    ) = (
        player.alt_weapon_id,
        player.alt_clip_size,
        player.alt_reload_active,
        player.alt_ammo,
        player.alt_reload_timer,
        player.alt_shot_cooldown,
        player.alt_reload_timer_max,
        player.weapon_id,
        player.clip_size,
        player.reload_active,
        player.ammo,
        player.reload_timer,
        player.shot_cooldown,
        player.reload_timer_max,
    )
    return True


def player_start_reload(player: PlayerState, state: GameplayState) -> None:
    """Start or refresh a reload timer (`player_start_reload` @ 0x00413430)."""

    if player.reload_active and (
        perk_active(player, PerkId.AMMUNITION_WITHIN) or perk_active(player, PerkId.REGRESSION_BULLETS)
    ):
        return

    weapon = _weapon_entry(player.weapon_id)
    reload_time = float(weapon.reload_time) if weapon is not None and weapon.reload_time is not None else 0.0

    if not player.reload_active:
        player.reload_active = True

    if perk_active(player, PerkId.FASTLOADER):
        reload_time *= 0.7
    if state.bonuses.weapon_power_up > 0.0:
        reload_time *= 0.6

    player.reload_timer = max(0.0, reload_time)
    player.reload_timer_max = player.reload_timer


def _spawn_projectile_ring(
    state: GameplayState,
    origin: _HasPos,
    *,
    count: int,
    angle_offset: float,
    type_id: int,
    owner_id: int,
    players: list[PlayerState] | None = None,
) -> None:
    if count <= 0:
        return
    step = math.tau / float(count)
    for idx in range(count):
        _projectile_spawn(
            state,
            players=players,
            pos=origin.pos,
            angle=float(idx) * step + float(angle_offset),
            type_id=int(type_id),
            owner_id=int(owner_id),
        )


def _fire_bullets_active(players: list[PlayerState] | None) -> bool:
    # Native `projectile_spawn` checks `player_state_table.fire_bullets_timer` and `player2_fire_bullets_timer`
    # (i.e. the first two players).
    if not players:
        return False
    for player in players[:2]:
        if float(player.fire_bullets_timer) > 0.0:
            return True
    return False


def _projectile_spawn(
    state: GameplayState,
    *,
    players: list[PlayerState] | None,
    pos: Vec2,
    angle: float,
    type_id: int,
    owner_id: int,
    hits_players: bool = False,
) -> int:
    # Mirror `projectile_spawn` (0x00420440) Fire Bullets override.
    type_id = int(type_id)
    owner_id = int(owner_id)
    if (
        (not state.bonus_spawn_guard)
        and owner_id in (-100, -1, -2, -3)
        and type_id != int(ProjectileTypeId.FIRE_BULLETS)
        and _fire_bullets_active(players)
    ):
        type_id = int(ProjectileTypeId.FIRE_BULLETS)

    meta = _projectile_meta_for_type_id(type_id)
    return state.projectiles.spawn(
        pos=pos,
        angle=float(angle),
        type_id=int(type_id),
        owner_id=int(owner_id),
        base_damage=float(meta),
        hits_players=bool(hits_players),
    )


def _perk_update_man_bomb(
    player: PlayerState, dt: float, state: GameplayState, *, players: list[PlayerState] | None
) -> None:
    player.man_bomb_timer += dt
    if player.man_bomb_timer <= state.perk_intervals.man_bomb:
        return

    owner_id = _owner_id_for_player_projectiles(state, player.index)
    for idx in range(8):
        type_id = ProjectileTypeId.ION_MINIGUN if ((idx & 1) == 0) else ProjectileTypeId.ION_RIFLE
        angle = (float(state.rng.rand() % 50) * 0.01) + float(idx) * (math.pi / 4.0) - 0.25
        _projectile_spawn(
            state,
            players=players,
            pos=player.pos,
            angle=angle,
            type_id=type_id,
            owner_id=owner_id,
        )
    state.sfx_queue.append("sfx_explosion_small")

    player.man_bomb_timer -= state.perk_intervals.man_bomb
    state.perk_intervals.man_bomb = 4.0


def _perk_update_hot_tempered(
    player: PlayerState, dt: float, state: GameplayState, *, players: list[PlayerState] | None
) -> None:
    player.hot_tempered_timer += dt
    if player.hot_tempered_timer <= state.perk_intervals.hot_tempered:
        return

    owner_id = _owner_id_for_player(player.index) if state.friendly_fire_enabled else -100
    for idx in range(8):
        type_id = ProjectileTypeId.PLASMA_MINIGUN if ((idx & 1) == 0) else ProjectileTypeId.PLASMA_RIFLE
        angle = float(idx) * (math.pi / 4.0)
        _projectile_spawn(
            state,
            players=players,
            pos=player.pos,
            angle=angle,
            type_id=type_id,
            owner_id=owner_id,
        )
    state.sfx_queue.append("sfx_explosion_small")

    player.hot_tempered_timer -= state.perk_intervals.hot_tempered
    state.perk_intervals.hot_tempered = float(state.rng.rand() % 8) + 2.0


def _perk_update_fire_cough(player: PlayerState, dt: float, state: GameplayState) -> None:
    player.fire_cough_timer += dt
    if player.fire_cough_timer <= state.perk_intervals.fire_cough:
        return

    owner_id = _owner_id_for_player_projectiles(state, player.index)
    state.sfx_queue.append("sfx_autorifle_fire")
    state.sfx_queue.append("sfx_plasmaminigun_fire")

    aim_heading = float(player.aim_heading)
    muzzle = player.pos + Vec2.from_heading(aim_heading).rotated(-0.150915) * 16.0

    aim = player.aim
    dist = (aim - player.pos).length()
    max_offset = dist * float(player.spread_heat) * 0.5
    dir_angle = float(int(state.rng.rand()) & 0x1FF) * (math.tau / 512.0)
    mag = float(int(state.rng.rand()) & 0x1FF) * (1.0 / 512.0)
    offset = max_offset * mag
    jitter = aim + Vec2.from_angle(dir_angle) * offset
    angle = (jitter - player.pos).to_heading()
    _projectile_spawn(
        state,
        players=[player],
        pos=muzzle,
        angle=angle,
        type_id=ProjectileTypeId.FIRE_BULLETS,
        owner_id=owner_id,
    )

    vel = Vec2.from_angle(aim_heading) * 25.0
    state.sprite_effects.spawn(pos=muzzle, vel=vel, scale=1.0, color=RGBA(0.5, 0.5, 0.5, 0.413))

    player.fire_cough_timer -= state.perk_intervals.fire_cough
    state.perk_intervals.fire_cough = float(state.rng.rand() % 4) + 2.0


@dataclass(slots=True)
class _PlayerPerkTickCtx:
    state: GameplayState
    player: PlayerState
    players: list[PlayerState] | None
    dt: float
    stationary: bool


_PlayerPerkTickStep = Callable[[_PlayerPerkTickCtx], None]


def _player_perk_tick_man_bomb(ctx: _PlayerPerkTickCtx) -> None:
    if ctx.stationary and perk_active(ctx.player, PerkId.MAN_BOMB):
        _perk_update_man_bomb(ctx.player, ctx.dt, ctx.state, players=ctx.players)
    else:
        ctx.player.man_bomb_timer = 0.0


def _player_perk_tick_living_fortress(ctx: _PlayerPerkTickCtx) -> None:
    if ctx.stationary and perk_active(ctx.player, PerkId.LIVING_FORTRESS):
        ctx.player.living_fortress_timer = min(30.0, ctx.player.living_fortress_timer + ctx.dt)
    else:
        ctx.player.living_fortress_timer = 0.0


def _player_perk_tick_fire_cough(ctx: _PlayerPerkTickCtx) -> None:
    if perk_active(ctx.player, PerkId.FIRE_CAUGH):
        _perk_update_fire_cough(ctx.player, ctx.dt, ctx.state)
    else:
        ctx.player.fire_cough_timer = 0.0


def _player_perk_tick_hot_tempered(ctx: _PlayerPerkTickCtx) -> None:
    if perk_active(ctx.player, PerkId.HOT_TEMPERED):
        _perk_update_hot_tempered(ctx.player, ctx.dt, ctx.state, players=ctx.players)
    else:
        ctx.player.hot_tempered_timer = 0.0


_PLAYER_PERK_TICK_STEPS: tuple[_PlayerPerkTickStep, ...] = (
    _player_perk_tick_man_bomb,
    _player_perk_tick_living_fortress,
    _player_perk_tick_fire_cough,
    _player_perk_tick_hot_tempered,
)


_NATIVE_FIRE_MUZZLE_SPRITES: dict[int, tuple[tuple[float, float, float], ...]] = {
    int(WeaponId.PISTOL): ((25.0, 1.0, 0.23), (15.0, 2.0, 0.213)),
    int(WeaponId.ASSAULT_RIFLE): ((25.0, 1.0, 0.23), (15.0, 2.0, 0.213)),
    int(WeaponId.SHOTGUN): ((25.0, 1.0, 0.25), (15.0, 2.0, 0.223)),
    int(WeaponId.SAWED_OFF_SHOTGUN): ((25.0, 1.0, 0.26), (15.0, 2.0, 0.233)),
    int(WeaponId.SUBMACHINE_GUN): ((25.0, 1.0, 0.23), (15.0, 2.0, 0.213)),
    int(WeaponId.GAUSS_GUN): ((25.0, 1.0, 0.33), (15.0, 2.0, 0.263)),
    int(WeaponId.ROCKET_LAUNCHER): ((25.0, 1.0, 0.34), (15.0, 2.0, 0.283)),
    int(WeaponId.SEEKER_ROCKETS): ((25.0, 1.0, 0.31), (15.0, 2.0, 0.243)),
    int(WeaponId.MINI_ROCKET_SWARMERS): ((25.0, 1.0, 0.34), (15.0, 2.0, 0.283)),
    int(WeaponId.ROCKET_MINIGUN): ((25.0, 1.0, 0.34),),
    int(WeaponId.JACKHAMMER): ((15.0, 2.0, 0.223),),
    int(WeaponId.SHRINKIFIER_5K): ((25.0, 1.0, 0.23), (15.0, 2.0, 0.213)),
    int(WeaponId.GAUSS_SHOTGUN): ((25.0, 1.0, 0.33), (15.0, 2.0, 0.263)),
}

_NATIVE_FIRE_MUZZLE_AFTER_PROJECTILE: frozenset[int] = frozenset(
    {
        int(WeaponId.PISTOL),
        int(WeaponId.SHRINKIFIER_5K),
    }
)


def _spawn_native_fire_muzzle_sprites(
    *,
    state: GameplayState,
    weapon_id: int,
    muzzle: Vec2,
    aim_heading: float,
    fire_bullets_active: bool,
) -> None:
    if fire_bullets_active:
        specs: tuple[tuple[float, float, float], ...] = ((25.0, 1.0, 0.413),)
    else:
        specs = _NATIVE_FIRE_MUZZLE_SPRITES.get(int(weapon_id), ())
    if not specs:
        return

    for speed, scale, alpha in specs:
        state.sprite_effects.spawn(
            pos=muzzle,
            vel=Vec2.from_heading(aim_heading) * float(speed),
            scale=float(scale),
            color=RGBA(0.5, 0.5, 0.5, float(alpha)),
        )


def player_fire_weapon(
    player: PlayerState,
    input_state: PlayerInput,
    dt: float,
    state: GameplayState,
    *,
    detail_preset: int = 5,
    creatures: Sequence[Damageable] | None = None,
) -> None:
    dt = float(dt)

    weapon_id = int(player.weapon_id)
    weapon = _weapon_entry(weapon_id)
    if weapon is None:
        return

    if player.shot_cooldown > 0.0:
        return
    if not input_state.fire_down:
        return

    firing_during_reload = False
    ammo_cost = 1.0
    is_fire_bullets = float(player.fire_bullets_timer) > 0.0
    if player.reload_timer > 0.0:
        if player.experience <= 0:
            return
        if perk_active(player, PerkId.REGRESSION_BULLETS):
            firing_during_reload = True
            ammo_class = int(weapon.ammo_class) if weapon.ammo_class is not None else 0

            reload_time = float(weapon.reload_time) if weapon.reload_time is not None else 0.0
            factor = 4.0 if ammo_class == 1 else 200.0
            player.experience = int(float(player.experience) - reload_time * factor)
            if player.experience < 0:
                player.experience = 0
        elif perk_active(player, PerkId.AMMUNITION_WITHIN):
            firing_during_reload = True
            ammo_class = int(weapon.ammo_class) if weapon.ammo_class is not None else 0

            from .player_damage import player_take_damage

            cost = 0.15 if ammo_class == 1 else 1.0
            player_take_damage(state, player, cost, dt=dt, rand=state.rng.rand)
        else:
            return

    if player.ammo <= 0 and not firing_during_reload and not is_fire_bullets:
        player_start_reload(player, state)
        return

    pellet_count = int(weapon.pellet_count) if weapon.pellet_count is not None else 0
    fire_bullets_weapon = weapon_entry_for_projectile_type_id(int(ProjectileTypeId.FIRE_BULLETS))

    shot_cooldown = float(weapon.shot_cooldown) if weapon.shot_cooldown is not None else 0.0
    weapon_spread_heat = float(weapon.spread_heat_inc) if weapon.spread_heat_inc is not None else 0.0
    fire_bullets_spread_heat = weapon_spread_heat
    if fire_bullets_weapon is not None and fire_bullets_weapon.spread_heat_inc is not None:
        fire_bullets_spread_heat = float(fire_bullets_weapon.spread_heat_inc)

    if is_fire_bullets and pellet_count == 1 and fire_bullets_weapon is not None:
        shot_cooldown = (
            float(fire_bullets_weapon.shot_cooldown) if fire_bullets_weapon.shot_cooldown is not None else 0.0
        )

    spread_heat_base = fire_bullets_spread_heat if is_fire_bullets else weapon_spread_heat
    spread_inc = spread_heat_base * 1.3

    if perk_active(player, PerkId.FASTSHOT):
        shot_cooldown *= 0.88
    if perk_active(player, PerkId.SHARPSHOOTER):
        shot_cooldown *= 1.05
    player.shot_cooldown = max(0.0, shot_cooldown)

    aim = input_state.aim
    aim_delta = aim - player.pos
    aim_heading = aim_delta.to_heading()

    muzzle = player.pos + Vec2.from_heading(aim_heading).rotated(-0.150915) * 16.0
    state.effects.spawn_shell_casing(
        pos=muzzle,
        aim_heading=aim_heading,
        weapon_flags=int(weapon.flags or 0),
        rand=state.rng.rand,
        detail_preset=int(detail_preset),
    )

    dist = aim_delta.length()
    max_offset = dist * float(player.spread_heat) * 0.5
    dir_angle = float(int(state.rng.rand()) & 0x1FF) * (math.tau / 512.0)
    mag = float(int(state.rng.rand()) & 0x1FF) * (1.0 / 512.0)
    offset = max_offset * mag
    aim_jitter = aim + Vec2.from_angle(dir_angle) * offset
    shot_angle = (aim_jitter - player.pos).to_heading()
    particle_angle = Vec2.from_heading(shot_angle).to_angle()
    if weapon_id in (WeaponId.FLAMETHROWER, WeaponId.BLOW_TORCH, WeaponId.HR_FLAMER):
        particle_angle = Vec2.from_heading(aim_heading).to_angle()

    # Native `player_fire_weapon` consumes one RNG draw for shot SFX variant
    # selection on every non-Fire-Bullets shot.
    if not is_fire_bullets:
        state.rng.rand()

    owner_id = _owner_id_for_player(player.index)
    projectile_owner_id = _owner_id_for_player_projectiles(state, player.index)
    shot_count = 1
    spawn_muzzle_after_projectile = bool(is_fire_bullets) or int(weapon_id) in _NATIVE_FIRE_MUZZLE_AFTER_PROJECTILE
    if not spawn_muzzle_after_projectile:
        _spawn_native_fire_muzzle_sprites(
            state=state,
            weapon_id=int(weapon_id),
            muzzle=muzzle,
            aim_heading=float(aim_heading),
            fire_bullets_active=bool(is_fire_bullets),
        )

    # `player_fire_weapon` (crimsonland.exe) uses weapon-specific extra angular jitter for pellet
    # weapons. This is separate from aim-point jitter driven by `player.spread_heat`.
    def _pellet_jitter_step(weapon_id: int) -> float:
        weapon_id = int(weapon_id)
        if weapon_id == WeaponId.SHOTGUN:
            return 0.0013
        if weapon_id == WeaponId.SAWED_OFF_SHOTGUN:
            return 0.004
        if weapon_id == WeaponId.JACKHAMMER:
            return 0.0013
        return 0.0015

    if is_fire_bullets:
        pellets = max(0, int(pellet_count))
        shot_count = pellets
        meta = _projectile_meta_for_type_id(ProjectileTypeId.FIRE_BULLETS)
        for _ in range(pellets):
            angle = shot_angle + float(int(state.rng.rand()) % 200 - 100) * 0.0015
            state.projectiles.spawn(
                pos=muzzle,
                angle=angle,
                type_id=ProjectileTypeId.FIRE_BULLETS,
                owner_id=projectile_owner_id,
                base_damage=meta,
            )
    elif weapon_id == WeaponId.ROCKET_LAUNCHER:
        # Rocket Launcher -> secondary type 1.
        state.secondary_projectiles.spawn(
            pos=muzzle,
            angle=shot_angle,
            type_id=SecondaryProjectileTypeId.ROCKET,
            owner_id=owner_id,
        )
    elif weapon_id == WeaponId.SEEKER_ROCKETS:
        # Seeker Rockets -> secondary type 2.
        state.secondary_projectiles.spawn(
            pos=muzzle,
            angle=shot_angle,
            type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
            owner_id=owner_id,
            target_hint=aim,
            creatures=creatures,
        )
    elif weapon_id == WeaponId.MINI_ROCKET_SWARMERS:
        # Mini-Rocket Swarmers -> secondary type 2 (fires the full clip in a spread).
        rocket_count = max(1, int(player.ammo))
        step = float(rocket_count) * (math.pi / 3.0)
        angle = (shot_angle - math.pi) - step * float(rocket_count) * 0.5
        for _ in range(rocket_count):
            state.secondary_projectiles.spawn(
                pos=muzzle,
                angle=angle,
                type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
                owner_id=owner_id,
                target_hint=aim,
                creatures=creatures,
            )
            angle += step
        ammo_cost = float(rocket_count)
        shot_count = rocket_count
    elif weapon_id == WeaponId.ROCKET_MINIGUN:
        # Rocket Minigun -> secondary type 4.
        state.secondary_projectiles.spawn(
            pos=muzzle,
            angle=shot_angle,
            type_id=SecondaryProjectileTypeId.ROCKET_MINIGUN,
            owner_id=owner_id,
        )
    elif weapon_id == WeaponId.FLAMETHROWER:
        # Flamethrower -> fast particle weapon (style 0), fractional ammo drain.
        state.particles.spawn_particle(pos=muzzle, angle=particle_angle, intensity=1.0, owner_id=owner_id)
        ammo_cost = 0.1
    elif weapon_id == WeaponId.BLOW_TORCH:
        # Blow Torch -> fast particle weapon (style 1), fractional ammo drain.
        particle_id = state.particles.spawn_particle(pos=muzzle, angle=particle_angle, intensity=1.0, owner_id=owner_id)
        state.particles.entries[particle_id].style_id = 1
        ammo_cost = 0.05
    elif weapon_id == WeaponId.HR_FLAMER:
        # HR Flamer -> fast particle weapon (style 2), fractional ammo drain.
        particle_id = state.particles.spawn_particle(pos=muzzle, angle=particle_angle, intensity=1.0, owner_id=owner_id)
        state.particles.entries[particle_id].style_id = 2
        ammo_cost = 0.1
    elif weapon_id == WeaponId.BUBBLEGUN:
        # Bubblegun -> slow particle weapon (style 8), fractional ammo drain.
        state.particles.spawn_particle_slow(
            pos=muzzle,
            angle=Vec2.from_heading(shot_angle).to_angle(),
            owner_id=owner_id,
        )
        ammo_cost = 0.15
    elif weapon_id == WeaponId.MULTI_PLASMA:
        # Multi-Plasma: 5-shot fixed spread using type 0x09 and 0x0B.
        # (`player_update` weapon_id==0x0a in crimsonland.exe)
        shot_count = 5
        # Native literals: 0.31415927 (~ pi/10), 0.5235988 (~ pi/6).
        spread_small = math.pi / 10
        spread_large = math.pi / 6
        patterns: tuple[tuple[float, ProjectileTypeId], ...] = (
            (-spread_small, ProjectileTypeId.PLASMA_RIFLE),
            (-spread_large, ProjectileTypeId.PLASMA_MINIGUN),
            (0.0, ProjectileTypeId.PLASMA_RIFLE),
            (spread_large, ProjectileTypeId.PLASMA_MINIGUN),
            (spread_small, ProjectileTypeId.PLASMA_RIFLE),
        )
        for angle_offset, type_id in patterns:
            state.projectiles.spawn(
                pos=muzzle,
                angle=shot_angle + angle_offset,
                type_id=type_id,
                owner_id=projectile_owner_id,
                base_damage=_projectile_meta_for_type_id(type_id),
            )
    elif weapon_id == WeaponId.PLASMA_SHOTGUN:
        # Plasma Shotgun: 14 plasma-minigun pellets with wide jitter and random speed_scale.
        # (`player_update` weapon_id==0x0e in crimsonland.exe)
        shot_count = 14
        meta = _projectile_meta_for_type_id(int(ProjectileTypeId.PLASMA_MINIGUN))
        for _ in range(14):
            jitter = float((int(state.rng.rand()) & 0xFF) - 0x80) * 0.002
            proj_id = state.projectiles.spawn(
                pos=muzzle,
                angle=shot_angle + jitter,
                type_id=ProjectileTypeId.PLASMA_MINIGUN,
                owner_id=projectile_owner_id,
                base_damage=meta,
            )
            state.projectiles.entries[int(proj_id)].speed_scale = 1.0 + float(int(state.rng.rand()) % 100) * 0.01
    elif weapon_id == WeaponId.GAUSS_SHOTGUN:
        # Gauss Shotgun: 6 gauss pellets, jitter 0.002 and speed_scale 1.4..(1.4 + 0.79).
        # (`player_update` weapon_id==0x1e in crimsonland.exe)
        shot_count = 6
        meta = _projectile_meta_for_type_id(int(ProjectileTypeId.GAUSS_GUN))
        for _ in range(6):
            jitter = float(int(state.rng.rand()) % 200 - 100) * 0.002
            proj_id = state.projectiles.spawn(
                pos=muzzle,
                angle=shot_angle + jitter,
                type_id=ProjectileTypeId.GAUSS_GUN,
                owner_id=projectile_owner_id,
                base_damage=meta,
            )
            state.projectiles.entries[int(proj_id)].speed_scale = 1.4 + float(int(state.rng.rand()) % 0x50) * 0.01
    elif weapon_id == WeaponId.ION_SHOTGUN:
        # Ion Shotgun: 8 ion-minigun pellets, jitter 0.0026 and speed_scale 1.4..(1.4 + 0.79).
        # (`player_update` weapon_id==0x1f in crimsonland.exe)
        shot_count = 8
        meta = _projectile_meta_for_type_id(int(ProjectileTypeId.ION_MINIGUN))
        for _ in range(8):
            jitter = float(int(state.rng.rand()) % 200 - 100) * 0.0026
            proj_id = state.projectiles.spawn(
                pos=muzzle,
                angle=shot_angle + jitter,
                type_id=ProjectileTypeId.ION_MINIGUN,
                owner_id=projectile_owner_id,
                base_damage=meta,
            )
            state.projectiles.entries[int(proj_id)].speed_scale = 1.4 + float(int(state.rng.rand()) % 0x50) * 0.01
    else:
        pellets = max(1, int(pellet_count))
        shot_count = pellets
        type_id = projectile_type_id_from_weapon_id(weapon_id)
        if type_id is None:
            return
        meta = _projectile_meta_for_type_id(type_id)
        jitter_step = _pellet_jitter_step(weapon_id)
        for _ in range(pellets):
            angle = shot_angle
            if pellets > 1:
                angle += float(int(state.rng.rand()) % 200 - 100) * jitter_step
            proj_id = state.projectiles.spawn(
                pos=muzzle,
                angle=angle,
                type_id=type_id,
                owner_id=projectile_owner_id,
                base_damage=meta,
            )
            # Shotgun variants randomize speed_scale per pellet (rand%100 * 0.01 + 1.0).
            if pellets > 1 and weapon_id in (WeaponId.SHOTGUN, WeaponId.SAWED_OFF_SHOTGUN, WeaponId.JACKHAMMER):
                state.projectiles.entries[int(proj_id)].speed_scale = 1.0 + float(int(state.rng.rand()) % 100) * 0.01

    if 0 <= int(player.index) < len(state.shots_fired):
        state.shots_fired[int(player.index)] += int(shot_count)
        if 0 <= weapon_id < WEAPON_COUNT_SIZE:
            state.weapon_shots_fired[int(player.index)][weapon_id] += int(shot_count)

    if spawn_muzzle_after_projectile:
        _spawn_native_fire_muzzle_sprites(
            state=state,
            weapon_id=int(weapon_id),
            muzzle=muzzle,
            aim_heading=float(aim_heading),
            fire_bullets_active=bool(is_fire_bullets),
        )

    if not perk_active(player, PerkId.SHARPSHOOTER):
        player.spread_heat = min(0.48, max(0.0, player.spread_heat + spread_inc))

    muzzle_inc = weapon_spread_heat
    if is_fire_bullets and pellet_count == 1:
        muzzle_inc = fire_bullets_spread_heat
    player.muzzle_flash_alpha = min(1.0, player.muzzle_flash_alpha)
    player.muzzle_flash_alpha = min(1.0, player.muzzle_flash_alpha + muzzle_inc)
    player.muzzle_flash_alpha = min(0.8, player.muzzle_flash_alpha)

    player.shot_seq += 1
    if state.bonuses.reflex_boost <= 0.0 and not is_fire_bullets:
        # Native allows ammo to cross below zero for reload-time firing paths
        # (for example Regression Bullets), and replay checkpoints rely on that.
        player.ammo = float(player.ammo) - float(ammo_cost)
    if player.ammo <= 0.0 and player.reload_timer <= 0.0:
        player_start_reload(player, state)


def player_update(
    player: PlayerState,
    input_state: PlayerInput,
    dt: float,
    state: GameplayState,
    *,
    detail_preset: int = 5,
    world_size: float = 1024.0,
    players: list[PlayerState] | None = None,
    creatures: Sequence[Damageable] | None = None,
) -> None:
    """Port of `player_update` (0x004136b0) for the rewrite runtime."""

    if dt <= 0.0:
        return

    prev_pos = player.pos

    if player.health <= 0.0:
        player.death_timer -= dt * 20.0
        return

    player.muzzle_flash_alpha = max(0.0, player.muzzle_flash_alpha - dt * 2.0)
    cooldown_decay = float(f32(float(dt) * (1.5 if state.bonuses.weapon_power_up > 0.0 else 1.0)))
    next_shot_cooldown = float(f32(float(player.shot_cooldown) - float(cooldown_decay)))
    player.shot_cooldown = max(0.0, float(next_shot_cooldown))
    if 0.0 < float(player.shot_cooldown) < 1e-6:
        player.shot_cooldown = 0.0

    if perk_active(player, PerkId.SHARPSHOOTER):
        player.spread_heat = 0.02
    else:
        player.spread_heat = max(0.01, player.spread_heat - dt * 0.4)

    speed_bonus_active = player.speed_bonus_timer > 0.0
    if player.aux_timer > 0.0:
        aux_decay = 1.4 if player.aux_timer >= 1.0 else 0.5
        player.aux_timer = max(0.0, player.aux_timer - dt * aux_decay)

    # Aim: compute direction from (player -> aim point).
    player.aim = input_state.aim
    aim_dir = (player.aim - player.pos).normalized()
    if aim_dir.length_sq() > 0.0:
        player.aim_dir = aim_dir
        player.aim_heading = aim_dir.to_heading()

    speed_multiplier = float(player.speed_multiplier)
    if speed_bonus_active:
        speed_multiplier += 1.0

    movement_dt = float(dt)
    if state.time_scale_active:
        time_scale_factor = 0.3
        reflex_timer = float(state.bonuses.reflex_boost)
        if reflex_timer < 1.0:
            time_scale_factor = (1.0 - reflex_timer) * 0.7 + 0.3
        if time_scale_factor > 1e-9:
            # Native `player_update` temporarily rescales frame_dt while applying
            # movement/heading, then restores the scaled frame_dt for the rest of
            # gameplay_update_and_render.
            movement_dt = float(movement_dt * (0.6 / float(time_scale_factor)))

    # Movement.
    raw_move = input_state.move
    raw_mag = raw_move.length()
    use_digital_move = (
        input_state.move_forward_pressed is not None
        and input_state.move_backward_pressed is not None
        and input_state.turn_left_pressed is not None
        and input_state.turn_right_pressed is not None
    )
    phase_sign = 1.0
    if use_digital_move:
        moving_forward = bool(input_state.move_forward_pressed)
        moving_backward = bool(input_state.move_backward_pressed)
        turning_left = bool(input_state.turn_left_pressed)
        turning_right = bool(input_state.turn_right_pressed)

        player.turn_speed = min(7.0, max(1.0, float(player.turn_speed)))
        turned = False
        # Native keyboard mode checks left first, then right (`player_update` mode 1),
        # so simultaneous turn keys resolve to left turn.
        if turning_left:
            player.turn_speed = float(player.turn_speed + movement_dt * 10.0)
            turn_delta = float(player.turn_speed) * movement_dt * 0.5
            player.heading = float(player.heading - turn_delta)
            player.aim_heading = float(player.aim_heading - turn_delta)
            turned = True
        elif turning_right:
            player.turn_speed = float(player.turn_speed + movement_dt * 10.0)
            turn_delta = float(player.turn_speed) * movement_dt * 0.5
            player.heading = float(player.heading + turn_delta)
            player.aim_heading = float(player.aim_heading + turn_delta)
            turned = True

        move_sign = 1.0
        # Native movement-key precedence is forward before backward.
        if moving_forward:
            if perk_active(player, PerkId.LONG_DISTANCE_RUNNER):
                if player.move_speed < 2.0:
                    player.move_speed = float(player.move_speed + movement_dt * 4.0)
                player.move_speed = float(player.move_speed + movement_dt)
                if player.move_speed > 2.8:
                    player.move_speed = 2.8
            else:
                player.move_speed = float(player.move_speed + movement_dt * 5.0)
                if player.move_speed > 2.0:
                    player.move_speed = 2.0
        elif moving_backward:
            if perk_active(player, PerkId.LONG_DISTANCE_RUNNER):
                if player.move_speed < 2.0:
                    player.move_speed = float(player.move_speed + movement_dt * 4.0)
                player.move_speed = float(player.move_speed + movement_dt)
                if player.move_speed > 2.8:
                    player.move_speed = 2.8
            else:
                player.move_speed = float(player.move_speed + movement_dt * 5.0)
                if player.move_speed > 2.0:
                    player.move_speed = 2.0
            move_sign = -1.0
            phase_sign = -1.0
        else:
            if not turned:
                player.turn_speed = 1.0
            player.move_speed = float(player.move_speed - movement_dt * 15.0)
            if player.move_speed < 0.0:
                player.move_speed = 0.0

        if player.weapon_id == WeaponId.MEAN_MINIGUN and player.move_speed > 0.8:
            player.move_speed = 0.8

        move = Vec2.from_heading(player.heading)
        speed = player.move_speed * speed_multiplier * 25.0 * move_sign
        if perk_active(player, PerkId.ALTERNATE_WEAPON):
            speed *= 0.8
    else:
        # Demo/autoplay uses very small analog magnitudes to represent turn-in-place and
        # heading alignment slowdown; don't apply a deadzone there.
        moving_input = raw_mag > (0.0 if state.demo_mode_active else 0.2)

        turn_alignment_scale = 1.0
        if moving_input:
            inv = 1.0 / raw_mag if raw_mag > 1e-9 else 0.0
            move = raw_move * inv
            # Native normalizes this heading into [0, 2pi] before calling
            # `player_heading_approach_target` (see ghidra @ 0x00413fxx).
            target_heading = _normalize_heading_angle(move.to_heading())
            angle_diff = _player_heading_approach_target(player, target_heading, movement_dt)
            move = Vec2.from_heading(player.heading)
            turn_alignment_scale = max(0.0, (math.pi - angle_diff) / math.pi)
            if perk_active(player, PerkId.LONG_DISTANCE_RUNNER):
                if player.move_speed < 2.0:
                    player.move_speed = float(player.move_speed + movement_dt * 4.0)
                player.move_speed = float(player.move_speed + movement_dt)
                if player.move_speed > 2.8:
                    player.move_speed = 2.8
            else:
                player.move_speed = float(player.move_speed + movement_dt * 5.0)
                if player.move_speed > 2.0:
                    player.move_speed = 2.0
        else:
            player.move_speed = float(player.move_speed - movement_dt * 15.0)
            if player.move_speed < 0.0:
                player.move_speed = 0.0
            move = Vec2.from_heading(player.heading)

        if player.weapon_id == WeaponId.MEAN_MINIGUN and player.move_speed > 0.8:
            player.move_speed = 0.8

        speed = player.move_speed * speed_multiplier * 25.0
        if moving_input:
            speed *= min(1.0, raw_mag)
            speed *= turn_alignment_scale
        if perk_active(player, PerkId.ALTERNATE_WEAPON):
            speed *= 0.8

    # Native movement stores through float32 velocity/delta slots before writing
    # player position; mirror those store boundaries for replay parity.
    move_step = f32(float(speed) * float(movement_dt))
    move_delta = Vec2(
        f32(float(move.x) * float(move_step)),
        f32(float(move.y) * float(move_step)),
    )
    next_pos = Vec2(
        f32(float(player.pos.x) + float(move_delta.x)),
        f32(float(player.pos.y) + float(move_delta.y)),
    )

    # Native clamps player world bounds at the end of `player_update`, after
    # firing/reload logic has consumed the in-frame movement position.
    player.pos = next_pos

    player.move_phase += phase_sign * movement_dt * player.move_speed * 19.0

    move_delta = player.pos - prev_pos
    stationary = abs(move_delta.x) <= 1e-9 and abs(move_delta.y) <= 1e-9
    reload_scale = 1.0
    if stationary and perk_active(player, PerkId.STATIONARY_RELOADER):
        reload_scale = 3.0

    perk_ctx = _PlayerPerkTickCtx(state=state, player=player, players=players, dt=dt, stationary=stationary)
    for step in _PLAYER_PERK_TICK_STEPS:
        step(perk_ctx)

    # Reload + reload perks.
    if perk_active(player, PerkId.ANXIOUS_LOADER) and input_state.fire_pressed and player.reload_timer > 0.0:
        anxious_next = f32(float(player.reload_timer) - 0.05)
        player.reload_timer = float(anxious_next)
        if float(anxious_next) <= 0.0:
            # Native restarts the tail of the reload at `frame_dt * 0.8` when
            # Anxious Loader overcuts the timer.
            player.reload_timer = float(f32(float(dt) * 0.8))

    # Native preloads ammo one frame before reload timer underflows, using
    # unscaled `frame_dt` (before Stationary Reloader scale is applied).
    reload_timer_now = float(f32(float(player.reload_timer)))
    dt_f32 = float(f32(float(dt)))
    if player.reload_active and float(f32(reload_timer_now - dt_f32)) < 0.0 and 0.0 <= reload_timer_now:
        player.ammo = float(player.clip_size)

    if player.reload_timer > 0.0:
        if (
            perk_active(player, PerkId.ANGRY_RELOADER)
            and player.reload_timer_max > 0.5
            and (player.reload_timer_max * 0.5) < player.reload_timer
        ):
            half = player.reload_timer_max * 0.5
            next_timer = float(f32(float(player.reload_timer) - float(reload_scale) * float(dt)))
            player.reload_timer = next_timer
            if next_timer <= half:
                count = 7 + int(player.reload_timer_max * 4.0)
                state.bonus_spawn_guard = True
                _spawn_projectile_ring(
                    state,
                    player,
                    count=count,
                    angle_offset=0.1,
                    type_id=ProjectileTypeId.PLASMA_MINIGUN,
                    owner_id=_owner_id_for_player_projectiles(state, player.index),
                    players=players,
                )
                state.bonus_spawn_guard = False
                state.sfx_queue.append("sfx_explosion_small")
        else:
            player.reload_timer = float(f32(float(player.reload_timer) - float(reload_scale) * float(dt)))

    if player.reload_timer < 0.0:
        player.reload_timer = 0.0

    # Native clears `reload_active` only once the player can shoot again.
    if player.shot_cooldown <= 0.0 and player.reload_timer == 0.0:
        player.reload_active = False

    if input_state.reload_pressed:
        if perk_active(player, PerkId.ALTERNATE_WEAPON) and player_swap_alt_weapon(player):
            weapon = _weapon_entry(player.weapon_id)
            if weapon is not None and weapon.reload_sound is not None:
                from .weapon_sfx import resolve_weapon_sfx_ref

                key = resolve_weapon_sfx_ref(weapon.reload_sound)
                if key is not None:
                    state.sfx_queue.append(key)
            player.shot_cooldown = float(player.shot_cooldown) + 0.1
        elif player.reload_timer == 0.0:
            player_start_reload(player, state)

    player_fire_weapon(
        player,
        input_state,
        dt,
        state,
        detail_preset=int(detail_preset),
        creatures=creatures,
    )

    while player.move_phase > 14.0:
        player.move_phase -= 14.0
    while player.move_phase < 0.0:
        player.move_phase += 14.0

    half_size = max(0.0, float(player.size) * 0.5)
    clamped_pos = player.pos.clamp_rect(
        half_size,
        half_size,
        float(world_size) - half_size,
        float(world_size) - half_size,
    )
    player.pos = Vec2(f32(float(clamped_pos.x)), f32(float(clamped_pos.y)))
    if player.muzzle_flash_alpha > 0.8:
        player.muzzle_flash_alpha = 0.8


def _player_heading_approach_target(player: PlayerState, target_heading: float, dt: float) -> float:
    """Native `player_heading_approach_target`: ease heading and return angular diff."""

    # Native runs this through float32 temporaries (`var_8`/`edx_1`) before the
    # direct-vs-wrapped compare and turn-sign branch. That quantization matters
    # near opposite-heading ties.
    heading = float(f32(float(_normalize_heading_angle(float(player.heading)))))
    player.heading = float(heading)
    target = float(f32(float(target_heading)))

    direct = float(f32(abs(float(f32(float(target - heading))))))
    high = heading
    if target > high:
        high = target
    low = heading
    if target < low:
        low = target
    wrapped = float(f32(abs(float(f32(float(f32(6.2831855 - high)) + low)))))
    diff = wrapped if direct >= wrapped else direct

    scaled = float(f32(float(f32(float(dt))) * float(diff)))
    if direct <= wrapped:
        if target > heading:
            turn_delta = float(f32(float(scaled) * 5.0))
        else:
            turn_delta = float(f32(float(scaled) * -5.0))
    else:
        if target >= heading:
            turn_delta = float(f32(float(scaled) * -5.0))
        else:
            turn_delta = float(f32(float(scaled) * 5.0))

    player.heading = float(f32(float(heading) + float(turn_delta)))
    return float(diff)

def _normalize_heading_angle(value: float) -> float:
    while value < 0.0:
        value += math.tau
    while value > math.tau:
        value -= math.tau
    return value
