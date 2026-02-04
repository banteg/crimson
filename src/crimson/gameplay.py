from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import TYPE_CHECKING, Callable, Protocol

from grim.math import clamp, distance_sq
from .bonuses import BONUS_BY_ID, BonusId
from grim.rand import Crand
from .effects import EffectPool, FxQueue, ParticlePool, SpriteEffectPool
from .game_modes import GameMode
from .perks import PerkFlags, PerkId, PERK_BY_ID, PERK_TABLE
from .projectiles import (
    CreatureDamageApplier,
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

if TYPE_CHECKING:
    from .persistence.save_status import GameStatus


class _HasPos(Protocol):
    pos_x: float
    pos_y: float


class _CreatureForPerks(Protocol):
    active: bool
    x: float
    y: float
    hp: float
    flags: int
    hitbox_size: float
    collision_timer: float
    reward_value: float
    size: float


@dataclass(frozen=True, slots=True)
class PlayerInput:
    move_x: float = 0.0
    move_y: float = 0.0
    aim_x: float = 0.0
    aim_y: float = 0.0
    fire_down: bool = False
    fire_pressed: bool = False
    reload_pressed: bool = False


PERK_COUNT_SIZE = 0x80
PERK_ID_MAX = max(int(meta.perk_id) for meta in PERK_TABLE)
WEAPON_COUNT_SIZE = max(int(entry.weapon_id) for entry in WEAPON_TABLE) + 1


@dataclass(slots=True)
class PlayerState:
    index: int
    pos_x: float
    pos_y: float
    health: float = 100.0
    size: float = 50.0

    speed_multiplier: float = 2.0
    move_speed: float = 0.0
    move_phase: float = 0.0
    heading: float = 0.0
    death_timer: float = 16.0
    low_health_timer: float = 100.0

    aim_x: float = 0.0
    aim_y: float = 0.0
    aim_heading: float = 0.0
    aim_dir_x: float = 1.0
    aim_dir_y: float = 0.0
    evil_eyes_target_creature: int = -1

    bonus_aim_hover_index: int = -1
    bonus_aim_hover_timer_ms: float = 0.0

    weapon_id: int = 1
    clip_size: int = 0
    ammo: float = 0.0
    reload_active: bool = False
    reload_timer: float = 0.0
    reload_timer_max: float = 0.0
    shot_cooldown: float = 0.0
    shot_seq: int = 0
    weapon_reset_latch: int = 0
    aux_timer: float = 0.0
    spread_heat: float = 0.01
    muzzle_flash_alpha: float = 0.0

    alt_weapon_id: int | None = None
    alt_clip_size: int = 0
    alt_ammo: float = 0.0
    alt_reload_active: bool = False
    alt_reload_timer: float = 0.0
    alt_reload_timer_max: float = 0.0
    alt_shot_cooldown: float = 0.0

    experience: int = 0
    level: int = 1

    perk_counts: list[int] = field(default_factory=lambda: [0] * PERK_COUNT_SIZE)
    plaguebearer_active: bool = False
    hot_tempered_timer: float = 0.0
    man_bomb_timer: float = 0.0
    living_fortress_timer: float = 0.0
    fire_cough_timer: float = 0.0

    speed_bonus_timer: float = 0.0
    shield_timer: float = 0.0
    fire_bullets_timer: float = 0.0


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


@dataclass(frozen=True, slots=True)
class _TimerRef:
    kind: str  # "global" or "player"
    key: str
    player_index: int | None = None


@dataclass(slots=True)
class BonusHudSlot:
    active: bool = False
    bonus_id: int = 0
    label: str = ""
    icon_id: int = -1
    slide_x: float = -184.0
    timer_ref: _TimerRef | None = None
    timer_ref_alt: _TimerRef | None = None
    timer_value: float = 0.0
    timer_value_alt: float = 0.0


BONUS_HUD_SLOT_COUNT = 16

BONUS_POOL_SIZE = 16
BONUS_SPAWN_MARGIN = 32.0
BONUS_SPAWN_MIN_DISTANCE = 32.0
BONUS_PICKUP_RADIUS = 26.0
BONUS_PICKUP_DECAY_RATE = 3.0
BONUS_PICKUP_LINGER = 0.5
BONUS_TIME_MAX = 10.0
BONUS_WEAPON_NEAR_RADIUS = 56.0
BONUS_AIM_HOVER_RADIUS = 24.0
BONUS_TELEKINETIC_PICKUP_MS = 650.0

WEAPON_DROP_ID_COUNT = 0x21  # weapon ids 1..33


@dataclass(slots=True)
class BonusHudState:
    slots: list[BonusHudSlot] = field(default_factory=lambda: [BonusHudSlot() for _ in range(BONUS_HUD_SLOT_COUNT)])

    def register(self, bonus_id: BonusId, *, label: str, icon_id: int, timer_ref: _TimerRef, timer_ref_alt: _TimerRef | None = None) -> None:
        existing = None
        free = None
        for slot in self.slots:
            if slot.active and slot.bonus_id == int(bonus_id):
                existing = slot
                break
            if (not slot.active) and free is None:
                free = slot
        slot = existing or free
        if slot is None:
            slot = self.slots[-1]
        slot.active = True
        slot.bonus_id = int(bonus_id)
        slot.label = label
        slot.icon_id = int(icon_id)
        slot.slide_x = -184.0
        slot.timer_ref = timer_ref
        slot.timer_ref_alt = timer_ref_alt
        slot.timer_value = 0.0
        slot.timer_value_alt = 0.0


@dataclass(slots=True)
class BonusEntry:
    bonus_id: int = 0
    picked: bool = False
    time_left: float = 0.0
    time_max: float = 0.0
    pos_x: float = 0.0
    pos_y: float = 0.0
    amount: int = 0


@dataclass(frozen=True, slots=True)
class BonusPickupEvent:
    player_index: int
    bonus_id: int
    amount: int
    pos_x: float
    pos_y: float


# Native `bonus_try_spawn_on_kill` uses the bonus entry `amount` field for a weird
# suppression check: it clears the spawned entry when `amount == player1.weapon_id`
# regardless of bonus type. In the rewrite, `amount` is used as the "effective"
# duration/value for some bonuses, so `--preserve-bugs` compares against the
# native amount domain (see docs/rewrite/original-bugs.md).
_BONUS_NATIVE_AMOUNT_WEAPON_ID_SUPPRESSION: dict[int, int] = {
    int(BonusId.DOUBLE_EXPERIENCE): 0,
    int(BonusId.FIRE_BULLETS): 4,
}


def _bonus_amount_for_weapon_id_suppression(*, bonus_id: int, amount: int) -> int:
    return int(_BONUS_NATIVE_AMOUNT_WEAPON_ID_SUPPRESSION.get(int(bonus_id), int(amount)))


class BonusPool:
    def __init__(self, *, size: int = BONUS_POOL_SIZE) -> None:
        self._entries = [BonusEntry() for _ in range(int(size))]

    @property
    def entries(self) -> list[BonusEntry]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.bonus_id = 0
            entry.picked = False
            entry.time_left = 0.0
            entry.time_max = 0.0
            entry.amount = 0

    def iter_active(self) -> list[BonusEntry]:
        return [entry for entry in self._entries if entry.bonus_id != 0]

    def _alloc_slot(self) -> BonusEntry | None:
        for entry in self._entries:
            if entry.bonus_id == 0:
                return entry
        return None

    def _clear_entry(self, entry: BonusEntry) -> None:
        entry.bonus_id = 0
        entry.picked = False
        entry.time_left = 0.0
        entry.time_max = 0.0
        entry.amount = 0

    def spawn_at(
        self,
        pos_x: float,
        pos_y: float,
        bonus_id: int | BonusId,
        duration_override: int = -1,
        *,
        state: "GameplayState",
        world_width: float = 1024.0,
        world_height: float = 1024.0,
    ) -> BonusEntry | None:
        if int(state.game_mode) == int(GameMode.RUSH):
            return None
        if int(bonus_id) == 0:
            return None
        entry = self._alloc_slot()
        if entry is None:
            return None

        x = clamp(float(pos_x), BONUS_SPAWN_MARGIN, float(world_width) - BONUS_SPAWN_MARGIN)
        y = clamp(float(pos_y), BONUS_SPAWN_MARGIN, float(world_height) - BONUS_SPAWN_MARGIN)

        entry.bonus_id = int(bonus_id)
        entry.picked = False
        entry.pos_x = x
        entry.pos_y = y
        entry.time_left = BONUS_TIME_MAX
        entry.time_max = BONUS_TIME_MAX

        amount = duration_override
        if amount == -1:
            meta = BONUS_BY_ID.get(int(bonus_id))
            amount = int(meta.default_amount or 0) if meta is not None else 0
        entry.amount = int(amount)
        return entry

    def spawn_at_pos(
        self,
        pos_x: float,
        pos_y: float,
        *,
        state: "GameplayState",
        players: list["PlayerState"],
        world_width: float = 1024.0,
        world_height: float = 1024.0,
    ) -> BonusEntry | None:
        if int(state.game_mode) == int(GameMode.RUSH):
            return None
        if (
            pos_x < BONUS_SPAWN_MARGIN
            or pos_y < BONUS_SPAWN_MARGIN
            or pos_x > world_width - BONUS_SPAWN_MARGIN
            or pos_y > world_height - BONUS_SPAWN_MARGIN
        ):
            return None

        min_dist_sq = BONUS_SPAWN_MIN_DISTANCE * BONUS_SPAWN_MIN_DISTANCE
        for entry in self._entries:
            if entry.bonus_id == 0:
                continue
            if distance_sq(pos_x, pos_y, entry.pos_x, entry.pos_y) < min_dist_sq:
                return None

        entry = self._alloc_slot()
        if entry is None:
            return None

        bonus_id = bonus_pick_random_type(self, state, players)
        entry.bonus_id = int(bonus_id)
        entry.picked = False
        entry.pos_x = float(pos_x)
        entry.pos_y = float(pos_y)
        entry.time_left = BONUS_TIME_MAX
        entry.time_max = BONUS_TIME_MAX

        rng = state.rng
        if entry.bonus_id == int(BonusId.WEAPON):
            entry.amount = weapon_pick_random_available(state)
        elif entry.bonus_id == int(BonusId.POINTS):
            entry.amount = 1000 if (rng.rand() & 7) < 3 else 500
        else:
            meta = BONUS_BY_ID.get(entry.bonus_id)
            entry.amount = int(meta.default_amount or 0) if meta is not None else 0
        return entry

    def try_spawn_on_kill(
        self,
        pos_x: float,
        pos_y: float,
        *,
        state: "GameplayState",
        players: list["PlayerState"],
        world_width: float = 1024.0,
        world_height: float = 1024.0,
    ) -> BonusEntry | None:
        game_mode = int(state.game_mode)
        if game_mode == int(GameMode.TYPO):
            return None
        if state.demo_mode_active:
            return None
        if game_mode == int(GameMode.RUSH):
            return None
        if game_mode == int(GameMode.TUTORIAL):
            return None
        if state.bonus_spawn_guard:
            return None

        rng = state.rng
        # Native special-case: while any player has Pistol, 3/4 chance to force a Weapon drop.
        if players and any(int(player.weapon_id) == int(WeaponId.PISTOL) for player in players):
            if (int(rng.rand()) & 3) < 3:
                entry = self.spawn_at_pos(
                    pos_x,
                    pos_y,
                    state=state,
                    players=players,
                    world_width=world_width,
                    world_height=world_height,
                )
                if entry is None:
                    return None

                entry.bonus_id = int(BonusId.WEAPON)
                weapon_id = int(weapon_pick_random_available(state))
                entry.amount = int(weapon_id)
                if weapon_id == int(WeaponId.PISTOL):
                    weapon_id = int(weapon_pick_random_available(state))
                    entry.amount = int(weapon_id)

                matches = sum(1 for bonus in self._entries if bonus.bonus_id == entry.bonus_id)
                if matches > 1:
                    self._clear_entry(entry)
                    return None

                if entry.amount == int(WeaponId.PISTOL) or (players and perk_active(players[0], PerkId.MY_FAVOURITE_WEAPON)):
                    self._clear_entry(entry)
                    return None

                return entry

        base_roll = int(rng.rand())
        if base_roll % 9 != 1:
            allow_without_magnet = False
            if players and int(players[0].weapon_id) == int(WeaponId.PISTOL):
                allow_without_magnet = int(rng.rand()) % 5 == 1

            if not allow_without_magnet:
                if not (players and perk_active(players[0], PerkId.BONUS_MAGNET)):
                    return None
                if int(rng.rand()) % 10 != 2:
                    return None

        entry = self.spawn_at_pos(
            pos_x,
            pos_y,
            state=state,
            players=players,
            world_width=world_width,
            world_height=world_height,
        )
        if entry is None:
            return None

        if entry.bonus_id == int(BonusId.WEAPON):
            near_sq = BONUS_WEAPON_NEAR_RADIUS * BONUS_WEAPON_NEAR_RADIUS
            if players and distance_sq(pos_x, pos_y, players[0].pos_x, players[0].pos_y) < near_sq:
                entry.bonus_id = int(BonusId.POINTS)
                entry.amount = 100

        if entry.bonus_id != int(BonusId.POINTS):
            matches = sum(1 for bonus in self._entries if bonus.bonus_id == entry.bonus_id)
            if matches > 1:
                self._clear_entry(entry)
                return None

        if players:
            weapon_id = int(players[0].weapon_id)
            if bool(state.preserve_bugs):
                amount = _bonus_amount_for_weapon_id_suppression(bonus_id=int(entry.bonus_id), amount=int(entry.amount))
                if amount == weapon_id:
                    self._clear_entry(entry)
                    return None
            else:
                if entry.bonus_id == int(BonusId.WEAPON) and int(entry.amount) == weapon_id:
                    self._clear_entry(entry)
                    return None

        return entry

    def update(
        self,
        dt: float,
        *,
        state: "GameplayState",
        players: list["PlayerState"],
        creatures: list[Damageable] | None = None,
        apply_creature_damage: CreatureDamageApplier | None = None,
        detail_preset: int = 5,
    ) -> list[BonusPickupEvent]:
        if dt <= 0.0:
            return []

        pickups: list[BonusPickupEvent] = []
        for entry in self._entries:
            if entry.bonus_id == 0:
                continue

            decay = dt * (BONUS_PICKUP_DECAY_RATE if entry.picked else 1.0)
            entry.time_left -= decay
            if not entry.picked and int(state.game_mode) == int(GameMode.TUTORIAL):
                entry.time_left = 5.0
            if entry.time_left < 0.0:
                self._clear_entry(entry)
                continue

            if entry.picked:
                continue

            for player in players:
                if distance_sq(entry.pos_x, entry.pos_y, player.pos_x, player.pos_y) < BONUS_PICKUP_RADIUS * BONUS_PICKUP_RADIUS:
                    bonus_apply(
                        state,
                        player,
                        BonusId(entry.bonus_id),
                        amount=entry.amount,
                        origin=entry,
                        creatures=creatures,
                        players=players,
                        apply_creature_damage=apply_creature_damage,
                        detail_preset=int(detail_preset),
                    )
                    entry.picked = True
                    entry.time_left = BONUS_PICKUP_LINGER
                    pickups.append(
                        BonusPickupEvent(
                            player_index=player.index,
                            bonus_id=entry.bonus_id,
                            amount=entry.amount,
                            pos_x=entry.pos_x,
                            pos_y=entry.pos_y,
                        )
                    )
                    break

        return pickups


def bonus_find_aim_hover_entry(player: PlayerState, bonus_pool: BonusPool) -> tuple[int, BonusEntry] | None:
    """Return the first bonus entry within the aim hover radius, matching the exe scan order."""

    aim_x = float(getattr(player, "aim_x", player.pos_x))
    aim_y = float(getattr(player, "aim_y", player.pos_y))
    radius_sq = BONUS_AIM_HOVER_RADIUS * BONUS_AIM_HOVER_RADIUS
    for idx, entry in enumerate(bonus_pool.entries):
        if entry.bonus_id == 0 or entry.picked:
            continue
        if distance_sq(aim_x, aim_y, entry.pos_x, entry.pos_y) < radius_sq:
            return idx, entry
    return None


@dataclass(slots=True)
class GameplayState:
    rng: Crand = field(default_factory=lambda: Crand(0xBEEF))
    effects: EffectPool = field(default_factory=EffectPool)
    particles: ParticlePool = field(init=False)
    sprite_effects: SpriteEffectPool = field(init=False)
    projectiles: ProjectilePool = field(default_factory=ProjectilePool)
    secondary_projectiles: SecondaryProjectilePool = field(default_factory=SecondaryProjectilePool)
    bonuses: BonusTimers = field(default_factory=BonusTimers)
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
    shock_chain_links_left: int = 0
    shock_chain_projectile_id: int = -1
    camera_shake_offset_x: float = 0.0
    camera_shake_offset_y: float = 0.0
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


def perk_count_get(player: PlayerState, perk_id: PerkId) -> int:
    idx = int(perk_id)
    if idx < 0:
        return 0
    if idx >= len(player.perk_counts):
        return 0
    return int(player.perk_counts[idx])


def perk_active(player: PlayerState, perk_id: PerkId) -> bool:
    return perk_count_get(player, perk_id) > 0


def _creature_find_in_radius(creatures: list[_CreatureForPerks], *, pos_x: float, pos_y: float, radius: float, start_index: int) -> int:
    """Port of `creature_find_in_radius` (0x004206a0)."""

    start_index = max(0, int(start_index))
    max_index = min(len(creatures), 0x180)
    if start_index >= max_index:
        return -1

    pos_x = float(pos_x)
    pos_y = float(pos_y)
    radius = float(radius)

    for idx in range(start_index, max_index):
        creature = creatures[idx]
        if not creature.active:
            continue

        dist = math.hypot(float(creature.x) - pos_x, float(creature.y) - pos_y) - radius
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
    creatures: list[_CreatureForPerks] | None
    fx_queue: FxQueue | None
    _aim_target: int | None = None

    def aim_target(self) -> int:
        if self._aim_target is not None:
            return int(self._aim_target)

        target = -1
        if self.players and self.creatures is not None and (
            perk_active(self.players[0], PerkId.PYROKINETIC) or perk_active(self.players[0], PerkId.EVIL_EYES)
        ):
            target = _creature_find_in_radius(
                self.creatures,
                pos_x=self.players[0].aim_x,
                pos_y=self.players[0].aim_y,
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
        pos_x = float(creature.x)
        pos_y = float(creature.y)
        for intensity in (0.8, 0.6, 0.4, 0.3, 0.2):
            angle = float(int(ctx.state.rng.rand()) % 0x274) * 0.01
            ctx.state.particles.spawn_particle(pos_x=pos_x, pos_y=pos_y, angle=angle, intensity=float(intensity))
        if ctx.fx_queue is not None:
            ctx.fx_queue.add_random(pos_x=pos_x, pos_y=pos_y, rand=ctx.state.rng.rand)


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
            ctx.fx_queue.add_random(pos_x=player.pos_x, pos_y=player.pos_y, rand=ctx.state.rng.rand)
            ctx.fx_queue.add_random(pos_x=player.pos_x, pos_y=player.pos_y, rand=ctx.state.rng.rand)

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


_PERKS_UPDATE_EFFECT_STEPS: tuple[_PerksUpdateEffectsStep, ...] = (
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
    creatures: list[_CreatureForPerks] | None = None,
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


def perk_can_offer(state: GameplayState, player: PlayerState, perk_id: PerkId, *, game_mode: int, player_count: int) -> bool:
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

    flags = meta.flags or PerkFlags(0)
    if (flags & PerkFlags.MODE_3_ONLY) and int(game_mode) != int(GameMode.QUESTS):
        return False
    if (flags & PerkFlags.TWO_PLAYER_ONLY) and int(player_count) != 2:
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

    # `perks_generate_choices` always fills a fixed array of 7 entries, even if the UI
    # only shows 5/6 (Perk Expert/Master). Preserve RNG consumption by generating the
    # full list, then slicing.
    choices: list[PerkId] = [PerkId.ANTIPERK] * 7
    choice_index = 0

    # Quest 1-7 special-case: force Monster Vision as the first choice if not owned.
    if (
        int(state.quest_stage_major) == 1
        and int(state.quest_stage_minor) == 7
        and perk_count_get(player, PerkId.MONSTER_VISION) == 0
    ):
        choices[0] = PerkId.MONSTER_VISION
        choice_index = 1

    while choice_index < 7:
        attempts = 0
        while True:
            attempts += 1
            perk_id = perk_select_random(state, player, game_mode=game_mode, player_count=player_count)

            # Pyromaniac can only be offered if the current weapon is Flamethrower.
            if perk_id == PerkId.PYROMANIAC and int(player.weapon_id) != int(WeaponId.FLAMETHROWER):
                continue

            if perk_count_get(player, PerkId.DEATH_CLOCK) > 0 and perk_id in _DEATH_CLOCK_BLOCKED:
                continue

            # Global rarity gate: certain perks have a 25% chance to be rejected.
            if perk_id in _PERK_RARITY_GATE and (int(state.rng.rand()) & 3) == 1:
                continue

            meta = PERK_BY_ID.get(int(perk_id))
            flags = meta.flags if meta is not None and meta.flags is not None else PerkFlags(0)
            stackable = (flags & PerkFlags.STACKABLE) != 0

            if attempts > 10_000 and stackable:
                break

            if perk_id in choices[:choice_index]:
                continue

            if stackable or perk_count_get(player, perk_id) < 1 or attempts > 29_999:
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
    creatures: list[_CreatureForPerks] | None

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
                pos_x=float(creature.x),
                pos_y=float(creature.y),
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
                pos_x=float(player.pos_x),
                pos_y=float(player.pos_y),
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
    creatures: list[_CreatureForPerks] | None = None,
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
    creatures: list[_CreatureForPerks] | None = None,
) -> list[PerkId]:
    """Resolve pending perks by auto-selecting from generated choices."""

    if not players:
        return []
    if player_count is None:
        player_count = len(players)
    picks: list[PerkId] = []
    while perk_state.pending_count > 0:
        if perk_state.choices_dirty or not perk_state.choices:
            perk_state.choices = [int(perk) for perk in perk_generate_choices(state, players[0], game_mode=game_mode, player_count=player_count)]
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
        perk_state.choices = [int(perk) for perk in perk_generate_choices(state, players[0], game_mode=game_mode, player_count=player_count)]
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
    creatures: list[_CreatureForPerks] | None = None,
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
    creatures: list[_CreatureForPerks] | None = None,
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


def _normalize(x: float, y: float) -> tuple[float, float]:
    mag = math.hypot(x, y)
    if mag <= 1e-9:
        return 0.0, 0.0
    inv = 1.0 / mag
    return x * inv, y * inv


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
        entry.bonus_id == int(BonusId.FIRE_BULLETS) and not entry.picked
        for entry in pool.entries
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
            best = max(range(start, len(counts)), key=counts.__getitem__)
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

    if player.reload_active and (perk_active(player, PerkId.AMMUNITION_WITHIN) or perk_active(player, PerkId.REGRESSION_BULLETS)):
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
            pos_x=float(origin.pos_x),
            pos_y=float(origin.pos_y),
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
    pos_x: float,
    pos_y: float,
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
        pos_x=float(pos_x),
        pos_y=float(pos_y),
        angle=float(angle),
        type_id=int(type_id),
        owner_id=int(owner_id),
        base_damage=float(meta),
        hits_players=bool(hits_players),
    )


def _perk_update_man_bomb(player: PlayerState, dt: float, state: GameplayState, *, players: list[PlayerState] | None) -> None:
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
            pos_x=player.pos_x,
            pos_y=player.pos_y,
            angle=angle,
            type_id=type_id,
            owner_id=owner_id,
        )
    state.sfx_queue.append("sfx_explosion_small")

    player.man_bomb_timer -= state.perk_intervals.man_bomb
    state.perk_intervals.man_bomb = 4.0


def _perk_update_hot_tempered(player: PlayerState, dt: float, state: GameplayState, *, players: list[PlayerState] | None) -> None:
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
            pos_x=player.pos_x,
            pos_y=player.pos_y,
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
    muzzle_dir = (aim_heading - math.pi / 2.0) - 0.150915
    muzzle_x = player.pos_x + math.cos(muzzle_dir) * 16.0
    muzzle_y = player.pos_y + math.sin(muzzle_dir) * 16.0

    aim_x = float(player.aim_x)
    aim_y = float(player.aim_y)
    dx = aim_x - float(player.pos_x)
    dy = aim_y - float(player.pos_y)
    dist = math.hypot(dx, dy)
    max_offset = dist * float(player.spread_heat) * 0.5
    dir_angle = float(int(state.rng.rand()) & 0x1FF) * (math.tau / 512.0)
    mag = float(int(state.rng.rand()) & 0x1FF) * (1.0 / 512.0)
    offset = max_offset * mag
    jitter_x = aim_x + math.cos(dir_angle) * offset
    jitter_y = aim_y + math.sin(dir_angle) * offset
    angle = math.atan2(jitter_y - float(player.pos_y), jitter_x - float(player.pos_x)) + math.pi / 2.0
    _projectile_spawn(
        state,
        players=[player],
        pos_x=muzzle_x,
        pos_y=muzzle_y,
        angle=angle,
        type_id=ProjectileTypeId.FIRE_BULLETS,
        owner_id=owner_id,
    )

    vel_x = math.cos(aim_heading) * 25.0
    vel_y = math.sin(aim_heading) * 25.0
    sprite_id = state.sprite_effects.spawn(pos_x=muzzle_x, pos_y=muzzle_y, vel_x=vel_x, vel_y=vel_y, scale=1.0)
    sprite = state.sprite_effects.entries[int(sprite_id)]
    sprite.color_r = 0.5
    sprite.color_g = 0.5
    sprite.color_b = 0.5
    sprite.color_a = 0.413

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


def player_fire_weapon(
    player: PlayerState,
    input_state: PlayerInput,
    dt: float,
    state: GameplayState,
    *,
    detail_preset: int = 5,
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
            float(fire_bullets_weapon.shot_cooldown)
            if fire_bullets_weapon.shot_cooldown is not None
            else 0.0
        )

    spread_heat_base = fire_bullets_spread_heat if is_fire_bullets else weapon_spread_heat
    spread_inc = spread_heat_base * 1.3

    if perk_active(player, PerkId.FASTSHOT):
        shot_cooldown *= 0.88
    if perk_active(player, PerkId.SHARPSHOOTER):
        shot_cooldown *= 1.05
    player.shot_cooldown = max(0.0, shot_cooldown)

    aim_x = float(input_state.aim_x)
    aim_y = float(input_state.aim_y)
    dx = aim_x - float(player.pos_x)
    dy = aim_y - float(player.pos_y)
    aim_heading = math.atan2(dy, dx) + math.pi / 2.0

    muzzle_dir = (aim_heading - math.pi / 2.0) - 0.150915
    muzzle_x = player.pos_x + math.cos(muzzle_dir) * 16.0
    muzzle_y = player.pos_y + math.sin(muzzle_dir) * 16.0
    state.effects.spawn_shell_casing(
        pos_x=muzzle_x,
        pos_y=muzzle_y,
        aim_heading=aim_heading,
        weapon_flags=int(weapon.flags or 0),
        rand=state.rng.rand,
        detail_preset=int(detail_preset),
    )

    dist = math.hypot(dx, dy)
    max_offset = dist * float(player.spread_heat) * 0.5
    dir_angle = float(int(state.rng.rand()) & 0x1FF) * (math.tau / 512.0)
    mag = float(int(state.rng.rand()) & 0x1FF) * (1.0 / 512.0)
    offset = max_offset * mag
    aim_jitter_x = aim_x + math.cos(dir_angle) * offset
    aim_jitter_y = aim_y + math.sin(dir_angle) * offset
    shot_angle = math.atan2(aim_jitter_y - float(player.pos_y), aim_jitter_x - float(player.pos_x)) + math.pi / 2.0
    particle_angle = shot_angle - math.pi / 2.0
    if weapon_id in (WeaponId.FLAMETHROWER, WeaponId.BLOW_TORCH, WeaponId.HR_FLAMER):
        particle_angle = aim_heading - math.pi / 2.0

    owner_id = _owner_id_for_player(player.index)
    shot_count = 1

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
                pos_x=muzzle_x,
                pos_y=muzzle_y,
                angle=angle,
                type_id=ProjectileTypeId.FIRE_BULLETS,
                owner_id=owner_id,
                base_damage=meta,
            )
    elif weapon_id == WeaponId.ROCKET_LAUNCHER:
        # Rocket Launcher -> secondary type 1.
        state.secondary_projectiles.spawn(
            pos_x=muzzle_x,
            pos_y=muzzle_y,
            angle=shot_angle,
            type_id=SecondaryProjectileTypeId.ROCKET,
            owner_id=owner_id,
        )
    elif weapon_id == WeaponId.SEEKER_ROCKETS:
        # Seeker Rockets -> secondary type 2.
        state.secondary_projectiles.spawn(
            pos_x=muzzle_x,
            pos_y=muzzle_y,
            angle=shot_angle,
            type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
            owner_id=owner_id,
            target_hint_x=float(aim_x),
            target_hint_y=float(aim_y),
        )
    elif weapon_id == WeaponId.MINI_ROCKET_SWARMERS:
        # Mini-Rocket Swarmers -> secondary type 2 (fires the full clip in a spread).
        rocket_count = max(1, int(player.ammo))
        step = float(rocket_count) * (math.pi / 3.0)
        angle = (shot_angle - math.pi) - step * float(rocket_count) * 0.5
        for _ in range(rocket_count):
            state.secondary_projectiles.spawn(
                pos_x=muzzle_x,
                pos_y=muzzle_y,
                angle=angle,
                type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
                owner_id=owner_id,
                target_hint_x=float(aim_x),
                target_hint_y=float(aim_y),
            )
            angle += step
        ammo_cost = float(rocket_count)
        shot_count = rocket_count
    elif weapon_id == WeaponId.ROCKET_MINIGUN:
        # Rocket Minigun -> secondary type 4.
        state.secondary_projectiles.spawn(
            pos_x=muzzle_x,
            pos_y=muzzle_y,
            angle=shot_angle,
            type_id=SecondaryProjectileTypeId.ROCKET_MINIGUN,
            owner_id=owner_id,
        )
    elif weapon_id == WeaponId.FLAMETHROWER:
        # Flamethrower -> fast particle weapon (style 0), fractional ammo drain.
        state.particles.spawn_particle(pos_x=muzzle_x, pos_y=muzzle_y, angle=particle_angle, intensity=1.0, owner_id=owner_id)
        ammo_cost = 0.1
    elif weapon_id == WeaponId.BLOW_TORCH:
        # Blow Torch -> fast particle weapon (style 1), fractional ammo drain.
        particle_id = state.particles.spawn_particle(pos_x=muzzle_x, pos_y=muzzle_y, angle=particle_angle, intensity=1.0, owner_id=owner_id)
        state.particles.entries[particle_id].style_id = 1
        ammo_cost = 0.05
    elif weapon_id == WeaponId.HR_FLAMER:
        # HR Flamer -> fast particle weapon (style 2), fractional ammo drain.
        particle_id = state.particles.spawn_particle(pos_x=muzzle_x, pos_y=muzzle_y, angle=particle_angle, intensity=1.0, owner_id=owner_id)
        state.particles.entries[particle_id].style_id = 2
        ammo_cost = 0.1
    elif weapon_id == WeaponId.BUBBLEGUN:
        # Bubblegun -> slow particle weapon (style 8), fractional ammo drain.
        state.particles.spawn_particle_slow(pos_x=muzzle_x, pos_y=muzzle_y, angle=shot_angle - math.pi / 2.0, owner_id=owner_id)
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
                pos_x=muzzle_x,
                pos_y=muzzle_y,
                angle=shot_angle + angle_offset,
                type_id=type_id,
                owner_id=owner_id,
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
                pos_x=muzzle_x,
                pos_y=muzzle_y,
                angle=shot_angle + jitter,
                type_id=ProjectileTypeId.PLASMA_MINIGUN,
                owner_id=owner_id,
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
                pos_x=muzzle_x,
                pos_y=muzzle_y,
                angle=shot_angle + jitter,
                type_id=ProjectileTypeId.GAUSS_GUN,
                owner_id=owner_id,
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
                pos_x=muzzle_x,
                pos_y=muzzle_y,
                angle=shot_angle + jitter,
                type_id=ProjectileTypeId.ION_MINIGUN,
                owner_id=owner_id,
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
                pos_x=muzzle_x,
                pos_y=muzzle_y,
                angle=angle,
                type_id=type_id,
                owner_id=owner_id,
                base_damage=meta,
            )
            # Shotgun variants randomize speed_scale per pellet (rand%100 * 0.01 + 1.0).
            if pellets > 1 and weapon_id in (WeaponId.SHOTGUN, WeaponId.SAWED_OFF_SHOTGUN, WeaponId.JACKHAMMER):
                state.projectiles.entries[int(proj_id)].speed_scale = 1.0 + float(int(state.rng.rand()) % 100) * 0.01

    if 0 <= int(player.index) < len(state.shots_fired):
        state.shots_fired[int(player.index)] += int(shot_count)
        if 0 <= weapon_id < WEAPON_COUNT_SIZE:
            state.weapon_shots_fired[int(player.index)][weapon_id] += int(shot_count)

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
        player.ammo = max(0.0, float(player.ammo) - float(ammo_cost))
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
) -> None:
    """Port of `player_update` (0x004136b0) for the rewrite runtime."""

    if dt <= 0.0:
        return

    prev_x = player.pos_x
    prev_y = player.pos_y

    if player.health <= 0.0:
        player.death_timer -= dt * 20.0
        return

    player.muzzle_flash_alpha = max(0.0, player.muzzle_flash_alpha - dt * 2.0)
    cooldown_decay = dt * (1.5 if state.bonuses.weapon_power_up > 0.0 else 1.0)
    player.shot_cooldown = max(0.0, player.shot_cooldown - cooldown_decay)

    if perk_active(player, PerkId.SHARPSHOOTER):
        player.spread_heat = 0.02
    else:
        player.spread_heat = max(0.01, player.spread_heat - dt * 0.4)

    player.shield_timer = max(0.0, player.shield_timer - dt)
    player.fire_bullets_timer = max(0.0, player.fire_bullets_timer - dt)
    player.speed_bonus_timer = max(0.0, player.speed_bonus_timer - dt)
    if player.aux_timer > 0.0:
        aux_decay = 1.4 if player.aux_timer >= 1.0 else 0.5
        player.aux_timer = max(0.0, player.aux_timer - dt * aux_decay)

    # Aim: compute direction from (player -> aim point).
    player.aim_x = float(input_state.aim_x)
    player.aim_y = float(input_state.aim_y)
    aim_dx = player.aim_x - player.pos_x
    aim_dy = player.aim_y - player.pos_y
    aim_dir_x, aim_dir_y = _normalize(aim_dx, aim_dy)
    if aim_dir_x != 0.0 or aim_dir_y != 0.0:
        player.aim_dir_x = aim_dir_x
        player.aim_dir_y = aim_dir_y
        player.aim_heading = math.atan2(aim_dir_y, aim_dir_x) + math.pi / 2.0

    # Movement.
    raw_move_x = float(input_state.move_x)
    raw_move_y = float(input_state.move_y)
    raw_mag = math.hypot(raw_move_x, raw_move_y)
    # Demo/autoplay uses very small analog magnitudes to represent turn-in-place and
    # heading alignment slowdown; don't apply a deadzone there.
    moving_input = raw_mag > (0.0 if state.demo_mode_active else 0.2)

    if moving_input:
        inv = 1.0 / raw_mag if raw_mag > 1e-9 else 0.0
        move_x = raw_move_x * inv
        move_y = raw_move_y * inv
        player.heading = math.atan2(move_y, move_x) + math.pi / 2.0
        if perk_active(player, PerkId.LONG_DISTANCE_RUNNER):
            if player.move_speed < 2.0:
                player.move_speed = float(player.move_speed + dt * 4.0)
            player.move_speed = float(player.move_speed + dt)
            if player.move_speed > 2.8:
                player.move_speed = 2.8
        else:
            player.move_speed = float(player.move_speed + dt * 5.0)
            if player.move_speed > 2.0:
                player.move_speed = 2.0
    else:
        player.move_speed = float(player.move_speed - dt * 15.0)
        if player.move_speed < 0.0:
            player.move_speed = 0.0
        move_x = math.cos(player.heading - math.pi / 2.0)
        move_y = math.sin(player.heading - math.pi / 2.0)

    if player.weapon_id == WeaponId.MEAN_MINIGUN and player.move_speed > 0.8:
        player.move_speed = 0.8

    speed_multiplier = float(player.speed_multiplier)
    if player.speed_bonus_timer > 0.0:
        speed_multiplier += 1.0

    speed = player.move_speed * speed_multiplier * 25.0
    if moving_input:
        speed *= min(1.0, raw_mag)
    if perk_active(player, PerkId.ALTERNATE_WEAPON):
        speed *= 0.8

    player.pos_x = clamp(player.pos_x + move_x * speed * dt, 0.0, float(world_size))
    player.pos_y = clamp(player.pos_y + move_y * speed * dt, 0.0, float(world_size))

    player.move_phase += dt * player.move_speed * 19.0

    stationary = abs(player.pos_x - prev_x) <= 1e-9 and abs(player.pos_y - prev_y) <= 1e-9
    reload_scale = 1.0
    if stationary and perk_active(player, PerkId.STATIONARY_RELOADER):
        reload_scale = 3.0

    perk_ctx = _PlayerPerkTickCtx(state=state, player=player, players=players, dt=dt, stationary=stationary)
    for step in _PLAYER_PERK_TICK_STEPS:
        step(perk_ctx)

    # Reload + reload perks.
    if perk_active(player, PerkId.ANXIOUS_LOADER) and input_state.fire_pressed and player.reload_timer > 0.0:
        player.reload_timer = max(0.0, player.reload_timer - 0.05)

    if player.reload_timer > 0.0:
        if (
            perk_active(player, PerkId.ANGRY_RELOADER)
            and player.reload_timer_max > 0.5
            and (player.reload_timer_max * 0.5) < player.reload_timer
        ):
            half = player.reload_timer_max * 0.5
            next_timer = player.reload_timer - reload_scale * dt
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
            player.reload_timer -= reload_scale * dt

    if player.reload_timer < 0.0:
        player.reload_timer = 0.0

    if player.reload_active and player.reload_timer <= 0.0 and player.reload_timer_max > 0.0:
        player.ammo = float(player.clip_size)
        player.reload_active = False
        player.reload_timer_max = 0.0

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

    player_fire_weapon(player, input_state, dt, state, detail_preset=int(detail_preset))

    while player.move_phase > 14.0:
        player.move_phase -= 14.0
    while player.move_phase < 0.0:
        player.move_phase += 14.0


@dataclass(slots=True)
class _BonusApplyCtx:
    state: GameplayState
    player: PlayerState
    bonus_id: BonusId
    amount: int
    origin: _HasPos | None
    creatures: list[Damageable] | None
    players: list[PlayerState] | None
    apply_creature_damage: CreatureDamageApplier | None
    detail_preset: int
    economist_multiplier: float
    label: str
    icon_id: int

    def register_global(self, timer_key: str) -> None:
        self.state.bonus_hud.register(
            self.bonus_id,
            label=self.label,
            icon_id=self.icon_id,
            timer_ref=_TimerRef("global", str(timer_key)),
        )

    def register_player(self, timer_key: str) -> None:
        if self.players is not None and len(self.players) > 1:
            self.state.bonus_hud.register(
                self.bonus_id,
                label=self.label,
                icon_id=self.icon_id,
                timer_ref=_TimerRef("player", str(timer_key), player_index=0),
                timer_ref_alt=_TimerRef("player", str(timer_key), player_index=1),
            )
        else:
            self.state.bonus_hud.register(
                self.bonus_id,
                label=self.label,
                icon_id=self.icon_id,
                timer_ref=_TimerRef("player", str(timer_key), player_index=int(self.player.index)),
            )

    def origin_pos(self) -> _HasPos:
        return self.origin or self.player


_BonusApplyHandler = Callable[[_BonusApplyCtx], None]


def _bonus_apply_points(ctx: _BonusApplyCtx) -> None:
    # Native adds Points directly to player0 XP (no Double XP multiplier).
    amount = int(ctx.amount)
    if amount <= 0:
        return
    target = ctx.player
    if ctx.players is not None and len(ctx.players) > 0:
        target = ctx.players[0]
    target.experience += int(amount)


def _bonus_apply_energizer(ctx: _BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.energizer)
    if old <= 0.0:
        ctx.register_global("energizer")

    # Native `bonus_apply` ignores `bonus_entry.amount` for Energizer and always adds
    # a fixed 8 seconds scaled by Bonus Economist.
    #
    # Ghidra (crimsonland.exe @ 0x00409890):
    #   _bonus_energizer_timer = local_10[0] * 8.0 + _bonus_energizer_timer;
    ctx.state.bonuses.energizer = float(old + 8.0 * ctx.economist_multiplier)


def _bonus_apply_weapon_power_up(ctx: _BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.weapon_power_up)
    if old <= 0.0:
        ctx.register_global("weapon_power_up")
    ctx.state.bonuses.weapon_power_up = float(old + float(ctx.amount) * ctx.economist_multiplier)
    ctx.player.weapon_reset_latch = 0
    ctx.player.shot_cooldown = 0.0
    ctx.player.reload_active = False
    ctx.player.reload_timer = 0.0
    ctx.player.reload_timer_max = 0.0
    ctx.player.ammo = float(ctx.player.clip_size)


def _bonus_apply_double_experience(ctx: _BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.double_experience)
    if old <= 0.0:
        ctx.register_global("double_experience")
    # Native uses a fixed +6 seconds per pickup (scaled by Bonus Economist).
    ctx.state.bonuses.double_experience = float(old + 6.0 * ctx.economist_multiplier)


def _bonus_apply_reflex_boost(ctx: _BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.reflex_boost)
    if old <= 0.0:
        ctx.register_global("reflex_boost")
    ctx.state.bonuses.reflex_boost = float(old + float(ctx.amount) * ctx.economist_multiplier)

    targets = ctx.players if ctx.players is not None else [ctx.player]
    for target in targets:
        target.ammo = float(target.clip_size)
        target.reload_active = False
        target.reload_timer = 0.0
        target.reload_timer_max = 0.0


def _bonus_apply_freeze(ctx: _BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.freeze)
    if old <= 0.0:
        ctx.register_global("freeze")
    ctx.state.bonuses.freeze = float(old + float(ctx.amount) * ctx.economist_multiplier)

    creatures = ctx.creatures
    if creatures:
        rand = ctx.state.rng.rand
        for creature in creatures:
            active = getattr(creature, "active", True)
            if not bool(active):
                continue
            if float(getattr(creature, "hp", 0.0)) > 0.0:
                continue
            pos_x = float(getattr(creature, "x", 0.0))
            pos_y = float(getattr(creature, "y", 0.0))
            for _ in range(8):
                angle = float(int(rand()) % 0x264) * 0.01
                ctx.state.effects.spawn_freeze_shard(
                    pos_x=pos_x,
                    pos_y=pos_y,
                    angle=angle,
                    rand=rand,
                    detail_preset=int(ctx.detail_preset),
                )
            angle = float(int(rand()) % 0x264) * 0.01
            ctx.state.effects.spawn_freeze_shatter(
                pos_x=pos_x,
                pos_y=pos_y,
                angle=angle,
                rand=rand,
                detail_preset=int(ctx.detail_preset),
            )
            if hasattr(creature, "active"):
                setattr(creature, "active", False)

    ctx.state.sfx_queue.append("sfx_shockwave")


def _bonus_apply_shield(ctx: _BonusApplyCtx) -> None:
    should_register = float(ctx.player.shield_timer) <= 0.0
    if ctx.players is not None and len(ctx.players) > 1:
        should_register = float(ctx.players[0].shield_timer) <= 0.0 and float(ctx.players[1].shield_timer) <= 0.0
    if should_register:
        ctx.register_player("shield_timer")
    ctx.player.shield_timer = float(ctx.player.shield_timer + float(ctx.amount) * ctx.economist_multiplier)


def _bonus_apply_speed(ctx: _BonusApplyCtx) -> None:
    should_register = float(ctx.player.speed_bonus_timer) <= 0.0
    if ctx.players is not None and len(ctx.players) > 1:
        should_register = (
            float(ctx.players[0].speed_bonus_timer) <= 0.0 and float(ctx.players[1].speed_bonus_timer) <= 0.0
        )
    if should_register:
        ctx.register_player("speed_bonus_timer")
    ctx.player.speed_bonus_timer = float(ctx.player.speed_bonus_timer + float(ctx.amount) * ctx.economist_multiplier)


def _bonus_apply_fire_bullets(ctx: _BonusApplyCtx) -> None:
    should_register = float(ctx.player.fire_bullets_timer) <= 0.0
    if ctx.players is not None and len(ctx.players) > 1:
        should_register = float(ctx.players[0].fire_bullets_timer) <= 0.0 and float(ctx.players[1].fire_bullets_timer) <= 0.0
    if should_register:
        ctx.register_player("fire_bullets_timer")
    # Native uses a fixed +5 seconds per pickup (scaled by Bonus Economist).
    ctx.player.fire_bullets_timer = float(ctx.player.fire_bullets_timer + 5.0 * ctx.economist_multiplier)
    ctx.player.weapon_reset_latch = 0
    ctx.player.shot_cooldown = 0.0
    ctx.player.reload_active = False
    ctx.player.reload_timer = 0.0
    ctx.player.reload_timer_max = 0.0
    ctx.player.ammo = float(ctx.player.clip_size)


def _bonus_apply_shock_chain(ctx: _BonusApplyCtx) -> None:
    creatures = ctx.creatures
    if not creatures:
        return

    origin_pos = ctx.origin_pos()
    # Mirrors the `exclude_id == -1` behavior of `creature_find_nearest(origin, -1, 0.0)`:
    # - requires `active != 0`
    # - requires `hitbox_size == 16.0` (alive sentinel)
    # - no HP gate
    # - falls back to index 0 if nothing qualifies
    origin_x = float(origin_pos.pos_x)
    origin_y = float(origin_pos.pos_y)
    best_idx = 0
    best_dist_sq = 1e12
    for idx, creature in enumerate(creatures):
        if not creature.active:
            continue
        if creature.hitbox_size != 16.0:
            continue
        d_sq = distance_sq(origin_x, origin_y, creature.x, creature.y)
        if d_sq < best_dist_sq:
            best_dist_sq = d_sq
            best_idx = idx

    target = creatures[best_idx]
    dx = target.x - origin_x
    dy = target.y - origin_y
    angle = math.atan2(dy, dx) + math.pi / 2.0
    owner_id = _owner_id_for_player(ctx.player.index) if ctx.state.friendly_fire_enabled else -100

    ctx.state.bonus_spawn_guard = True
    ctx.state.shock_chain_links_left = 0x20
    ctx.state.shock_chain_projectile_id = _projectile_spawn(
        ctx.state,
        players=ctx.players,
        pos_x=origin_x,
        pos_y=origin_y,
        angle=angle,
        type_id=int(ProjectileTypeId.ION_RIFLE),
        owner_id=int(owner_id),
    )
    ctx.state.bonus_spawn_guard = False
    ctx.state.sfx_queue.append("sfx_shock_hit_01")


def _bonus_apply_weapon(ctx: _BonusApplyCtx) -> None:
    weapon_id = int(ctx.amount)
    if perk_active(ctx.player, PerkId.ALTERNATE_WEAPON) and ctx.player.alt_weapon_id is None:
        ctx.player.alt_weapon_id = int(ctx.player.weapon_id)
        ctx.player.alt_clip_size = int(ctx.player.clip_size)
        ctx.player.alt_ammo = float(ctx.player.ammo)
        ctx.player.alt_reload_active = bool(ctx.player.reload_active)
        ctx.player.alt_reload_timer = float(ctx.player.reload_timer)
        ctx.player.alt_shot_cooldown = float(ctx.player.shot_cooldown)
        ctx.player.alt_reload_timer_max = float(ctx.player.reload_timer_max)
    weapon_assign_player(ctx.player, weapon_id, state=ctx.state)


def _bonus_apply_medikit(ctx: _BonusApplyCtx) -> None:
    if float(ctx.player.health) >= 100.0:
        return
    ctx.player.health = min(100.0, float(ctx.player.health) + 10.0)


def _bonus_apply_fireblast(ctx: _BonusApplyCtx) -> None:
    origin_pos = ctx.origin_pos()
    owner_id = _owner_id_for_player(ctx.player.index) if ctx.state.friendly_fire_enabled else -100
    ctx.state.bonus_spawn_guard = True
    _spawn_projectile_ring(
        ctx.state,
        origin_pos,
        count=16,
        angle_offset=0.0,
        type_id=ProjectileTypeId.PLASMA_RIFLE,
        owner_id=int(owner_id),
        players=ctx.players,
    )
    ctx.state.bonus_spawn_guard = False
    ctx.state.sfx_queue.append("sfx_explosion_medium")


def _bonus_apply_nuke(ctx: _BonusApplyCtx) -> None:
    # `bonus_apply` (crimsonland.exe @ 0x00409890) starts screen shake via:
    #   camera_shake_pulses = 0x14;
    #   camera_shake_timer = 0.2f;
    ctx.state.camera_shake_pulses = 0x14
    ctx.state.camera_shake_timer = 0.2

    origin_pos = ctx.origin_pos()
    ox = float(origin_pos.pos_x)
    oy = float(origin_pos.pos_y)
    rand = ctx.state.rng.rand

    bullet_count = int(rand()) & 3
    bullet_count += 4
    for _ in range(bullet_count):
        angle = float(int(rand()) % 0x274) * 0.01
        proj_id = _projectile_spawn(
            ctx.state,
            players=ctx.players,
            pos_x=ox,
            pos_y=oy,
            angle=float(angle),
            type_id=int(ProjectileTypeId.PISTOL),
            owner_id=-100,
        )
        if proj_id != -1:
            speed_scale = float(int(rand()) % 0x32) * 0.01 + 0.5
            ctx.state.projectiles.entries[proj_id].speed_scale *= float(speed_scale)

    for _ in range(2):
        angle = float(int(rand()) % 0x274) * 0.01
        _projectile_spawn(
            ctx.state,
            players=ctx.players,
            pos_x=ox,
            pos_y=oy,
            angle=float(angle),
            type_id=int(ProjectileTypeId.GAUSS_GUN),
            owner_id=-100,
        )

    ctx.state.effects.spawn_explosion_burst(
        pos_x=ox,
        pos_y=oy,
        scale=1.0,
        rand=rand,
        detail_preset=int(ctx.detail_preset),
    )

    creatures = ctx.creatures
    if creatures:
        prev_guard = bool(ctx.state.bonus_spawn_guard)
        ctx.state.bonus_spawn_guard = True
        for idx, creature in enumerate(creatures):
            # Native applies explosion damage to any active creature, including
            # those already in the death/corpse state (this shrinks corpses
            # faster via the hp<=0 path in creature_apply_damage).
            if not bool(getattr(creature, "active", True)):
                continue
            dx = float(creature.x) - ox
            dy = float(creature.y) - oy
            if abs(dx) > 256.0 or abs(dy) > 256.0:
                continue
            dist = math.hypot(dx, dy)
            if dist < 256.0:
                damage = (256.0 - dist) * 5.0
                if ctx.apply_creature_damage is not None:
                    ctx.apply_creature_damage(
                        int(idx),
                        float(damage),
                        3,
                        0.0,
                        0.0,
                        _owner_id_for_player(ctx.player.index),
                    )
                else:
                    creature.hp -= float(damage)
        ctx.state.bonus_spawn_guard = prev_guard

    ctx.state.sfx_queue.append("sfx_explosion_large")
    ctx.state.sfx_queue.append("sfx_shockwave")


_BONUS_APPLY_HANDLERS: dict[BonusId, _BonusApplyHandler] = {
    BonusId.POINTS: _bonus_apply_points,
    BonusId.ENERGIZER: _bonus_apply_energizer,
    BonusId.WEAPON_POWER_UP: _bonus_apply_weapon_power_up,
    BonusId.DOUBLE_EXPERIENCE: _bonus_apply_double_experience,
    BonusId.REFLEX_BOOST: _bonus_apply_reflex_boost,
    BonusId.FREEZE: _bonus_apply_freeze,
    BonusId.SHIELD: _bonus_apply_shield,
    BonusId.MEDIKIT: _bonus_apply_medikit,
    BonusId.SPEED: _bonus_apply_speed,
    BonusId.FIRE_BULLETS: _bonus_apply_fire_bullets,
    BonusId.SHOCK_CHAIN: _bonus_apply_shock_chain,
    BonusId.WEAPON: _bonus_apply_weapon,
    BonusId.FIREBLAST: _bonus_apply_fireblast,
    BonusId.NUKE: _bonus_apply_nuke,
}


def bonus_apply(
    state: GameplayState,
    player: PlayerState,
    bonus_id: BonusId,
    *,
    amount: int | None = None,
    origin: _HasPos | None = None,
    creatures: list[Damageable] | None = None,
    players: list[PlayerState] | None = None,
    apply_creature_damage: CreatureDamageApplier | None = None,
    detail_preset: int = 5,
) -> None:
    """Apply a bonus to player + global timers (subset of `bonus_apply`)."""

    meta = BONUS_BY_ID.get(int(bonus_id))
    if meta is None:
        return
    if amount is None:
        amount = int(meta.default_amount or 0)

    economist_multiplier = 1.5 if perk_count_get(player, PerkId.BONUS_ECONOMIST) != 0 else 1.0
    icon_id = int(meta.icon_id) if meta.icon_id is not None else -1
    label = meta.name
    ctx = _BonusApplyCtx(
        state=state,
        player=player,
        bonus_id=bonus_id,
        amount=int(amount),
        origin=origin,
        creatures=creatures,
        players=players,
        apply_creature_damage=apply_creature_damage,
        detail_preset=int(detail_preset),
        economist_multiplier=float(economist_multiplier),
        label=str(label),
        icon_id=int(icon_id),
    )
    handler = _BONUS_APPLY_HANDLERS.get(bonus_id)
    if handler is not None:
        handler(ctx)

    # Bonus types not modeled yet.
    return


def bonus_hud_update(state: GameplayState, players: list[PlayerState], *, dt: float = 0.0) -> None:
    """Refresh HUD slots based on current timer values + advance slide animation."""

    def _timer_value(ref: _TimerRef | None) -> float:
        if ref is None:
            return 0.0
        if ref.kind == "global":
            return float(getattr(state.bonuses, ref.key, 0.0) or 0.0)
        if ref.kind == "player":
            idx = ref.player_index
            if idx is None or not (0 <= idx < len(players)):
                return 0.0
            return float(getattr(players[idx], ref.key, 0.0) or 0.0)
        return 0.0

    player_count = len(players)
    dt = max(0.0, float(dt))

    for slot_index, slot in enumerate(state.bonus_hud.slots):
        if not slot.active:
            continue
        timer = max(0.0, _timer_value(slot.timer_ref))
        timer_alt = max(0.0, _timer_value(slot.timer_ref_alt)) if (slot.timer_ref_alt is not None and player_count > 1) else 0.0
        slot.timer_value = float(timer)
        slot.timer_value_alt = float(timer_alt)

        if timer > 0.0 or timer_alt > 0.0:
            slot.slide_x += dt * 350.0
        else:
            slot.slide_x -= dt * 320.0

        if slot.slide_x > -2.0:
            slot.slide_x = -2.0

        if slot.slide_x < -184.0 and not any(other.active for other in state.bonus_hud.slots[slot_index + 1 :]):
            slot.active = False
            slot.bonus_id = 0
            slot.label = ""
            slot.icon_id = -1
            slot.slide_x = -184.0
            slot.timer_ref = None
            slot.timer_ref_alt = None
            slot.timer_value = 0.0
            slot.timer_value_alt = 0.0


def bonus_telekinetic_update(
    state: GameplayState,
    players: list[PlayerState],
    dt: float,
    *,
    creatures: list[Damageable] | None = None,
    apply_creature_damage: CreatureDamageApplier | None = None,
    detail_preset: int = 5,
) -> list[BonusPickupEvent]:
    """Allow Telekinetic perk owners to pick up bonuses by aiming at them."""

    if dt <= 0.0:
        return []

    pickups: list[BonusPickupEvent] = []
    dt_ms = float(dt) * 1000.0

    for player in players:
        if player.health <= 0.0:
            player.bonus_aim_hover_index = -1
            player.bonus_aim_hover_timer_ms = 0.0
            continue

        hovered = bonus_find_aim_hover_entry(player, state.bonus_pool)
        if hovered is None:
            player.bonus_aim_hover_index = -1
            player.bonus_aim_hover_timer_ms = 0.0
            continue

        idx, entry = hovered
        if idx != int(player.bonus_aim_hover_index):
            player.bonus_aim_hover_index = int(idx)
            player.bonus_aim_hover_timer_ms = dt_ms
        else:
            player.bonus_aim_hover_timer_ms += dt_ms

        if player.bonus_aim_hover_timer_ms <= BONUS_TELEKINETIC_PICKUP_MS:
            continue
        if not perk_active(player, PerkId.TELEKINETIC):
            continue
        if entry.picked or entry.bonus_id == 0:
            continue

        bonus_apply(
            state,
            player,
            BonusId(int(entry.bonus_id)),
            amount=int(entry.amount),
            origin=entry,
            creatures=creatures,
            players=players,
            apply_creature_damage=apply_creature_damage,
            detail_preset=int(detail_preset),
        )
        entry.picked = True
        entry.time_left = BONUS_PICKUP_LINGER
        pickups.append(
            BonusPickupEvent(
                player_index=int(player.index),
                bonus_id=int(entry.bonus_id),
                amount=int(entry.amount),
                pos_x=float(entry.pos_x),
                pos_y=float(entry.pos_y),
            )
        )

        # Match the exe: after a telekinetic pickup, reset the hover accumulator.
        player.bonus_aim_hover_index = -1
        player.bonus_aim_hover_timer_ms = 0.0

    return pickups


def bonus_update(
    state: GameplayState,
    players: list[PlayerState],
    dt: float,
    *,
    creatures: list[Damageable] | None = None,
    update_hud: bool = True,
    apply_creature_damage: CreatureDamageApplier | None = None,
    detail_preset: int = 5,
) -> list[BonusPickupEvent]:
    """Advance world bonuses and global timers (subset of `bonus_update`)."""

    pickups = bonus_telekinetic_update(
        state,
        players,
        dt,
        creatures=creatures,
        apply_creature_damage=apply_creature_damage,
        detail_preset=int(detail_preset),
    )
    pickups.extend(
        state.bonus_pool.update(
            dt,
            state=state,
            players=players,
            creatures=creatures,
            apply_creature_damage=apply_creature_damage,
            detail_preset=int(detail_preset),
        )
    )

    if dt > 0.0:
        state.bonuses.weapon_power_up = max(0.0, state.bonuses.weapon_power_up - dt)
        state.bonuses.reflex_boost = max(0.0, state.bonuses.reflex_boost - dt)
        state.bonuses.energizer = max(0.0, state.bonuses.energizer - dt)
        state.bonuses.double_experience = max(0.0, state.bonuses.double_experience - dt)
        state.bonuses.freeze = max(0.0, state.bonuses.freeze - dt)

    if update_hud:
        bonus_hud_update(state, players, dt=dt)

    return pickups
