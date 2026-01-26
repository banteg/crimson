from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Protocol

from .bonuses import BONUS_BY_ID, BonusId
from .crand import Crand
from .perks import PerkFlags, PerkId, PerkMeta, PERK_TABLE
from .projectiles import Damageable, ProjectilePool, SecondaryProjectilePool
from .weapons import WEAPON_BY_ID, WEAPON_TABLE, Weapon


class _HasPos(Protocol):
    pos_x: float
    pos_y: float


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


@dataclass(slots=True)
class PlayerState:
    index: int
    pos_x: float
    pos_y: float
    health: float = 100.0
    size: float = 50.0

    move_speed_multiplier: float = 2.0
    move_phase: float = 0.0

    aim_heading: float = 0.0
    aim_dir_x: float = 1.0
    aim_dir_y: float = 0.0

    weapon_id: int = 0
    clip_size: int = 0
    ammo: int = 0
    reload_active: bool = False
    reload_timer: float = 0.0
    reload_timer_max: float = 0.0
    shot_cooldown: float = 0.0
    spread_heat: float = 0.01
    muzzle_flash_alpha: float = 0.0

    alt_weapon_id: int | None = None
    alt_clip_size: int = 0
    alt_ammo: int = 0
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
    timer_ref: _TimerRef | None = None
    timer_ref_alt: _TimerRef | None = None


BONUS_HUD_SLOT_COUNT = 16

BONUS_POOL_SIZE = 16
BONUS_SPAWN_MARGIN = 32.0
BONUS_SPAWN_MIN_DISTANCE = 32.0
BONUS_PICKUP_RADIUS = 26.0
BONUS_PICKUP_DECAY_RATE = 3.0
BONUS_PICKUP_LINGER = 0.5
BONUS_TIME_MAX = 10.0
BONUS_WEAPON_NEAR_RADIUS = 56.0

_WEAPON_RANDOM_IDS = [entry.weapon_id for entry in WEAPON_TABLE if entry.name is not None]


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
        slot.timer_ref = timer_ref
        slot.timer_ref_alt = timer_ref_alt


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
        world_width: float = 1024.0,
        world_height: float = 1024.0,
    ) -> BonusEntry | None:
        if int(bonus_id) == 0:
            return None
        entry = self._alloc_slot()
        if entry is None:
            return None

        x = _clamp(float(pos_x), BONUS_SPAWN_MARGIN, float(world_width) - BONUS_SPAWN_MARGIN)
        y = _clamp(float(pos_y), BONUS_SPAWN_MARGIN, float(world_height) - BONUS_SPAWN_MARGIN)

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
            if _distance_sq(pos_x, pos_y, entry.pos_x, entry.pos_y) < min_dist_sq:
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
            entry.amount = weapon_pick_random_available(rng)
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
        if state.bonus_spawn_guard:
            return None

        rng = state.rng
        if rng.rand() % 9 != 1:
            if not any(perk_active(player, PerkId.BONUS_MAGNET) for player in players):
                return None
            if rng.rand() % 10 != 2:
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
            for player in players:
                if _distance_sq(pos_x, pos_y, player.pos_x, player.pos_y) < near_sq:
                    entry.bonus_id = int(BonusId.POINTS)
                    entry.amount = 100
                    break

        if entry.bonus_id != int(BonusId.POINTS):
            matches = sum(1 for bonus in self._entries if bonus.bonus_id == entry.bonus_id)
            if matches > 1:
                self._clear_entry(entry)
                return None

        if entry.bonus_id == int(BonusId.WEAPON):
            for player in players:
                if entry.amount == player.weapon_id:
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
    ) -> list[BonusPickupEvent]:
        if dt <= 0.0:
            return []

        pickups: list[BonusPickupEvent] = []
        for entry in self._entries:
            if entry.bonus_id == 0:
                continue

            decay = dt * (BONUS_PICKUP_DECAY_RATE if entry.picked else 1.0)
            entry.time_left -= decay
            if entry.time_left < 0.0:
                self._clear_entry(entry)
                continue

            if entry.picked:
                continue

            for player in players:
                if _distance_sq(entry.pos_x, entry.pos_y, player.pos_x, player.pos_y) < BONUS_PICKUP_RADIUS * BONUS_PICKUP_RADIUS:
                    bonus_apply(
                        state,
                        player,
                        BonusId(entry.bonus_id),
                        amount=entry.amount,
                        origin=player,
                        creatures=creatures,
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


@dataclass(slots=True)
class GameplayState:
    rng: Crand = field(default_factory=lambda: Crand(0xBEEF))
    projectiles: ProjectilePool = field(default_factory=ProjectilePool)
    secondary_projectiles: SecondaryProjectilePool = field(default_factory=SecondaryProjectilePool)
    bonuses: BonusTimers = field(default_factory=BonusTimers)
    perk_intervals: PerkEffectIntervals = field(default_factory=PerkEffectIntervals)
    perk_selection: PerkSelectionState = field(default_factory=PerkSelectionState)
    bonus_spawn_guard: bool = False
    bonus_hud: BonusHudState = field(default_factory=BonusHudState)
    bonus_pool: BonusPool = field(default_factory=BonusPool)
    shock_chain_links_left: int = 0
    shock_chain_projectile_id: int = -1


def perk_count_get(player: PlayerState, perk_id: PerkId) -> int:
    idx = int(perk_id)
    if idx < 0:
        return 0
    if idx >= len(player.perk_counts):
        return 0
    return int(player.perk_counts[idx])


def perk_active(player: PlayerState, perk_id: PerkId) -> bool:
    return perk_count_get(player, perk_id) > 0


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


def perk_can_offer(player: PlayerState, meta: PerkMeta, *, game_mode: int, player_count: int) -> bool:
    perk_id = meta.perk_id
    if perk_id == PerkId.ANTIPERK:
        return False
    flags = meta.flags or PerkFlags(0)
    if (flags & PerkFlags.MODE_3_ONLY) and game_mode != 3:
        return False
    if (flags & PerkFlags.TWO_PLAYER_ONLY) and player_count != 2:
        return False
    if (flags & PerkFlags.STACKABLE) == 0 and perk_count_get(player, perk_id) > 0:
        return False
    if meta.prereq and any(perk_count_get(player, req) <= 0 for req in meta.prereq):
        return False
    return True


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
    pool = [meta.perk_id for meta in PERK_TABLE if perk_can_offer(player, meta, game_mode=game_mode, player_count=player_count)]
    choices: list[PerkId] = []
    while pool and len(choices) < count:
        idx = int(state.rng.rand() % len(pool))
        choices.append(pool.pop(idx))
    return choices


def _increment_perk_count(player: PlayerState, perk_id: PerkId, *, amount: int = 1) -> None:
    idx = int(perk_id)
    if 0 <= idx < len(player.perk_counts):
        player.perk_counts[idx] += int(amount)


def perk_apply(
    state: GameplayState,
    players: list[PlayerState],
    perk_id: PerkId,
    *,
    perk_state: PerkSelectionState | None = None,
) -> None:
    """Apply immediate perk effects and increment the perk counter."""

    if not players:
        return
    owner = players[0]
    _increment_perk_count(owner, perk_id)

    if perk_id == PerkId.INSTANT_WINNER:
        owner.experience += 2500
        return

    if perk_id == PerkId.FATAL_LOTTERY:
        if state.rng.rand() & 1:
            for player in players:
                if player.health > 0.0:
                    player.health = -1.0
        else:
            owner.experience += 10000
        return

    if perk_id == PerkId.LIFELINE_50_50:
        # Requires creature pool access; keep as a no-op for now.
        return

    if perk_id == PerkId.THICK_SKINNED:
        for player in players:
            if player.health > 0.0:
                player.health = max(1.0, player.health * (2.0 / 3.0))
        return

    if perk_id == PerkId.BREATHING_ROOM:
        for player in players:
            if player.health > 0.0:
                player.health -= player.health * (2.0 / 3.0)
        # Creature clear not modeled yet.
        return

    if perk_id == PerkId.INFERNAL_CONTRACT:
        owner.level += 3
        if perk_state is not None:
            perk_state.pending_count += 3
            perk_state.choices_dirty = True
        for player in players:
            if player.health > 0.0:
                player.health = 0.1
        return

    if perk_id == PerkId.GRIM_DEAL:
        owner.health = -1.0
        owner.experience += int(owner.experience * 0.18)
        return

    if perk_id == PerkId.AMMO_MANIAC:
        for player in players:
            player.ammo = player.clip_size
            player.reload_active = False
            player.reload_timer = 0.0
            player.reload_timer_max = 0.0
        return

    if perk_id == PerkId.DEATH_CLOCK:
        _increment_perk_count(owner, PerkId.REGENERATION, amount=-perk_count_get(owner, PerkId.REGENERATION))
        _increment_perk_count(owner, PerkId.GREATER_REGENERATION, amount=-perk_count_get(owner, PerkId.GREATER_REGENERATION))
        for player in players:
            if player.health > 0.0:
                player.health = 100.0
        return

    if perk_id == PerkId.BANDAGE:
        for player in players:
            if player.health > 0.0:
                scale = float(state.rng.rand() % 50 + 1)
                player.health = min(100.0, player.health * scale)
        return

    if perk_id == PerkId.MY_FAVOURITE_WEAPON:
        for player in players:
            player.clip_size += 2
        return

    if perk_id == PerkId.PLAGUEBEARER:
        owner.plaguebearer_active = True


def perk_auto_pick(
    state: GameplayState,
    players: list[PlayerState],
    perk_state: PerkSelectionState,
    *,
    game_mode: int,
    player_count: int | None = None,
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
        perk_apply(state, players, perk_id, perk_state=perk_state)
        picks.append(perk_id)
        perk_state.pending_count -= 1
        perk_state.choices_dirty = True
    return picks


def survival_progression_update(
    state: GameplayState,
    players: list[PlayerState],
    *,
    game_mode: int,
    player_count: int | None = None,
    auto_pick: bool = True,
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
        )
    return []


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _normalize(x: float, y: float) -> tuple[float, float]:
    mag = math.hypot(x, y)
    if mag <= 1e-9:
        return 0.0, 0.0
    inv = 1.0 / mag
    return x * inv, y * inv


def _distance_sq(x0: float, y0: float, x1: float, y1: float) -> float:
    dx = x1 - x0
    dy = y1 - y0
    return dx * dx + dy * dy


def _owner_id_for_player(player_index: int) -> int:
    # crimsonland.exe uses -1/-2/-3 for players (and sometimes -100 in demo paths).
    return -1 - int(player_index)


FIRE_BULLETS_PROJECTILE_TYPE_ID = 0x2C


def _weapon_entry(weapon_id: int) -> Weapon | None:
    return WEAPON_BY_ID.get(int(weapon_id))


def weapon_pick_random_available(rng: Crand) -> int:
    if not _WEAPON_RANDOM_IDS:
        return 0
    idx = int(rng.rand()) % len(_WEAPON_RANDOM_IDS)
    return int(_WEAPON_RANDOM_IDS[idx])


def _projectile_meta_for_type_id(type_id: int) -> float:
    entry = WEAPON_BY_ID.get(int(type_id))
    meta = entry.projectile_type if entry is not None else None
    return float(meta if meta is not None else 45.0)


def _bonus_enabled(bonus_id: int) -> bool:
    meta = BONUS_BY_ID.get(int(bonus_id))
    if meta is None:
        return False
    return meta.bonus_id != BonusId.UNUSED


def _bonus_id_from_roll(roll: int, rng: Crand) -> int:
    # Mirrors bonus_pick_random_type (0x412470): r = rand() % 162 (0..161),
    # Points if r <= 12, Energizer if r == 13 and (rand & 63) == 0, else
    # bucketed ids 3..14 with a 10-step loop that wraps every 120 counts.
    r = roll - 1
    if r < 0 or r >= 162:
        return 0
    if r <= 12:
        return int(BonusId.POINTS)
    if r == 13 and (rng.rand() & 63) == 0:
        return int(BonusId.ENERGIZER)
    bucket_index = (r - 13) % 120
    return int(BonusId.WEAPON) + (bucket_index // 10)


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
        if state.shock_chain_links_left > 0 and bonus_id == int(BonusId.SHOCK_CHAIN):
            continue
        if bonus_id == int(BonusId.FREEZE) and state.bonuses.freeze > 0.0:
            continue
        if bonus_id == int(BonusId.SHIELD) and any(player.shield_timer > 0.0 for player in players):
            continue
        if bonus_id == int(BonusId.WEAPON) and has_fire_bullets_drop:
            continue
        if bonus_id == int(BonusId.WEAPON) and any(perk_active(player, PerkId.MY_FAVOURITE_WEAPON) for player in players):
            continue
        if bonus_id == int(BonusId.MEDIKIT) and any(perk_active(player, PerkId.DEATH_CLOCK) for player in players):
            continue
        if not _bonus_enabled(bonus_id):
            continue
        return bonus_id
    return int(BonusId.POINTS)


def weapon_assign_player(player: PlayerState, weapon_id: int) -> None:
    """Assign weapon and reset per-weapon runtime state (ammo/cooldowns)."""

    weapon = _weapon_entry(weapon_id)
    player.weapon_id = int(weapon_id)
    clip = int(getattr(weapon, "clip_size", 0) or 0) if weapon is not None else 0
    player.clip_size = max(0, clip)
    player.ammo = player.clip_size
    player.reload_active = False
    player.reload_timer = 0.0
    player.reload_timer_max = 0.0
    player.shot_cooldown = 0.0


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
    reload_time = float(getattr(weapon, "reload_time", 0.0) or 0.0) if weapon is not None else 0.0

    if not player.reload_active:
        player.reload_active = True

    if perk_active(player, PerkId.FASTLOADER):
        reload_time *= 0.69999999
    if state.bonuses.weapon_power_up > 0.0:
        reload_time *= 0.60000002

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
) -> None:
    if count <= 0:
        return
    step = math.tau / float(count)
    meta = _projectile_meta_for_type_id(type_id)
    for idx in range(count):
        state.projectiles.spawn(
            pos_x=float(origin.pos_x),
            pos_y=float(origin.pos_y),
            angle=float(idx) * step + float(angle_offset),
            type_id=int(type_id),
            owner_id=int(owner_id),
            base_damage=meta,
        )


def _perk_update_man_bomb(player: PlayerState, dt: float, state: GameplayState) -> None:
    player.man_bomb_timer += dt
    if player.man_bomb_timer <= state.perk_intervals.man_bomb:
        return

    owner_id = _owner_id_for_player(player.index)
    state.bonus_spawn_guard = True
    for idx in range(8):
        type_id = 0x14 if (idx % 2) else 0x15
        angle = (float(state.rng.rand() % 50) * 0.01) + float(idx) * (math.pi / 4.0) - 0.25
        state.projectiles.spawn(
            pos_x=player.pos_x,
            pos_y=player.pos_y,
            angle=angle,
            type_id=type_id,
            owner_id=owner_id,
            base_damage=_projectile_meta_for_type_id(type_id),
        )
    state.bonus_spawn_guard = False

    player.man_bomb_timer -= state.perk_intervals.man_bomb
    state.perk_intervals.man_bomb = 4.0


def _perk_update_hot_tempered(player: PlayerState, dt: float, state: GameplayState) -> None:
    player.hot_tempered_timer += dt
    if player.hot_tempered_timer <= state.perk_intervals.hot_tempered:
        return

    owner_id = _owner_id_for_player(player.index)
    state.bonus_spawn_guard = True
    for idx in range(8):
        type_id = 8 if (idx % 2) else 0x0A
        angle = float(idx) * (math.pi / 4.0)
        state.projectiles.spawn(
            pos_x=player.pos_x,
            pos_y=player.pos_y,
            angle=angle,
            type_id=type_id,
            owner_id=owner_id,
            base_damage=_projectile_meta_for_type_id(type_id),
        )
    state.bonus_spawn_guard = False

    player.hot_tempered_timer -= state.perk_intervals.hot_tempered
    state.perk_intervals.hot_tempered = float(state.rng.rand() % 8) + 2.0


def _perk_update_fire_cough(player: PlayerState, dt: float, state: GameplayState) -> None:
    player.fire_cough_timer += dt
    if player.fire_cough_timer <= state.perk_intervals.fire_cough:
        return

    owner_id = _owner_id_for_player(player.index)
    # Fire Cough spawns a fire projectile (and a small sprite burst) from the muzzle.
    theta = math.atan2(player.aim_dir_y, player.aim_dir_x)
    jitter = (float(state.rng.rand() % 200) - 100.0) * 0.0015
    angle = theta + jitter + math.pi / 2.0
    muzzle_x = player.pos_x + player.aim_dir_x * 16.0
    muzzle_y = player.pos_y + player.aim_dir_y * 16.0
    state.projectiles.spawn(
        pos_x=muzzle_x,
        pos_y=muzzle_y,
        angle=angle,
        type_id=FIRE_BULLETS_PROJECTILE_TYPE_ID,
        owner_id=owner_id,
        base_damage=_projectile_meta_for_type_id(FIRE_BULLETS_PROJECTILE_TYPE_ID),
    )

    player.fire_cough_timer -= state.perk_intervals.fire_cough
    state.perk_intervals.fire_cough = float(state.rng.rand() % 4) + 2.0


def player_fire_weapon(player: PlayerState, input_state: PlayerInput, dt: float, state: GameplayState) -> None:
    del dt

    weapon = _weapon_entry(player.weapon_id)
    if weapon is None:
        return

    if player.reload_timer > 0.0:
        return
    if player.shot_cooldown > 0.0:
        return
    if not input_state.fire_down:
        return

    if player.ammo <= 0:
        player_start_reload(player, state)
        return

    pellet_count = int(getattr(weapon, "pellet_count", 0) or 0)
    fire_bullets_weapon = _weapon_entry(FIRE_BULLETS_PROJECTILE_TYPE_ID)

    shot_cooldown = float(getattr(weapon, "fire_rate", 0.0) or 0.0)
    spread_inc = float(getattr(weapon, "spread", 0.0) or 0.0) * 1.3
    if player.fire_bullets_timer > 0.0 and pellet_count == 1 and fire_bullets_weapon is not None:
        shot_cooldown = float(getattr(fire_bullets_weapon, "fire_rate", 0.0) or 0.0)
        spread_inc = float(getattr(fire_bullets_weapon, "spread", 0.0) or 0.0) * 1.3

    if perk_active(player, PerkId.FASTSHOT):
        shot_cooldown *= 0.88
    if perk_active(player, PerkId.SHARPSHOOTER):
        shot_cooldown *= 1.05
    player.shot_cooldown = max(0.0, shot_cooldown)

    if not perk_active(player, PerkId.SHARPSHOOTER):
        player.spread_heat = min(0.48, max(0.0, player.spread_heat + spread_inc))

    # Secondary-projectile weapons (effects.md).
    if player.weapon_id == 12:
        # Seeker Rockets -> secondary type 1.
        theta = math.atan2(player.aim_dir_y, player.aim_dir_x) + math.pi / 2.0
        muzzle_x = player.pos_x + player.aim_dir_x * 16.0
        muzzle_y = player.pos_y + player.aim_dir_y * 16.0
        state.secondary_projectiles.spawn(pos_x=muzzle_x, pos_y=muzzle_y, angle=theta, type_id=1)
    elif player.weapon_id == 13:
        # Plasma Shotgun -> secondary type 2.
        theta = math.atan2(player.aim_dir_y, player.aim_dir_x) + math.pi / 2.0
        muzzle_x = player.pos_x + player.aim_dir_x * 16.0
        muzzle_y = player.pos_y + player.aim_dir_y * 16.0
        state.secondary_projectiles.spawn(pos_x=muzzle_x, pos_y=muzzle_y, angle=theta, type_id=2)
    elif player.weapon_id == 17:
        # Rocket Minigun -> secondary type 2 (multiple per shot in native; keep 1 for now).
        theta = math.atan2(player.aim_dir_y, player.aim_dir_x) + math.pi / 2.0
        muzzle_x = player.pos_x + player.aim_dir_x * 16.0
        muzzle_y = player.pos_y + player.aim_dir_y * 16.0
        state.secondary_projectiles.spawn(pos_x=muzzle_x, pos_y=muzzle_y, angle=theta, type_id=2)
    elif player.weapon_id == 18:
        # Pulse Gun -> secondary type 4.
        theta = math.atan2(player.aim_dir_y, player.aim_dir_x) + math.pi / 2.0
        muzzle_x = player.pos_x + player.aim_dir_x * 16.0
        muzzle_y = player.pos_y + player.aim_dir_y * 16.0
        state.secondary_projectiles.spawn(pos_x=muzzle_x, pos_y=muzzle_y, angle=theta, type_id=4)
    else:
        theta = math.atan2(player.aim_dir_y, player.aim_dir_x)
        if player.spread_heat > 0.0:
            theta += (float(state.rng.rand()) / 32767.0 * 2.0 - 1.0) * player.spread_heat
        angle = theta + math.pi / 2.0
        muzzle_x = player.pos_x + player.aim_dir_x * 16.0
        muzzle_y = player.pos_y + player.aim_dir_y * 16.0
        if player.fire_bullets_timer > 0.0:
            count = max(1, pellet_count)
            meta = _projectile_meta_for_type_id(FIRE_BULLETS_PROJECTILE_TYPE_ID)
            for _ in range(count):
                jitter = (float(state.rng.rand() % 200) - 100.0) * 0.0015
                state.projectiles.spawn(
                    pos_x=muzzle_x,
                    pos_y=muzzle_y,
                    angle=angle + jitter,
                    type_id=FIRE_BULLETS_PROJECTILE_TYPE_ID,
                    owner_id=_owner_id_for_player(player.index),
                    base_damage=meta,
                )
        else:
            # Most main-projectile weapons map `weapon_id -> projectile_type_id` in the rewrite.
            type_id = int(player.weapon_id)
            state.projectiles.spawn(
                pos_x=muzzle_x,
                pos_y=muzzle_y,
                angle=angle,
                type_id=type_id,
                owner_id=_owner_id_for_player(player.index),
                base_damage=_projectile_meta_for_type_id(type_id),
            )

    player.muzzle_flash_alpha = min(1.0, player.muzzle_flash_alpha + 0.8)

    player.ammo = max(0, player.ammo - 1)
    if player.ammo <= 0:
        player_start_reload(player, state)


def player_update(player: PlayerState, input_state: PlayerInput, dt: float, state: GameplayState, *, world_size: float = 1024.0) -> None:
    """Port of `player_update` (0x004136b0) for the rewrite runtime."""

    if dt <= 0.0:
        return

    prev_x = player.pos_x
    prev_y = player.pos_y

    player.muzzle_flash_alpha = max(0.0, player.muzzle_flash_alpha - dt * 2.0)
    cooldown_decay = dt * (1.5 if state.bonuses.weapon_power_up > 0.0 else 1.0)
    player.shot_cooldown = max(0.0, player.shot_cooldown - cooldown_decay)

    if perk_active(player, PerkId.SHARPSHOOTER):
        player.spread_heat = max(0.02, player.spread_heat - dt * 2.0)
    else:
        player.spread_heat = max(0.01, player.spread_heat - dt * 0.4)

    player.shield_timer = max(0.0, player.shield_timer - dt)
    player.fire_bullets_timer = max(0.0, player.fire_bullets_timer - dt)
    player.speed_bonus_timer = max(0.0, player.speed_bonus_timer - dt)

    # Aim: compute direction from (player -> aim point).
    aim_dx = input_state.aim_x - player.pos_x
    aim_dy = input_state.aim_y - player.pos_y
    aim_dir_x, aim_dir_y = _normalize(aim_dx, aim_dy)
    if aim_dir_x != 0.0 or aim_dir_y != 0.0:
        player.aim_dir_x = aim_dir_x
        player.aim_dir_y = aim_dir_y
        player.aim_heading = math.atan2(aim_dir_y, aim_dir_x) + math.pi / 2.0

    # Movement.
    move_x, move_y = _normalize(float(input_state.move_x), float(input_state.move_y))
    speed = 120.0 * player.move_speed_multiplier
    if player.speed_bonus_timer > 0.0:
        speed *= 1.35
    player.pos_x = _clamp(player.pos_x + move_x * speed * dt, 0.0, float(world_size))
    player.pos_y = _clamp(player.pos_y + move_y * speed * dt, 0.0, float(world_size))

    stationary = abs(player.pos_x - prev_x) <= 1e-9 and abs(player.pos_y - prev_y) <= 1e-9
    reload_scale = 1.0
    if stationary and perk_active(player, PerkId.STATIONARY_RELOADER):
        reload_scale = 3.0

    if stationary and perk_active(player, PerkId.MAN_BOMB):
        _perk_update_man_bomb(player, dt, state)
    else:
        player.man_bomb_timer = 0.0

    if stationary and perk_active(player, PerkId.LIVING_FORTRESS):
        player.living_fortress_timer = min(30.0, player.living_fortress_timer + dt)
    else:
        player.living_fortress_timer = 0.0

    if perk_active(player, PerkId.FIRE_CAUGH):
        _perk_update_fire_cough(player, dt, state)
    else:
        player.fire_cough_timer = 0.0

    if perk_active(player, PerkId.HOT_TEMPERED):
        _perk_update_hot_tempered(player, dt, state)
    else:
        player.hot_tempered_timer = 0.0

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
                    type_id=0x0A,
                    owner_id=_owner_id_for_player(player.index),
                )
                state.bonus_spawn_guard = False
        else:
            player.reload_timer -= reload_scale * dt

    if player.reload_timer < 0.0:
        player.reload_timer = 0.0

    if player.reload_active and player.reload_timer <= 0.0 and player.reload_timer_max > 0.0:
        player.ammo = player.clip_size
        player.reload_active = False
        player.reload_timer_max = 0.0

    if input_state.reload_pressed:
        if perk_active(player, PerkId.ALTERNATE_WEAPON) and player_swap_alt_weapon(player):
            pass
        elif player.reload_timer == 0.0:
            player_start_reload(player, state)

    player_fire_weapon(player, input_state, dt, state)


def bonus_apply(
    state: GameplayState,
    player: PlayerState,
    bonus_id: BonusId,
    *,
    amount: int | None = None,
    origin: _HasPos | None = None,
    creatures: list[Damageable] | None = None,
) -> None:
    """Apply a bonus to player + global timers (subset of `bonus_apply`)."""

    meta = BONUS_BY_ID.get(int(bonus_id))
    if meta is None:
        return
    if amount is None:
        amount = int(meta.default_amount or 0)

    if bonus_id == BonusId.POINTS:
        award_experience(state, player, int(amount))
        return

    if bonus_id == BonusId.ENERGIZER:
        state.bonuses.energizer = max(state.bonuses.energizer, float(amount))
    elif bonus_id == BonusId.WEAPON_POWER_UP:
        state.bonuses.weapon_power_up = max(state.bonuses.weapon_power_up, float(amount))
    elif bonus_id == BonusId.DOUBLE_EXPERIENCE:
        state.bonuses.double_experience = max(state.bonuses.double_experience, float(amount))
    elif bonus_id == BonusId.REFLEX_BOOST:
        state.bonuses.reflex_boost = max(state.bonuses.reflex_boost, float(amount))
    elif bonus_id == BonusId.FREEZE:
        state.bonuses.freeze = max(state.bonuses.freeze, float(amount))
    elif bonus_id == BonusId.SHIELD:
        player.shield_timer = max(player.shield_timer, float(amount))
    elif bonus_id == BonusId.SPEED:
        player.speed_bonus_timer = max(player.speed_bonus_timer, float(amount))
    elif bonus_id == BonusId.FIRE_BULLETS:
        player.fire_bullets_timer = max(player.fire_bullets_timer, float(amount))
    elif bonus_id == BonusId.SHOCK_CHAIN:
        if creatures:
            origin_pos = origin or player
            best_idx: int | None = None
            best_dist = 0.0
            for idx, creature in enumerate(creatures):
                if creature.hp <= 0.0:
                    continue
                d = _distance_sq(float(origin_pos.pos_x), float(origin_pos.pos_y), creature.x, creature.y)
                if best_idx is None or d < best_dist:
                    best_idx = idx
                    best_dist = d
            if best_idx is not None:
                target = creatures[best_idx]
                dx = target.x - float(origin_pos.pos_x)
                dy = target.y - float(origin_pos.pos_y)
                angle = math.atan2(dy, dx) + math.pi / 2.0
                state.bonus_spawn_guard = True
                state.shock_chain_links_left = 0x20
                state.shock_chain_projectile_id = state.projectiles.spawn(
                    pos_x=float(origin_pos.pos_x),
                    pos_y=float(origin_pos.pos_y),
                    angle=angle,
                    type_id=0x14,
                    owner_id=_owner_id_for_player(player.index),
                    base_damage=_projectile_meta_for_type_id(0x14),
                )
                state.bonus_spawn_guard = False
        return
    elif bonus_id == BonusId.WEAPON:
        weapon_assign_player(player, int(amount))
        return
    elif bonus_id == BonusId.FIREBLAST:
        origin_pos = origin or player
        state.bonus_spawn_guard = True
        _spawn_projectile_ring(
            state,
            origin_pos,
            count=16,
            angle_offset=0.0,
            type_id=8,
            owner_id=_owner_id_for_player(player.index),
        )
        state.bonus_spawn_guard = False
        return
    else:
        # Bonus types not modeled yet: nuke, shock chain, etc.
        return

    # Register timed bonuses in the HUD.
    icon_id = int(meta.icon_id) if meta.icon_id is not None else -1
    label = meta.name
    if bonus_id in (BonusId.SHIELD, BonusId.SPEED, BonusId.FIRE_BULLETS):
        timer_key = {
            BonusId.SHIELD: "shield_timer",
            BonusId.SPEED: "speed_bonus_timer",
            BonusId.FIRE_BULLETS: "fire_bullets_timer",
        }[bonus_id]
        state.bonus_hud.register(
            bonus_id,
            label=label,
            icon_id=icon_id,
            timer_ref=_TimerRef("player", timer_key, player_index=player.index),
        )
        return

    timer_key = {
        BonusId.ENERGIZER: "energizer",
        BonusId.WEAPON_POWER_UP: "weapon_power_up",
        BonusId.DOUBLE_EXPERIENCE: "double_experience",
        BonusId.REFLEX_BOOST: "reflex_boost",
        BonusId.FREEZE: "freeze",
    }.get(bonus_id)
    if timer_key is None:
        return
    state.bonus_hud.register(
        bonus_id,
        label=label,
        icon_id=icon_id,
        timer_ref=_TimerRef("global", timer_key),
    )


def bonus_hud_update(state: GameplayState, players: list[PlayerState]) -> None:
    """Refresh HUD slots based on current timer values."""

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

    for slot in state.bonus_hud.slots:
        if not slot.active:
            continue
        timer = _timer_value(slot.timer_ref)
        if slot.timer_ref_alt is not None:
            timer = max(timer, _timer_value(slot.timer_ref_alt))
        if timer <= 0.0:
            slot.active = False
            slot.timer_ref = None
            slot.timer_ref_alt = None


def bonus_update(
    state: GameplayState,
    players: list[PlayerState],
    dt: float,
    *,
    update_hud: bool = True,
) -> list[BonusPickupEvent]:
    """Advance world bonuses and global timers (subset of `bonus_update`)."""

    pickups = state.bonus_pool.update(dt, state=state, players=players)

    if dt > 0.0:
        state.bonuses.weapon_power_up = max(0.0, state.bonuses.weapon_power_up - dt)
        state.bonuses.reflex_boost = max(0.0, state.bonuses.reflex_boost - dt)
        state.bonuses.energizer = max(0.0, state.bonuses.energizer - dt)
        state.bonuses.double_experience = max(0.0, state.bonuses.double_experience - dt)
        state.bonuses.freeze = max(0.0, state.bonuses.freeze - dt)

    if update_hud:
        bonus_hud_update(state, players)

    return pickups
