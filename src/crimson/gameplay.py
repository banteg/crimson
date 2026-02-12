from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import TYPE_CHECKING, Callable, Protocol, Sequence

from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand
from .bonuses.freeze import DeferredFreezeCorpseFx
from .bonuses.hud import BonusHudState
from .bonuses.pool import BonusPool
from .effects import EffectPool, ParticlePool, SpriteEffectPool
from .game_modes import GameMode
from .math_parity import f32
from .perks import PerkId
from .perks.helpers import perk_active
from .perks.runtime.player_ticks import apply_player_perk_ticks
from .perks.selection import perk_auto_pick
from .perks.state import CreatureForPerks, PerkEffectIntervals, PerkSelectionState
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


WEAPON_COUNT_SIZE = max(int(entry.weapon_id) for entry in WEAPON_TABLE) + 1


@dataclass(slots=True)
class BonusTimers:
    weapon_power_up: float = 0.0
    reflex_boost: float = 0.0
    energizer: float = 0.0
    double_experience: float = 0.0
    freeze: float = 0.0


WEAPON_DROP_ID_COUNT = 0x21  # weapon ids 1..33
_RELOAD_PRELOAD_UNDERFLOW_EPS = 1e-7


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
    survival_reward_weapon_guard_id: int = int(WeaponId.PISTOL)
    survival_reward_handout_enabled: bool = True
    survival_reward_fire_seen: bool = False
    survival_reward_damage_seen: bool = False
    survival_recent_death_pos: list[Vec2] = field(default_factory=lambda: [Vec2(), Vec2(), Vec2()])
    survival_recent_death_count: int = 0
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


def award_experience(state: GameplayState, player: PlayerState, amount: int) -> int:
    """Grant XP while honoring active bonus multipliers."""

    xp = int(amount)
    if xp <= 0:
        return 0
    if state.bonuses.double_experience > 0.0:
        xp *= 2
    player.experience += xp
    return xp


def _award_experience_once_from_reward(player: PlayerState, reward_value: float) -> int:
    """Mirror native `__ftol(player_xp + reward_value)` accumulation for one award."""

    reward_f32 = f32(float(reward_value))
    if float(reward_f32) <= 0.0:
        return 0

    before = int(player.experience)
    total_f32 = f32(f32(float(before)) + float(reward_f32))
    after = int(float(total_f32))
    player.experience = int(after)
    return int(after - before)


def award_experience_from_reward(state: GameplayState, player: PlayerState, reward_value: float) -> int:
    """Grant kill XP from floating reward values with native float32 store semantics."""

    gained = _award_experience_once_from_reward(player, float(reward_value))
    if gained <= 0:
        return 0
    if state.bonuses.double_experience > 0.0:
        gained += _award_experience_once_from_reward(player, float(reward_value))
    return int(gained)


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


def survival_progression_update(
    state: GameplayState,
    players: list[PlayerState],
    *,
    game_mode: int,
    player_count: int | None = None,
    auto_pick: bool = True,
    dt: float | None = None,
    creatures: Sequence[CreatureForPerks] | None = None,
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


_SURVIVAL_RECENT_DEATH_CENTROID_SCALE = 0.33333334


def survival_record_recent_death(state: GameplayState, *, pos: Vec2) -> None:
    """Track Survival recent-death samples used by one-off weapon handout gating."""

    recent_count = int(state.survival_recent_death_count)
    if recent_count >= 6:
        return

    if recent_count < 3:
        state.survival_recent_death_pos[recent_count] = Vec2(
            f32(float(pos.x)),
            f32(float(pos.y)),
        )

    recent_count += 1
    state.survival_recent_death_count = int(recent_count)
    if recent_count == 3:
        state.survival_reward_fire_seen = False
        state.survival_reward_handout_enabled = False


def survival_update_weapon_handouts(
    state: GameplayState,
    players: list[PlayerState],
    *,
    survival_elapsed_ms: float,
) -> None:
    """Apply native `survival_update` one-off Survival weapon handout checks."""

    if len(players) != 1:
        return
    player = players[0]

    if (
        (not bool(state.survival_reward_damage_seen))
        and (not bool(state.survival_reward_fire_seen))
        and int(float(survival_elapsed_ms)) > 64000
        and bool(state.survival_reward_handout_enabled)
    ):
        if int(player.weapon_id) == int(WeaponId.PISTOL):
            weapon_assign_player(player, int(WeaponId.SHRINKIFIER_5K), state=state)
            state.survival_reward_weapon_guard_id = int(WeaponId.SHRINKIFIER_5K)
        state.survival_reward_handout_enabled = False
        state.survival_reward_damage_seen = True
        state.survival_reward_fire_seen = True

    if int(state.survival_recent_death_count) == 3 and (not bool(state.survival_reward_fire_seen)):
        pos0, pos1, pos2 = state.survival_recent_death_pos
        centroid_x = f32(float(f32(float(pos0.x) + float(pos1.x) + float(pos2.x))) * _SURVIVAL_RECENT_DEATH_CENTROID_SCALE)
        centroid_y = f32(float(f32(float(pos0.y) + float(pos1.y) + float(pos2.y))) * _SURVIVAL_RECENT_DEATH_CENTROID_SCALE)
        dx = float(player.pos.x) - float(centroid_x)
        dy = float(player.pos.y) - float(centroid_y)
        if math.sqrt(dx * dx + dy * dy) < 16.0 and float(player.health) < 15.0:
            weapon_assign_player(player, int(WeaponId.BLADE_GUN), state=state)
            state.survival_reward_weapon_guard_id = int(WeaponId.BLADE_GUN)
            state.survival_reward_fire_seen = True
            state.survival_reward_handout_enabled = False


def survival_enforce_reward_weapon_guard(state: GameplayState, players: Sequence[PlayerState]) -> None:
    """Revoke temporary Survival handout weapons when guard id mismatches."""

    guard_id = int(state.survival_reward_weapon_guard_id)
    for player in players:
        weapon_id = int(player.weapon_id)
        if weapon_id == int(WeaponId.BLADE_GUN) and guard_id != int(WeaponId.BLADE_GUN):
            weapon_assign_player(player, int(WeaponId.PISTOL))
        if weapon_id == int(WeaponId.SHRINKIFIER_5K) and guard_id != int(WeaponId.SHRINKIFIER_5K):
            weapon_assign_player(player, int(WeaponId.PISTOL))


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

    ammo_cost = 1.0
    is_fire_bullets = float(player.fire_bullets_timer) > 0.0
    if player.reload_timer > 0.0:
        if player.experience <= 0:
            return
        if perk_active(player, PerkId.REGRESSION_BULLETS):
            ammo_class = int(weapon.ammo_class) if weapon.ammo_class is not None else 0

            reload_time = float(weapon.reload_time) if weapon.reload_time is not None else 0.0
            factor = 4.0 if ammo_class == 1 else 200.0
            player.experience = int(float(player.experience) - reload_time * factor)
            if player.experience < 0:
                player.experience = 0
        elif perk_active(player, PerkId.AMMUNITION_WITHIN):
            ammo_class = int(weapon.ammo_class) if weapon.ammo_class is not None else 0

            from .player_damage import player_take_damage

            cost = 0.15 if ammo_class == 1 else 1.0
            player_take_damage(state, player, cost, dt=dt, rand=state.rng.rand)
        else:
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

    apply_player_perk_ticks(
        player=player,
        dt=dt,
        state=state,
        players=players,
        stationary=stationary,
        owner_id_for_player=_owner_id_for_player,
        owner_id_for_player_projectiles=_owner_id_for_player_projectiles,
        projectile_spawn=_projectile_spawn,
    )

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
    reload_preload_underflow = float(f32(reload_timer_now - dt_f32))
    if (
        player.reload_active
        and reload_timer_now > 0.0
        and reload_preload_underflow < -_RELOAD_PRELOAD_UNDERFLOW_EPS
    ):
        player.ammo = float(player.clip_size)

    reload_timer_started = float(player.reload_timer)
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

    if (
        player.reload_active
        and reload_timer_started <= 0.0
        and player.reload_timer == 0.0
        and player.ammo <= 0.0
        and input_state.fire_down
    ):
        player.ammo = float(player.clip_size)

    # Native clears `reload_active` only once the player can shoot again.
    if player.shot_cooldown <= 0.0 and player.reload_timer == 0.0 and player.ammo > 0.0:
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
        elif player.reload_timer == 0.0 and not input_state.move_to_cursor_pressed:
            player_start_reload(player, state)

    if input_state.fire_down:
        state.survival_reward_fire_seen = True

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
