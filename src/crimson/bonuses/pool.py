from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2

from ..creatures.damage_runtime import CreatureDamageRuntime
from ..game_modes import GameMode
from ..math_parity import f32, x87_pc24_hypot, x87_pc24_sub
from ..perks.helpers import perk_active
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import BonusPickupEvent, GameplayState, PlayerState
from ..weapon_runtime.availability import weapon_pick_random_available
from ..weapons import WEAPON_BY_ID, WeaponId, weapon_display_name
from .apply import bonus_apply
from .ids import BONUS_BY_ID, BonusId, bonus_display_name
from .selection import bonus_pick_random_type

if TYPE_CHECKING:
    from ..creatures.runtime import CreatureState

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


class BonusEntry(msgspec.Struct):
    bonus_id: BonusId = BonusId.UNUSED
    picked: bool = False
    time_left: float = 0.0
    time_max: float = 0.0
    pos: Vec2 = Vec2()
    amount: int = 0


def _bonus_entry_is_empty(entry: BonusEntry) -> bool:
    return (
        entry.bonus_id == BonusId.UNUSED
        and not entry.picked
        and float(entry.time_left) <= 0.0
        and float(entry.time_max) <= 0.0
        and int(entry.amount) == 0
    )


def _weapon_id_from_native_amount(amount: int) -> WeaponId | None:
    # Keep native amount-domain behavior: any raw bonus amount that happens to
    # match a weapon id can trip suppression checks under `--preserve-bugs`.
    weapon_id = int(amount)
    if weapon_id not in WEAPON_BY_ID:
        return None
    return WeaponId(weapon_id)


def _weapon_id_from_weapon_entry(entry: BonusEntry) -> WeaponId | None:
    if entry.bonus_id != BonusId.WEAPON:
        return None
    return _weapon_id_from_native_amount(entry.amount)


def _all_carried_weapon_ids(players: Sequence[PlayerState]) -> set[WeaponId]:
    carried: set[WeaponId] = set()
    for player in players:
        weapon_id = player.weapon.weapon_id
        if weapon_id > WeaponId.NONE:
            carried.add(weapon_id)
        if player.alt_weapon is None:
            continue
        alt = player.alt_weapon.weapon_id
        if alt > WeaponId.NONE:
            carried.add(alt)
    return carried


def _within_native_radius(a: Vec2, b: Vec2, radius: float) -> bool:
    return x87_pc24_hypot(
        x87_pc24_sub(a.x, b.x),
        x87_pc24_sub(a.y, b.y),
    ) < radius


class BonusPool:
    def __init__(self, *, size: int = BONUS_POOL_SIZE) -> None:
        self._entries = [BonusEntry() for _ in range(int(size))]
        # Native bonus code uses a writable sentinel entry when allocation/spacing
        # checks fail. Some callers still mutate it, which affects RNG consumption.
        self._sentinel = BonusEntry()

    @property
    def entries(self) -> list[BonusEntry]:
        return self._entries

    def reset(self) -> None:
        for entry in self._entries:
            entry.bonus_id = BonusId.UNUSED
            entry.picked = False
            entry.time_left = 0.0
            entry.time_max = 0.0
            entry.amount = 0

    def iter_active(self) -> list[BonusEntry]:
        return [entry for entry in self._entries if entry.bonus_id != BonusId.UNUSED]

    def _alloc_slot(self) -> BonusEntry | None:
        # Native bonus_alloc_slot checks only `bonus_id == NONE`, so a slot
        # whose bonus expired and was then picked (linger with UNUSED id) is
        # immediately reusable.
        for entry in self._entries:
            if entry.bonus_id == BonusId.UNUSED:
                return entry
        return None

    def _alloc_slot_or_sentinel(self) -> BonusEntry:
        entry = self._alloc_slot()
        if entry is not None:
            return entry
        return self._sentinel

    def _is_sentinel_entry(self, entry: BonusEntry) -> bool:
        return entry is self._sentinel

    def _clear_entry(self, entry: BonusEntry) -> None:
        entry.bonus_id = BonusId.UNUSED
        entry.picked = False
        entry.time_left = 0.0
        entry.time_max = 0.0
        entry.amount = 0

    def spawn_at(
        self,
        pos: Vec2,
        bonus_id: BonusId,
        duration_override: int = -1,
        *,
        state: GameplayState,
        world_width: float = 1024.0,
        world_height: float = 1024.0,
        detail_preset: int = 5,
        emit_burst: bool = True,
    ) -> BonusEntry | None:
        clamped_pos = pos.clamp_rect(
            BONUS_SPAWN_MARGIN,
            BONUS_SPAWN_MARGIN,
            float(world_width) - BONUS_SPAWN_MARGIN,
            float(world_height) - BONUS_SPAWN_MARGIN,
        )
        if state.game_mode == GameMode.RUSH:
            return None
        entry = self._alloc_slot_or_sentinel()

        entry.bonus_id = bonus_id
        entry.picked = False
        entry.pos = clamped_pos
        entry.time_left = BONUS_TIME_MAX
        entry.time_max = BONUS_TIME_MAX

        amount = duration_override
        if amount == -1:
            meta = BONUS_BY_ID.get(bonus_id)
            amount = int(meta.native_amount or 0) if meta is not None else 0
        entry.amount = int(amount)

        if emit_burst:
            # Native `bonus_spawn_at` always spawns a 16-particle burst
            # (4 crt_rand draws each). The tutorial writes the pool directly
            # in native code and emits its own 12-particle burst instead.
            state.effects.spawn_burst(
                pos=entry.pos,
                count=16,
                rng=state.rng,
                detail_preset=int(detail_preset),
                rotation_caller=RngCallerStatic.BONUS_SPAWN_AT_BURST_ROTATION,
                vel_x_caller=RngCallerStatic.BONUS_SPAWN_AT_BURST_VEL_X,
                vel_y_caller=RngCallerStatic.BONUS_SPAWN_AT_BURST_VEL_Y,
                scale_step_caller=RngCallerStatic.BONUS_SPAWN_AT_BURST_SCALE_STEP,
            )
        return None if self._is_sentinel_entry(entry) else entry

    def spawn_at_pos(
        self,
        pos: Vec2,
        *,
        state: GameplayState,
        players: list[PlayerState],
        world_width: float = 1024.0,
        world_height: float = 1024.0,
    ) -> BonusEntry:
        if state.game_mode == GameMode.RUSH:
            return self._sentinel
        if (
            pos.x < BONUS_SPAWN_MARGIN
            or pos.y < BONUS_SPAWN_MARGIN
            or pos.x > world_width - BONUS_SPAWN_MARGIN
            or pos.y > world_height - BONUS_SPAWN_MARGIN
        ):
            return self._sentinel

        entry = self._alloc_slot_or_sentinel()

        bonus_id = bonus_pick_random_type(self, state, players)
        for active_entry in self._entries:
            if active_entry.bonus_id == BonusId.UNUSED:
                continue
            distance = x87_pc24_hypot(
                x87_pc24_sub(pos.x, active_entry.pos.x),
                x87_pc24_sub(pos.y, active_entry.pos.y),
            )
            if distance < BONUS_SPAWN_MIN_DISTANCE:
                entry = self._sentinel
                break

        entry.bonus_id = bonus_id
        entry.picked = False
        entry.pos = pos
        entry.time_left = BONUS_TIME_MAX
        entry.time_max = BONUS_TIME_MAX

        rng = state.rng
        if entry.bonus_id == BonusId.WEAPON:
            entry.amount = int(weapon_pick_random_available(state))
        elif entry.bonus_id == BonusId.POINTS:
            entry.amount = 1000 if (rng.rand_tagged(RngCallerStatic.BONUS_SPAWN_AT_POS_POINTS_AMOUNT) & 7) < 3 else 500
        else:
            meta = BONUS_BY_ID.get(entry.bonus_id)
            entry.amount = int(meta.native_amount or 0) if meta is not None else 0
        return entry

    def try_spawn_on_kill(
        self,
        pos: Vec2,
        *,
        state: GameplayState,
        players: list[PlayerState],
        detail_preset: int = 5,
        world_width: float = 1024.0,
        world_height: float = 1024.0,
    ) -> BonusEntry | None:
        from ..perks import PerkId

        game_mode = state.game_mode
        if game_mode == GameMode.TYPO:
            return None
        if state.demo_mode_active:
            return None
        if game_mode == GameMode.RUSH:
            return None
        if game_mode == GameMode.TUTORIAL:
            return None
        if state.bonus_spawn_guard:
            return None

        rng = state.rng
        # Native special-case: while any player has Pistol, 3/4 chance to force a Weapon drop.
        if players and any(player.weapon.weapon_id == WeaponId.PISTOL for player in players):
            if (rng.rand_tagged(RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_PISTOL_FORCE_WEAPON) & 3) < 3:
                entry = self.spawn_at_pos(
                    pos,
                    state=state,
                    players=players,
                    world_width=world_width,
                    world_height=world_height,
                )

                entry.bonus_id = BonusId.WEAPON
                weapon_id = weapon_pick_random_available(state)
                entry.amount = int(weapon_id)
                if weapon_id == WeaponId.PISTOL:
                    weapon_id = weapon_pick_random_available(state)
                    entry.amount = int(weapon_id)

                matches = sum(1 for bonus in self._entries if bonus.bonus_id == entry.bonus_id)
                if matches > 1:
                    self._clear_entry(entry)
                    return None

                if entry.amount == WeaponId.PISTOL or (
                    players and perk_active(players[0], PerkId.MY_FAVOURITE_WEAPON)
                ):
                    self._clear_entry(entry)
                    return None

                if self._is_sentinel_entry(entry):
                    return None
                self._spawn_on_kill_burst(entry=entry, state=state, detail_preset=detail_preset)
                return entry

        base_roll = rng.rand_tagged(RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BASE_GATE)
        if base_roll % 9 != 1:
            allow_without_magnet = False
            if players:
                has_pistol = False
                if bool(state.preserve_bugs):
                    has_pistol = players[0].weapon.weapon_id == WeaponId.PISTOL
                else:
                    has_pistol = any(player.weapon.weapon_id == WeaponId.PISTOL for player in players)
                if has_pistol:
                    allow_without_magnet = (
                        rng.rand_tagged(RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_PISTOL_ALLOW_WITHOUT_MAGNET)
                        % 5
                        == 1
                    )

            if not allow_without_magnet:
                has_bonus_magnet = False
                if players:
                    if bool(state.preserve_bugs):
                        has_bonus_magnet = perk_active(players[0], PerkId.BONUS_MAGNET)
                    else:
                        has_bonus_magnet = any(perk_active(player, PerkId.BONUS_MAGNET) for player in players)
                if not has_bonus_magnet:
                    return None
                if rng.rand_tagged(RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BONUS_MAGNET) % 10 != 2:
                    return None

        entry = self.spawn_at_pos(
            pos,
            state=state,
            players=players,
            world_width=world_width,
            world_height=world_height,
        )

        if entry.bonus_id == BonusId.WEAPON:
            near_player = False
            if players:
                if bool(state.preserve_bugs):
                    # Native checks player 1 position only.
                    near_player = _within_native_radius(pos, players[0].pos, BONUS_WEAPON_NEAR_RADIUS)
                else:
                    near_player = any(
                        _within_native_radius(pos, player.pos, BONUS_WEAPON_NEAR_RADIUS) for player in players
                    )
            if near_player:
                entry.bonus_id = BonusId.POINTS
                entry.amount = 100

        if entry.bonus_id != BonusId.POINTS:
            matches = sum(1 for bonus in self._entries if bonus.bonus_id == entry.bonus_id)
            if matches > 1:
                self._clear_entry(entry)
                return None

        if players:
            if bool(state.preserve_bugs):
                weapon_id = players[0].weapon.weapon_id
                suppression_weapon_id = _weapon_id_from_native_amount(entry.amount)
                if suppression_weapon_id == weapon_id:
                    self._clear_entry(entry)
                    return None
            else:
                carried_weapon_ids = _all_carried_weapon_ids(players)
                bonus_weapon_id = _weapon_id_from_weapon_entry(entry)
                if entry.bonus_id == BonusId.WEAPON and bonus_weapon_id in carried_weapon_ids:
                    self._clear_entry(entry)
                    return None

        if self._is_sentinel_entry(entry):
            return None
        self._spawn_on_kill_burst(entry=entry, state=state, detail_preset=detail_preset)
        return entry

    def _spawn_on_kill_burst(self, *, entry: BonusEntry, state: GameplayState, detail_preset: int) -> None:
        rng = state.rng
        for _ in range(16):
            state.effects.spawn_burst_particle(
                pos=entry.pos,
                rotation_draw=rng.rand_tagged(RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BURST_ROTATION),
                vel_x_draw=rng.rand_tagged(RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BURST_VEL_X),
                vel_y_draw=rng.rand_tagged(RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BURST_VEL_Y),
                scale_step_draw=rng.rand_tagged(RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BURST_SCALE_STEP),
                detail_preset=detail_preset,
            )

    def update(
        self,
        dt: float,
        *,
        state: GameplayState,
        players: list[PlayerState],
        creatures: Sequence[CreatureState],
        detail_preset: int = 5,
        defer_freeze_corpse_fx: bool = False,
        freeze_corpse_indices: set[int] | None = None,
        creature_damage_runtime: CreatureDamageRuntime | None = None,
    ) -> list[BonusPickupEvent]:
        if dt <= 0.0:
            return []

        pickups: list[BonusPickupEvent] = []
        for entry in self._entries:
            if _bonus_entry_is_empty(entry):
                continue

            decay = f32(float(f32(dt)) * (BONUS_PICKUP_DECAY_RATE if entry.picked else 1.0))
            entry.time_left = f32(float(f32(entry.time_left)) - float(decay))
            if not entry.picked and state.game_mode == GameMode.TUTORIAL:
                entry.time_left = 5.0
            expired_to_unused = False
            if entry.time_left < 0.0:
                if entry.picked:
                    self._clear_entry(entry)
                    continue
                # Native `bonus_update` sets bonus_id to NONE before pickup checks
                # and still allows one final in-range pickup in that tick.
                entry.bonus_id = BonusId.UNUSED
                expired_to_unused = True

            if entry.picked:
                continue

            # Native's player loop has no break: every player inside the
            # pickup radius applies the bonus this tick (a nuke detonates
            # twice, both players gain shield, and both consume RNG).
            picked_now = False
            for player in players:
                if Vec2.distance_sq(entry.pos, player.pos) < BONUS_PICKUP_RADIUS * BONUS_PICKUP_RADIUS:
                    bonus_apply(
                        state,
                        player,
                        entry.bonus_id,
                        amount=entry.amount,
                        origin=entry.pos,
                        creatures=creatures,
                        players=players,
                        detail_preset=int(detail_preset),
                        defer_freeze_corpse_fx=bool(defer_freeze_corpse_fx),
                        freeze_corpse_indices=freeze_corpse_indices,
                        creature_damage_runtime=creature_damage_runtime,
                    )
                    entry.picked = True
                    entry.time_left = BONUS_PICKUP_LINGER
                    pickups.append(
                        BonusPickupEvent(
                            player_index=player.index,
                            bonus_id=entry.bonus_id,
                            amount=entry.amount,
                            pos=entry.pos,
                        ),
                    )
                    picked_now = True

            if expired_to_unused and not picked_now:
                self._clear_entry(entry)

        return pickups


def bonus_find_aim_hover_entry(player: PlayerState, bonus_pool: BonusPool) -> tuple[int, BonusEntry] | None:
    """Return the first bonus entry within the aim hover radius, matching the exe scan order."""

    aim_pos = player.aim
    radius_sq = BONUS_AIM_HOVER_RADIUS * BONUS_AIM_HOVER_RADIUS
    for idx, entry in enumerate(bonus_pool.entries):
        if entry.bonus_id == BonusId.UNUSED:
            continue
        if Vec2.distance_sq(aim_pos, entry.pos) < radius_sq:
            return idx, entry
    return None


def bonus_label_for_entry(entry: BonusEntry, *, preserve_bugs: bool = False) -> str:
    """Return the classic label text for a bonus entry (`bonus_label_for_entry`)."""

    bonus_id = entry.bonus_id
    if bonus_id == BonusId.WEAPON:
        weapon_id = _weapon_id_from_weapon_entry(entry)
        if weapon_id is None:
            return "Weapon"
        return weapon_display_name(weapon_id, preserve_bugs=bool(preserve_bugs))
    if bonus_id == BonusId.POINTS:
        points = int(entry.amount)
        points_label = bonus_display_name(BonusId.POINTS, preserve_bugs=bool(preserve_bugs))
        return f"{points_label}: {points}"
    meta = BONUS_BY_ID.get(bonus_id)
    if meta is not None:
        return bonus_display_name(meta.bonus_id, preserve_bugs=bool(preserve_bugs))
    return "Bonus"
