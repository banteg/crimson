from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from grim.geom import Vec2

from ..game_modes import GameMode
from ..perks.helpers import perk_active
from ..projectiles import CreatureDamageApplier, Damageable
from ..sim.state_types import BonusPickupEvent, GameplayState, PlayerState
from ..weapon_runtime.availability import weapon_pick_random_available
from ..weapons import WEAPON_BY_ID, WeaponId, weapon_display_name
from .apply import bonus_apply
from .ids import BONUS_BY_ID, BonusId, bonus_display_name
from .selection import bonus_pick_random_type

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


@dataclass(slots=True)
class BonusEntry:
    bonus_id: int = 0
    picked: bool = False
    time_left: float = 0.0
    time_max: float = 0.0
    pos: Vec2 = field(default_factory=Vec2)
    amount: int = 0


def _bonus_entry_is_empty(entry: BonusEntry) -> bool:
    return (
        int(entry.bonus_id) == 0
        and not bool(entry.picked)
        and float(entry.time_left) <= 0.0
        and float(entry.time_max) <= 0.0
        and int(entry.amount) == 0
    )


# Native `bonus_try_spawn_on_kill` uses the bonus entry `amount` field for a weird
# suppression check: it clears the spawned entry when `amount == player1.weapon_id`
# regardless of bonus type. In the rewrite, `amount` is used as the "effective"
# duration/value for some bonuses, so `--preserve-bugs` compares against the
# native amount domain (see docs/rewrite/original-bugs.md).
_BONUS_NATIVE_AMOUNT_WEAPON_ID_SUPPRESSION: dict[int, int] = {
    # Native default amount stored for Double Experience drops is 1.
    int(BonusId.DOUBLE_EXPERIENCE): 1,
    int(BonusId.FIRE_BULLETS): 4,
}


def _bonus_amount_for_weapon_id_suppression(*, bonus_id: int, amount: int) -> int:
    return int(_BONUS_NATIVE_AMOUNT_WEAPON_ID_SUPPRESSION.get(int(bonus_id), int(amount)))


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
            entry.bonus_id = 0
            entry.picked = False
            entry.time_left = 0.0
            entry.time_max = 0.0
            entry.amount = 0

    def iter_active(self) -> list[BonusEntry]:
        return [entry for entry in self._entries if entry.bonus_id != 0]

    def _alloc_slot(self) -> BonusEntry | None:
        for entry in self._entries:
            if _bonus_entry_is_empty(entry):
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
        entry.bonus_id = 0
        entry.picked = False
        entry.time_left = 0.0
        entry.time_max = 0.0
        entry.amount = 0

    def spawn_at(
        self,
        pos: Vec2,
        bonus_id: int | BonusId,
        duration_override: int = -1,
        *,
        state: GameplayState,
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

        entry.bonus_id = int(bonus_id)
        entry.picked = False
        entry.pos = pos.clamp_rect(
            BONUS_SPAWN_MARGIN,
            BONUS_SPAWN_MARGIN,
            float(world_width) - BONUS_SPAWN_MARGIN,
            float(world_height) - BONUS_SPAWN_MARGIN,
        )
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
        pos: Vec2,
        *,
        state: GameplayState,
        players: list[PlayerState],
        world_width: float = 1024.0,
        world_height: float = 1024.0,
    ) -> BonusEntry:
        if int(state.game_mode) == int(GameMode.RUSH):
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
        min_dist_sq = BONUS_SPAWN_MIN_DISTANCE * BONUS_SPAWN_MIN_DISTANCE
        for active_entry in self._entries:
            if active_entry.bonus_id == 0:
                continue
            if Vec2.distance_sq(pos, active_entry.pos) < min_dist_sq:
                entry = self._sentinel
                break

        entry.bonus_id = int(bonus_id)
        entry.picked = False
        entry.pos = pos
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
        pos: Vec2,
        *,
        state: GameplayState,
        players: list[PlayerState],
        world_width: float = 1024.0,
        world_height: float = 1024.0,
    ) -> BonusEntry | None:
        from ..perks import PerkId

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
                    pos,
                    state=state,
                    players=players,
                    world_width=world_width,
                    world_height=world_height,
                )

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

                if entry.amount == int(WeaponId.PISTOL) or (
                    players and perk_active(players[0], PerkId.MY_FAVOURITE_WEAPON)
                ):
                    self._clear_entry(entry)
                    return None

                if self._is_sentinel_entry(entry):
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
            pos,
            state=state,
            players=players,
            world_width=world_width,
            world_height=world_height,
        )

        if entry.bonus_id == int(BonusId.WEAPON):
            near_sq = BONUS_WEAPON_NEAR_RADIUS * BONUS_WEAPON_NEAR_RADIUS
            if players and Vec2.distance_sq(pos, players[0].pos) < near_sq:
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

        if self._is_sentinel_entry(entry):
            return None
        return entry

    def update(
        self,
        dt: float,
        *,
        state: GameplayState,
        players: list[PlayerState],
        creatures: Sequence[Damageable] | None = None,
        apply_creature_damage: CreatureDamageApplier | None = None,
        detail_preset: int = 5,
        defer_freeze_corpse_fx: bool = False,
        freeze_corpse_indices: set[int] | None = None,
    ) -> list[BonusPickupEvent]:
        if dt <= 0.0:
            return []

        pickups: list[BonusPickupEvent] = []
        for entry in self._entries:
            if _bonus_entry_is_empty(entry):
                continue

            decay = dt * (BONUS_PICKUP_DECAY_RATE if entry.picked else 1.0)
            entry.time_left -= decay
            if not entry.picked and int(state.game_mode) == int(GameMode.TUTORIAL):
                entry.time_left = 5.0
            expired_to_unused = False
            if entry.time_left < 0.0:
                if entry.picked:
                    self._clear_entry(entry)
                    continue
                # Native `bonus_update` sets bonus_id to NONE before pickup checks
                # and still allows one final in-range pickup in that tick.
                entry.bonus_id = int(BonusId.UNUSED)
                expired_to_unused = True

            if entry.picked:
                continue

            picked_now = False
            for player in players:
                if Vec2.distance_sq(entry.pos, player.pos) < BONUS_PICKUP_RADIUS * BONUS_PICKUP_RADIUS:
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
                        defer_freeze_corpse_fx=bool(defer_freeze_corpse_fx),
                        freeze_corpse_indices=freeze_corpse_indices,
                    )
                    entry.picked = True
                    entry.time_left = BONUS_PICKUP_LINGER
                    pickups.append(
                        BonusPickupEvent(
                            player_index=player.index,
                            bonus_id=entry.bonus_id,
                            amount=entry.amount,
                            pos=entry.pos,
                        )
                    )
                    picked_now = True
                    break

            if expired_to_unused and not picked_now:
                self._clear_entry(entry)

        return pickups


def bonus_find_aim_hover_entry(player: PlayerState, bonus_pool: BonusPool) -> tuple[int, BonusEntry] | None:
    """Return the first bonus entry within the aim hover radius, matching the exe scan order."""

    aim_pos = player.aim
    radius_sq = BONUS_AIM_HOVER_RADIUS * BONUS_AIM_HOVER_RADIUS
    for idx, entry in enumerate(bonus_pool.entries):
        if entry.bonus_id == 0:
            continue
        if Vec2.distance_sq(aim_pos, entry.pos) < radius_sq:
            return idx, entry
    return None


def bonus_label_for_entry(entry: BonusEntry, *, preserve_bugs: bool = False) -> str:
    """Return the classic label text for a bonus entry (`bonus_label_for_entry`)."""

    bonus_id = int(entry.bonus_id)
    if bonus_id == int(BonusId.WEAPON):
        weapon = WEAPON_BY_ID.get(int(entry.amount))
        if weapon is not None and weapon.name:
            return weapon_display_name(int(entry.amount), preserve_bugs=bool(preserve_bugs))
        return "Weapon"
    if bonus_id == int(BonusId.POINTS):
        points_label = bonus_display_name(int(BonusId.POINTS), preserve_bugs=bool(preserve_bugs))
        return f"{points_label}: {int(entry.amount)}"
    meta = BONUS_BY_ID.get(bonus_id)
    if meta is not None:
        return bonus_display_name(int(meta.bonus_id), preserve_bugs=bool(preserve_bugs))
    return "Bonus"
