from __future__ import annotations

from collections.abc import Callable

import msgspec

from ..perks import PerkId
from ..perks.helpers import perk_active
from ..sim.state_types import GameplayState, PlayerState, WeaponSlot
from ..weapon_usage import weapon_usage_slot_for_weapon_id
from ..weapons import WEAPON_BY_ID, Weapon, WeaponId


def weapon_entry(weapon_id: WeaponId) -> Weapon:
    return WEAPON_BY_ID[weapon_id]


class _WeaponAssignCtx(msgspec.Struct):
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


def init_default_alt_weapon(player: PlayerState) -> None:
    """Initialize native reset-time alternate weapon slot state."""

    player.alt_weapon = WeaponSlot(
        weapon_id=WeaponId.PISTOL,
        clip_size=12,
        ammo=12.0,
        reload_active=False,
        reload_timer=0.0,
        reload_timer_max=1.2,
        shot_cooldown=0.0,
    )


def weapon_assign_player(player: PlayerState, weapon_id: WeaponId, *, state: GameplayState) -> None:
    """Assign weapon and reset per-weapon runtime state (ammo/cooldowns)."""

    weapon_id = WeaponId(weapon_id)
    if state.status is not None and not state.demo_mode_active:
        usage_slot = weapon_usage_slot_for_weapon_id(int(weapon_id))
        if usage_slot is not None:
            state.status.increment_weapon_usage_slot(usage_slot)

    weapon = weapon_entry(weapon_id)
    player.weapon.weapon_id = weapon_id

    clip_size = int(weapon.clip_size)
    clip_ctx = _WeaponAssignCtx(player=player, clip_size=max(0, clip_size))
    for modifier in _WEAPON_ASSIGN_CLIP_MODIFIERS:
        modifier(clip_ctx)
    player.weapon.clip_size = max(0, int(clip_ctx.clip_size))
    player.weapon.ammo = float(player.weapon.clip_size)
    player.weapon_reset_latch = 0
    # Native resets only ammo, the reset latch, shot cooldown, reload timer,
    # and aux timer; reload_active and reload_timer_max keep their previous
    # values across a weapon pickup mid-reload.
    player.weapon.reload_timer = 0.0
    player.weapon.shot_cooldown = 0.0
    player.aux_timer = 2.0

    if state is not None:
        state.sfx_queue.append(weapon.reload_sound)


def most_used_weapon_id_for_player(
    state: GameplayState,
    *,
    player_index: int,
    fallback_weapon_id: WeaponId,
) -> WeaponId:
    """Return a weapon id for the player's most-used weapon."""

    idx = int(player_index)
    if 0 <= idx < len(state.weapon_shots_fired):
        counts = state.weapon_shots_fired[idx]
        if counts:
            start = 1 if len(counts) > 1 else 0
            best = max(range(start, len(counts)), key=lambda i: int(counts[i]))
            if int(counts[best]) > 0:
                return WeaponId(best)
    return WeaponId(fallback_weapon_id)


def player_swap_alt_weapon(player: PlayerState) -> bool:
    """Swap primary and alternate weapon runtime blocks (Alternate Weapon perk)."""

    if player.alt_weapon is None:
        return False
    player.weapon, player.alt_weapon = player.alt_weapon, player.weapon
    return True


def player_start_reload(player: PlayerState, state: GameplayState) -> None:
    """Start or refresh a reload timer (`player_start_reload` @ 0x00413430)."""

    if player.weapon.reload_active and (
        perk_active(player, PerkId.AMMUNITION_WITHIN) or perk_active(player, PerkId.REGRESSION_BULLETS)
    ):
        return

    weapon = weapon_entry(player.weapon.weapon_id)
    reload_time = float(weapon.reload_time)

    if not player.weapon.reload_active:
        player.weapon.reload_active = True

    if perk_active(player, PerkId.FASTLOADER):
        reload_time *= 0.7
    if state.bonuses.weapon_power_up > 0.0:
        reload_time *= 0.6

    player.weapon.reload_timer = max(0.0, reload_time)
    player.weapon.reload_timer_max = player.weapon.reload_timer
