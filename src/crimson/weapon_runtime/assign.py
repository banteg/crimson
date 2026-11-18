from __future__ import annotations

from typing import TYPE_CHECKING

from grim.math import i32
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..math_parity import NATIVE_TAU, f32, x87_pc24_add, x87_pc24_div, x87_pc24_mul, x87_pc24_sub
from ..movement_controls import MovementControlType
from ..owner_id import player_projectile_owner_id
from ..perks import PerkId
from ..projectiles.runtime import projectile_spawn
from ..projectiles.types import ProjectileTemplateId
from ..sim.state_types import PlayerState, WeaponSlot
from ..weapon_usage import weapon_usage_slot_for_weapon_id
from ..weapons import WEAPON_BY_ID, Weapon, WeaponId

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ..sim.input import PlayerInput
    from ..sim.world_state import WorldStepRuntime


def weapon_entry(weapon_id: WeaponId) -> Weapon:
    return WEAPON_BY_ID[weapon_id]


def _clip_size_with_perks(state: GameplayState, clip_size: int) -> int:
    clip_size = max(0, clip_size)
    if PerkId.AMMO_MANIAC in state.perks:
        clip_size += max(1, int(float(clip_size) * 0.25))
    # 1.9.8 adds My Favourite Weapon's +2 only when the perk is picked, so the next
    # assign loses it (original bug 59).
    if PerkId.MY_FAVOURITE_WEAPON in state.perks and not state.bugs_1_9_8:
        clip_size += 2
    return clip_size


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
    usage_slot = weapon_usage_slot_for_weapon_id(int(weapon_id))
    if usage_slot is not None:
        state.status.increment_weapon_usage_slot(usage_slot)

    weapon = weapon_entry(weapon_id)
    player.weapon.weapon_id = weapon_id

    player.weapon.clip_size = _clip_size_with_perks(state, int(weapon.clip_size))
    player.weapon.ammo = float(player.weapon.clip_size)
    player.weapon_reset_latch = 0
    # Native resets only ammo, the reset latch, shot cooldown, reload timer,
    # and aux timer; reload_active and reload_timer_max keep their previous
    # values across a weapon pickup mid-reload.
    player.weapon.reload_timer = 0.0
    player.weapon.shot_cooldown = 0.0
    player.weapon_popup_timer = 2.0
    state.sfx_queue.append(SfxRequest(weapon.reload_sound, player.pos))


def most_used_weapon_id_for_player(
    state: GameplayState,
    *,
    fallback_weapon_id: WeaponId,
) -> WeaponId:
    """Return native's most-used weapon from the global equipped-time table."""

    times = state.weapon_usage_time
    if len(times) < 2:
        return WeaponId(fallback_weapon_id)

    def signed_time(weapon_id: int) -> int:
        return i32(int(times[weapon_id]))

    best = 1
    for weapon_id in range(2, min(len(times), 64)):
        if signed_time(weapon_id) > signed_time(best):
            best = weapon_id
    try:
        return WeaponId(best)
    except ValueError:
        return WeaponId(fallback_weapon_id)


def player_swap_alt_weapon(player: PlayerState) -> bool:
    """Swap primary and alternate weapon runtime blocks (Alternate Weapon perk)."""

    if player.alt_weapon is None:
        return False
    player.weapon, player.alt_weapon = player.alt_weapon, player.weapon
    return True


def player_start_reload(
    player: PlayerState,
    state: GameplayState,
) -> None:
    """Start or refresh a reload timer (`player_start_reload` @ 0x00413430)."""

    if player.weapon.reload_active and (
        PerkId.AMMUNITION_WITHIN in state.perks or PerkId.REGRESSION_BULLETS in state.perks
    ):
        return

    weapon = weapon_entry(player.weapon.weapon_id)
    reload_time = f32(weapon.reload_time)

    if not player.weapon.reload_active:
        state.sfx_queue.append(SfxRequest(weapon.reload_sound, player.pos))
        player.weapon.reload_active = True

    player.weapon.reload_timer = reload_time
    if PerkId.FASTLOADER in state.perks:
        player.weapon.reload_timer = x87_pc24_mul(reload_time, f32(0.7))
    if state.bonuses.weapon_power_up > 0.0:
        player.weapon.reload_timer = x87_pc24_mul(player.weapon.reload_timer, f32(0.6))

    player.weapon.reload_timer_max = player.weapon.reload_timer


def _fire_angry_reloader_ring(player: PlayerState, step_runtime: WorldStepRuntime) -> None:
    state = step_runtime.world.state
    count = 7 + int(player.weapon.reload_timer_max * 4.0)
    owner_id = player_projectile_owner_id(friendly_fire=state.friendly_fire_enabled, player_index=player.index)
    # Native `(float)i * (6.2831855f / (float)count) + 0.1f` at PC24.
    ring_step = x87_pc24_div(NATIVE_TAU, float(count))
    state.scripted_burst_active = True
    for idx in range(count):
        projectile_spawn(
            state,
            players=step_runtime.world.players,
            pos=player.pos,
            angle=x87_pc24_add(x87_pc24_mul(float(idx), ring_step), f32(0.1)),
            type_id=ProjectileTemplateId.PLASMA_MINIGUN,
            owner_id=owner_id,
            owner_player_index=player.index,
        )
    state.scripted_burst_active = False
    state.sfx_queue.append(SfxRequest(SfxId.EXPLOSION_SMALL, player.pos))


def advance_weapon_reload(
    player: PlayerState, input_state: PlayerInput, dt: float, *, stationary: bool, step_runtime: WorldStepRuntime,
) -> None:
    """Advance the equipped slot's reload, then honor a held manual reload key."""
    state = step_runtime.world.state
    slot = player.weapon
    if input_state.fire_pressed and slot.reload_timer > 0.0 and PerkId.ANXIOUS_LOADER in state.perks:
        slot.reload_timer = x87_pc24_sub(slot.reload_timer, f32(0.05))
        if slot.reload_timer <= 0.0:
            # Anxious Loader restarts the last fraction of the reload when it overshoots.
            slot.reload_timer = x87_pc24_mul(dt, f32(0.8))

    if slot.reload_timer > 0.0:
        before = slot.reload_timer
        scale = 3.0 if stationary and PerkId.STATIONARY_RELOADER in state.perks else 1.0
        reload_step = x87_pc24_mul(scale, f32(dt))
        # Native tests an unscaled delta for preload. Stationary Reloader can cross
        # zero without refilling. Rules 2 also refill when the timer lands exactly on zero.
        preload_step = f32(dt) if state.preserve_bugs else reload_step
        preload_timer = f32(before)
        preload_remaining = x87_pc24_sub(preload_timer, preload_step)
        refill = preload_remaining <= 0.0 if state.rules2_fixes else preload_remaining < 0.0
        if preload_timer > 0.0 and refill:
            slot.ammo = float(slot.clip_size)

        slot.reload_timer = x87_pc24_sub(before, reload_step)
        if PerkId.ANGRY_RELOADER in state.perks and (state.rules_1_9_8 or slot.reload_timer_max > 0.5):
            midpoint = x87_pc24_mul(slot.reload_timer_max, f32(0.5))
            if slot.reload_timer <= midpoint < before:
                _fire_angry_reloader_ring(player, step_runtime)

    if slot.reload_timer < 0.0:
        slot.reload_timer = 0.0

    # A held key chains reloads at completion. Alternate Weapon and point-click
    # claim that key for swapping and movement. Native only accepts manual reload solo.
    if (
        (input_state.reload_down or input_state.reload_pressed)
        and slot.reload_timer == 0.0
        and PerkId.ALTERNATE_WEAPON not in state.perks
        and input_state.move_mode != MovementControlType.MOUSE_POINT_CLICK
        and (len(step_runtime.world.players) == 1 or (not state.preserve_bugs and not state.legacy_coop_reload))
    ):
        player_start_reload(player, state)
