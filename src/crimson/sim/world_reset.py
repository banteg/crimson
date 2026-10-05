from __future__ import annotations

from typing import TYPE_CHECKING

from grim.geom import Vec2

from ..math_parity import f32
from ..weapon_runtime import init_default_alt_weapon
from ..weapons import WeaponId
from .gameplay_state import GameplayState
from .state_types import TERRAIN_SIZE, PerkCounts, PlayerState

if TYPE_CHECKING:
    from .world_state import WorldState


def _reset_player_weapon_native(player: PlayerState) -> None:
    """Port of the weapon block in `player_reset_all` (0x41fc80).

    Native resets every run to a hardcoded 10-round pistol with a primed
    1.0s reload duration and a decaying 0.8s shot cooldown; it does not go
    through `weapon_assign_player` (no table stats, no usage count, no
    reload sfx), and it leaves the primary reload-active byte untouched.
    Quest setup assigns the start weapon on top of this."""

    weapon = player.weapon
    weapon.weapon_id = WeaponId.PISTOL
    weapon.clip_size = 10
    weapon.ammo = 10.0
    weapon.reload_timer = 0.0
    weapon.reload_timer_max = 1.0
    weapon.shot_cooldown = f32(0.8)


def reset_world_players(
    players: list[PlayerState],
    *,
    state: GameplayState,
    player_count: int,
) -> None:
    previous_players = tuple(players)
    players.clear()
    # `player_reset_all` clears player one's struct, which holds the perk table.
    state.perks = PerkCounts()

    center = f32(TERRAIN_SIZE * 0.5)
    base = Vec2(center, center)
    count = max(1, int(player_count))

    for idx in range(count):
        offset = f32(idx * 0x50)
        if idx % 2:
            pos = Vec2(f32(base.x - offset), f32(base.y - offset))
        else:
            pos = Vec2(f32(base.x + offset), f32(base.y + offset))
        if idx < len(previous_players):
            player = previous_players[idx]
            player.index = idx
        else:
            player = PlayerState(index=idx, pos=pos)

        # `player_reset_all` mutates selected fields in the two static native
        # records; it does not reconstruct the player object. Keep the same
        # contract here so run-transition residue remains observable.
        player.pos = pos
        player.health = 100.0
        player.size = 48.0
        player.speed_multiplier = 2.0
        player.move_speed = 0.0
        player.heading = 0.0
        player.death_timer = 16.0
        player.experience = 0
        player.level = 1
        player.spread_heat = 0.0
        player.plaguebearer_active = False
        player.speed_bonus_timer = 0.0
        player.shield_timer = 0.0
        _reset_player_weapon_native(player)
        init_default_alt_weapon(player)

        # `gameplay_reset_state` immediately follows `player_reset_all` with
        # these represented per-player writes. The native move target is held
        # by the input runtime rather than PlayerState in this port.
        player.bleed_drip_timer = 100.0
        player.auto_target = 0
        player.weapon_popup_timer = 0.0
        players.append(player)


def build_reset_world(
    *,
    seed: int,
    player_count: int,
    hardcore: bool = False,
    quest_fail_retry_count: int = 0,
    preserve_bugs: bool = False,
) -> WorldState:
    """Build a fresh world, seed its rng and place the players, as a run reset does."""
    from .world_state import WorldState

    world = WorldState.build(
        hardcore=bool(hardcore),
        quest_fail_retry_count=int(quest_fail_retry_count),
        preserve_bugs=bool(preserve_bugs),
    )
    world.state.rng.srand(int(seed))
    reset_world_players(
        world.players,
        state=world.state,
        player_count=int(player_count),
    )
    world.creatures.apply_gameplay_reset_target_players(len(world.players))
    return world
