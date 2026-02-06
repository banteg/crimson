from __future__ import annotations

from grim.geom import Vec2

from crimson.bonuses import BonusId
from crimson.creatures.spawn import CreatureFlags
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.gameplay import PlayerInput, PlayerState
from crimson.perks import PerkId
from crimson.projectiles import ProjectileTypeId
from crimson.sim.world_state import WorldState


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_poison_bullets_sets_self_damage_flag_when_rng_hits() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )
    world.state.rng = _FixedRng(1)  # rand & 7 == 1

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.POISON_BULLETS)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.x = 100.0
    creature.y = 100.0
    creature.hp = 1000.0
    creature.max_hp = 1000.0

    world.state.projectiles.spawn(
        pos_x=creature.x,
        pos_y=creature.y,
        angle=0.0,
        type_id=int(ProjectileTypeId.PISTOL),
        owner_id=-100,
        base_damage=45.0,
    )

    events = world.step(
        0.016,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )
    assert events.hits
    assert creature.flags & CreatureFlags.SELF_DAMAGE_TICK


def test_poison_bullets_does_not_set_flag_when_rng_misses() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )
    world.state.rng = _FixedRng(0)  # rand & 7 != 1

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    player.perk_counts[int(PerkId.POISON_BULLETS)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.x = 100.0
    creature.y = 100.0
    creature.hp = 1000.0
    creature.max_hp = 1000.0

    world.state.projectiles.spawn(
        pos_x=creature.x,
        pos_y=creature.y,
        angle=0.0,
        type_id=int(ProjectileTypeId.PISTOL),
        owner_id=-100,
        base_damage=45.0,
    )

    events = world.step(
        0.016,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )
    assert events.hits
    assert not (creature.flags & CreatureFlags.SELF_DAMAGE_TICK)


def test_poison_bullets_does_not_trigger_on_nuke_radius_damage() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )
    world.state.rng = _FixedRng(1)  # rand & 7 == 1

    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    player.perk_counts[int(PerkId.POISON_BULLETS)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.x = player.pos.x + 100.0
    creature.y = player.pos.y
    creature.hp = 2000.0
    creature.max_hp = 2000.0

    assert world.state.bonus_pool.spawn_at(player.pos.x, player.pos.y, int(BonusId.NUKE), state=world.state) is not None

    world.step(
        0.016,
        inputs=[PlayerInput()],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )
    assert not (creature.flags & CreatureFlags.SELF_DAMAGE_TICK)
