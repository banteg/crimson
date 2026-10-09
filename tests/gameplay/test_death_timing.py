from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from crimson.bonuses import BonusId
from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE, CreatureState
from crimson.creatures.spawn import CreatureTypeId
from crimson.effects import FxQueue, FxQueueRotated, ParticleStyleId
from crimson.owner_id import player_owner_id
from crimson.perks import PerkId
from crimson.projectiles.runtime import fx_spawn_secondary_projectile, projectile_spawn
from crimson.projectiles.types import ProjectileTemplateId, SecondaryProjectileTypeId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldEvents, WorldState
from crimson.weapon_runtime import prepare_weapon_availability, weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from grim.sfx_map import SfxId
from tests.support.audio import sfx_ids
from tests.support.factories import make_creature_state, player_input
from tests.support.helpers import ScriptedCrand

_ALIEN_DEATH_SFX = (SfxId.ALIEN_DIE_01, SfxId.ALIEN_DIE_02, SfxId.ALIEN_DIE_03, SfxId.ALIEN_DIE_04)
# A pistol kill's `creature_apply_damage` draws: heading jitter, then the
# `creature_handle_death` bonus-drop rolls for a non-forced pistol-held drop.
_PISTOL_KILL_DRAWS = [
    RngCallerStatic.CREATURE_APPLY_DAMAGE_HEADING_JITTER,
    RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_PISTOL_FORCE_WEAPON,
    RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BASE_GATE,
    RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_PISTOL_ALLOW_WITHOUT_MAGNET,
]


def _build_world(**kwargs: Any) -> WorldState:
    # Run init prepares weapon availability; kills can roll weapon drops.
    world = WorldState.build(**kwargs)
    prepare_weapon_availability(world.state)
    return world


def _world_with_player(**kwargs: Any) -> WorldState:
    world = _build_world(hardcore=False, quest_fail_retry_count=0, **kwargs)
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))
    return world


def _step(world: WorldState, dt: float, *, inputs: Sequence[PlayerInput] | None = None) -> WorldEvents:
    return world.step(
        dt,
        inputs=[player_input() for _ in world.players] if inputs is None else inputs,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        perk_progression_enabled=False,
    )


def _shoot_pistol_at(world: WorldState, creature: CreatureState) -> None:
    """Spawn a player pistol bullet on `creature`, so this step's projectile update hits it."""

    projectile_spawn(
        world.state,
        players=world.players,
        pos=creature.pos,
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner_id=player_owner_id(0),
        owner_player_index=0,
    )


def _callers_since(rng: ScriptedCrand | RecordingCrand, start: int) -> list[int | None]:
    return [record.caller for record in rng.records_since(start)]


def _draw_values(rng: ScriptedCrand | RecordingCrand, caller: RngCallerStatic) -> list[int]:
    return [record.value for record in rng.records_since(0) if record.caller == caller]


def test_weapon_guard_runs_before_same_frame_locked_splitter_pickup() -> None:
    world = _build_world(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    weapon_assign_player(player, WeaponId.PISTOL, state=world.state)
    world.players.append(player)
    entry = world.state.bonus_pool.spawn_at(
        pos=player.pos,
        bonus_id=BonusId.WEAPON,
        amount_override=int(WeaponId.SPLITTER_GUN),
        state=world.state,
    )
    assert entry is not None

    first = _step(world, 0.016)

    assert len(first.pickups) == 1
    assert player.weapon.weapon_id == WeaponId.SPLITTER_GUN

    _step(world, 0.016)

    assert player.weapon.weapon_id == WeaponId.PISTOL


def test_weapon_usage_time_precedes_same_frame_weapon_pickup() -> None:
    world = _build_world(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    weapon_assign_player(player, WeaponId.PISTOL, state=world.state)
    world.players.append(player)
    entry = world.state.bonus_pool.spawn_at(
        pos=player.pos,
        bonus_id=BonusId.WEAPON,
        amount_override=int(WeaponId.ASSAULT_RIFLE),
        state=world.state,
    )
    assert entry is not None

    first = _step(world, 0.016)

    assert len(first.pickups) == 1
    assert player.weapon.weapon_id == WeaponId.ASSAULT_RIFLE
    assert world.state.weapon_usage_time[WeaponId.PISTOL] == 16
    assert world.state.weapon_usage_time[WeaponId.ASSAULT_RIFLE] == 0

    _step(world, 0.016)

    assert world.state.weapon_usage_time[WeaponId.PISTOL] == 16
    assert world.state.weapon_usage_time[WeaponId.ASSAULT_RIFLE] == 16


def test_highscore_score_stages_before_same_frame_points_pickup() -> None:
    world = _build_world(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), experience=10)
    world.players.append(player)
    entry = world.state.bonus_pool.spawn_at(
        pos=player.pos,
        bonus_id=BonusId.POINTS,
        amount_override=500,
        state=world.state,
    )
    assert entry is not None

    first = _step(world, 0.016)

    assert len(first.pickups) == 1
    assert world.state.highscore_score_xp == 10
    assert player.experience == 510

    _step(world, 0.016)

    assert world.state.highscore_score_xp == 510


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_sfx"),
    (
        (False, SfxId.TROOPER_DIE_01),
        (True, SfxId.TROOPER_INPAIN_01),
    ),
)
def test_world_step_trooper_death_sfx_respects_preserve_bugs(
    preserve_bugs: bool,
    expected_sfx: SfxId,
) -> None:
    world = _world_with_player(preserve_bugs=preserve_bugs)
    creature = world.creatures.entries[0] = make_creature_state(
        pos=Vec2(256.0, 256.0),
        hp=25.0,
        type_id=CreatureTypeId.TROOPER,
    )
    _shoot_pistol_at(world, creature)
    # Death-sfx roll 3: `3 % 3` picks the first trooper death sound; the
    # preserved-bug `3 & 3` indexes the unwritten fourth bank slot.
    rng = ScriptedCrand(3, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world.state.rng = rng

    events = _step(world, 0.1)

    assert len(events.deaths) == 1
    assert sfx_ids(events.sfx) == [expected_sfx]
    callers = _callers_since(rng, 0)
    jitter = callers.index(RngCallerStatic.CREATURE_APPLY_DAMAGE_HEADING_JITTER)
    # The kill's heading jitter and bonus-drop rolls, then its single death sfx pick.
    assert callers[jitter : jitter + 5] == [*_PISTOL_KILL_DRAWS, RngCallerStatic.CREATURE_APPLY_DAMAGE_DEATH_SFX]
    assert callers.count(RngCallerStatic.CREATURE_APPLY_DAMAGE_DEATH_SFX) == 1


def test_detonation_followup_does_not_duplicate_resolved_death_sfx() -> None:
    world = _world_with_player()
    creature = world.creatures.entries[0] = make_creature_state(
        pos=Vec2(256.0, 256.0),
        hp=25.0,
        type_id=CreatureTypeId.ALIEN,
    )

    # A rocket's direct-hit detonation state: `vel` carries (t, scale).
    detonation = world.state.secondary_projectiles.entries[0]
    detonation.active = True
    detonation.type_id = SecondaryProjectileTypeId.DETONATION
    detonation.pos = creature.pos
    detonation.vel = Vec2(0.0, 1.0)
    detonation.detonation_t = 0.0
    detonation.detonation_scale = 1.0

    events = _step(world, 0.1)

    # Native detonation follow-up re-enters creature death handling for side effects,
    # but does not perform a second death-SFX random pick.
    assert len(events.deaths) == 2
    assert sum(key in _ALIEN_DEATH_SFX for key in sfx_ids(events.sfx)) == 1


def test_bubblegun_expiry_reenters_active_zero_hp_death_and_owns_sfx() -> None:
    world = _world_with_player()
    creature = world.creatures.entries[0] = make_creature_state(
        pos=Vec2(256.0, 256.0),
        hp=0.0,
        max_hp=25.0,
        type_id=CreatureTypeId.ZOMBIE,
    )
    # Expiry sound slot `2 % 3` is the third zombie death sound.
    rng = ScriptedCrand(2, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world.state.rng = rng
    # A bubble that already captured the creature and expires this step.
    particle = world.state.particles.entries[0]
    particle.active = True
    particle.in_flight = False
    particle.intensity = 0.81
    particle.style_id = ParticleStyleId.BUBBLEGUN
    particle.target_id = 0

    events = _step(world, 0.1)

    assert not creature.active
    assert len(events.deaths) == 1
    assert sfx_ids(events.sfx) == [SfxId.ZOMBIE_DIE_03]
    # The zero-hp corpse tick draws nothing, so the expiry sound is the step's first draw.
    assert rng.records_since(0)[0].caller == RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_BUBBLEGUN_EXPIRY_SFX


def test_plague_kill_death_event_has_no_resolved_death_sfx() -> None:
    world = _world_with_player()
    creature = world.creatures.entries[0] = make_creature_state(
        pos=Vec2(256.0, 256.0),
        hp=10.0,
        type_id=CreatureTypeId.ALIEN,
        plague_infected=True,
    )
    # The plague tick lands this step and its 15 damage kills.
    creature.dot_tick_timer = 0.0
    rng = RecordingCrand(Crand(0x1234))
    world.state.rng = rng

    events = _step(world, 0.016)

    assert len(events.deaths) == 1
    callers = _callers_since(rng, 0)
    assert RngCallerStatic.CREATURE_APPLY_DAMAGE_DEATH_SFX not in callers
    # The plague kill plays the bank-b attack sound, not a death sound.
    [plague_sfx_roll] = _draw_values(rng, RngCallerStatic.CREATURE_UPDATE_ALL_PLAGUE_KILL_SFX)
    assert sfx_ids(events.sfx) == [(SfxId.ALIEN_ATTACK_01, SfxId.ALIEN_ATTACK_02)[plague_sfx_roll & 1]]


def test_perk_effects_step_uses_previous_aim_before_player_update() -> None:
    world = _build_world(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    player.aim = Vec2(128.0, 256.0)
    world.players.append(player)
    world.state.perks[PerkId.DOCTOR] = 1
    creature = world.creatures.entries[3]
    creature.active = True
    creature.pos = Vec2(128.0, 256.0)
    creature.hp = 100.0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE

    _step(world, 0.016, inputs=[player_input(aim=Vec2(900.0, 900.0))])

    # `perks_update_effects` searched around the aim from before `player_update` moved it.
    assert player.doctor_target_creature == 3
    assert player.aim == Vec2(900.0, 900.0)


def test_first_secondary_rocket_hit_triggers_game_tune() -> None:
    world = _world_with_player()

    creature = world.creatures.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 1000.0
    creature.max_hp = 1000.0
    creature.size = 50.0

    fx_spawn_secondary_projectile(
        world.state,
        world.players[0],
        world.creatures.entries,
        pos=Vec2(100.0, 100.0),
        angle=0.0,
        type_id=SecondaryProjectileTypeId.ROCKET,
    )

    events = _step(world, 0.016, inputs=[player_input()])

    # Native secondary-rocket hits run the same first-hit game-tune branch as
    # bullet hits instead of the panned explosion sound.
    assert events.trigger_game_tune is True
    assert SfxId.EXPLOSION_MEDIUM not in sfx_ids(world.state.sfx_queue)
    assert SfxId.EXPLOSION_MEDIUM not in sfx_ids(events.hit_sfx)
