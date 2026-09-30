"""The mode updates `gameplay_update_and_render` runs after the player updates."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

import msgspec

from grim.color import RGBA
from grim.geom import Vec2

from ..creatures.spawn import (
    CreatureAiMode,
    CreatureFlags,
    CreatureTypeId,
    SpawnId,
    clamp01,
    creature_spawn,
    survival_spawn_creature,
)
from ..math_parity import (
    f32,
    f32_from_bits,
    x87_pc24_add,
    x87_pc24_cos_mul,
    x87_pc24_hypot,
    x87_pc24_mul,
    x87_pc24_sin_mul,
    x87_pc24_sub,
)
from ..quests.timeline import quest_spawn_table_empty, quest_spawn_timeline_update
from ..quests.types import SpawnEntry
from ..rng_caller_static import RngCallerStatic
from ..weapon_runtime import weapon_assign_player
from ..weapons import WeaponId
from .state_types import TERRAIN_SIZE

if TYPE_CHECKING:
    from .world_state import WorldState


class SurvivalSpawnState(msgspec.Struct):
    stage: int = 0
    spawn_cooldown_ms: float = 0.0


class RushSpawnState(msgspec.Struct):
    spawn_cooldown_ms: float = 0.0


class QuestSpawnState(msgspec.Struct):
    spawn_entries: tuple[SpawnEntry, ...] = ()
    # Native `quest_spawn_total_creatures`, summed once at quest start.
    total_creatures: int = 0
    spawn_timeline_ms: float = 0.0
    no_creatures_timer_ms: float = 0.0
    completion_transition_ms: float = -1.0
    completed: bool = False
    play_hit_sfx: bool = False
    play_completion_music: bool = False


def survival_update(world: WorldState, spawn: SurvivalSpawnState, *, elapsed_ms: float, dt_ms: float) -> None:
    """Port of `survival_update` (0x00407cd0): weapon handouts, milestone spawns, then the wave spawner."""

    state = world.state
    rng = state.rng
    player = world.players[0]

    if len(world.players) == 1:
        if (
            not state.survival_reward_damage_seen
            and not state.survival_reward_fire_seen
            and int(elapsed_ms) > 64000
            and state.survival_reward_handout_enabled
        ):
            if player.weapon.weapon_id == WeaponId.PISTOL:
                weapon_assign_player(player, WeaponId.SHRINKIFIER_5K, state=state)
                state.survival_reward_weapon_guard_id = WeaponId.SHRINKIFIER_5K
            state.survival_reward_handout_enabled = False
            state.survival_reward_damage_seen = True
            state.survival_reward_fire_seen = True

        if state.survival_recent_death_count == 3 and not state.survival_reward_fire_seen:
            pos0, pos1, pos2 = state.survival_recent_death_pos
            centroid_x = x87_pc24_mul(x87_pc24_add(x87_pc24_add(pos0.x, pos1.x), pos2.x), f32(0.33333334))
            centroid_y = x87_pc24_mul(x87_pc24_add(x87_pc24_add(pos0.y, pos1.y), pos2.y), f32(0.33333334))
            dx = x87_pc24_sub(player.pos.x, centroid_x)
            dy = x87_pc24_sub(player.pos.y, centroid_y)
            if x87_pc24_hypot(dx, dy) < 16.0 and player.health < 15.0:
                weapon_assign_player(player, WeaponId.BLADE_GUN, state=state)
                state.survival_reward_weapon_guard_id = WeaponId.BLADE_GUN
                state.survival_reward_fire_seen = True
                state.survival_reward_handout_enabled = False

    def spawn_template(template_id: SpawnId, pos: Vec2) -> None:
        world.creatures.spawn_template(template_id, pos, math.pi, state=state, detail_preset=state.detail_preset)

    # Native gates each stage on player 1's level and jumps to the wave spawner
    # at the first gate that holds, so one frame can run several stages.
    level = player.level
    if spawn.stage == 0 and level > 4:
        spawn.stage = 1
        spawn_template(SpawnId.FORMATION_RING_ALIEN_8_12, Vec2(-164.0, 512.0))
        spawn_template(SpawnId.FORMATION_RING_ALIEN_8_12, Vec2(1188.0, 512.0))
    if spawn.stage == 1 and level > 8:
        spawn.stage = 2
        spawn_template(SpawnId.ALIEN_CONST_RED_BOSS_2C, Vec2(1088.0, 512.0))
    if spawn.stage == 2 and level > 10:
        spawn.stage = 3
        for i in range(12):
            spawn_template(SpawnId.SPIDER_SP2_RANDOM_35, Vec2(1088.0, f32(f32(i) * f32(42.666668) + 256.0)))
    if spawn.stage == 3 and level > 12:
        spawn.stage = 4
        for i in range(4):
            spawn_template(SpawnId.ALIEN_DEADLY_FAST_2B, Vec2(1088.0, i * 64.0 + 384.0))
    if spawn.stage == 4 and level > 14:
        spawn.stage = 5
        for i in range(4):
            spawn_template(SpawnId.SPIDER_SP1_AI7_TIMER_38, Vec2(1088.0, i * 64.0 + 384.0))
        for i in range(4):
            spawn_template(SpawnId.SPIDER_SP1_AI7_TIMER_38, Vec2(-64.0, i * 64.0 + 384.0))
    if spawn.stage == 5 and level > 16:
        spawn.stage = 6
        spawn_template(SpawnId.SPIDER_BOSS_3A, Vec2(1088.0, 512.0))
    if spawn.stage == 6 and level > 18:
        spawn.stage = 7
        spawn_template(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(640.0, 512.0))
    if spawn.stage == 7 and level > 20:
        spawn.stage = 8
        spawn_template(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(384.0, 256.0))
        spawn_template(SpawnId.SPIDER_SP2_SPLITTER_01, Vec2(640.0, 768.0))
    if spawn.stage == 8 and level > 25:
        spawn.stage = 9
        for i in range(4):
            spawn_template(SpawnId.SPIDER_PLASMA_SHOOTER_3C, Vec2(1088.0, i * 64.0 + 384.0))
        for i in range(4):
            spawn_template(SpawnId.SPIDER_PLASMA_SHOOTER_3C, Vec2(-64.0, i * 64.0 + 384.0))
    if spawn.stage == 9 and level > 31:
        spawn.stage = 10
        spawn_template(SpawnId.SPIDER_BOSS_3A, Vec2(1088.0, 512.0))
        spawn_template(SpawnId.SPIDER_BOSS_3A, Vec2(-64.0, 512.0))
        for i in range(4):
            spawn_template(SpawnId.SPIDER_PLASMA_SHOOTER_3C, Vec2(i * 64.0 + 384.0, -64.0))
        for i in range(4):
            spawn_template(SpawnId.SPIDER_PLASMA_SHOOTER_3C, Vec2(i * 64.0 + 384.0, 1088.0))

    # Wave spawner: past 15 minutes the interval goes negative and each pass
    # spawns an extra creature per 2 ms below zero.
    experience = player.experience
    cooldown = f32(f32(spawn.spawn_cooldown_ms) - f32(f32(len(world.players)) * f32(dt_ms)))
    while cooldown < 0.0:
        interval = 500 - int(elapsed_ms) // 1800
        while interval < 0:
            match rng.rand_tagged(RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_EDGE) & 3:
                case 0:
                    x = rng.rand_tagged(RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_TOP_X) % TERRAIN_SIZE
                    pos = Vec2(float(x), -40.0)
                case 1:
                    x = rng.rand_tagged(RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_BOTTOM_X) % TERRAIN_SIZE
                    pos = Vec2(float(x), TERRAIN_SIZE + 40.0)
                case 2:
                    y = rng.rand_tagged(RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_LEFT_Y) % TERRAIN_SIZE
                    pos = Vec2(-40.0, float(y))
                case _:
                    y = rng.rand_tagged(RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_RIGHT_Y) % TERRAIN_SIZE
                    pos = Vec2(TERRAIN_SIZE + 40.0, float(y))
            survival_spawn_creature(world.creatures, pos, rng, player_experience=experience)
            interval += 2

        if interval < 1:
            interval = 1
        cooldown = f32(cooldown + f32(interval))

        match rng.rand_tagged(RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_EDGE) & 3:
            case 0:
                x = rng.rand_tagged(RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_TOP_X) % TERRAIN_SIZE
                pos = Vec2(float(x), -40.0)
            case 1:
                x = rng.rand_tagged(RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_BOTTOM_X) % TERRAIN_SIZE
                pos = Vec2(float(x), TERRAIN_SIZE + 40.0)
            case 2:
                y = rng.rand_tagged(RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_LEFT_Y) % TERRAIN_SIZE
                pos = Vec2(-40.0, float(y))
            case _:
                y = rng.rand_tagged(RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_RIGHT_Y) % TERRAIN_SIZE
                pos = Vec2(TERRAIN_SIZE + 40.0, float(y))
        survival_spawn_creature(world.creatures, pos, rng, player_experience=experience)
    spawn.spawn_cooldown_ms = float(cooldown)


def rush_mode_update(world: WorldState, spawn: RushSpawnState, *, elapsed_ms: float, dt_ms: float) -> None:
    """Port of `rush_mode_update` (0x004072b0): forced assault rifles, then an alien and a spider every 250 ms."""

    # Native stomps the weapon id and ammo every frame, after the player update
    # and without `weapon_assign_player`: the run starts on the reset pistol
    # (its clip and 0.8 s cooldown), and a manual reload still runs.
    for player in world.players:
        player.weapon.weapon_id = WeaponId.ASSAULT_RIFLE
        player.weapon.ammo = 30.0

    rng = world.state.rng
    elapsed = int(elapsed_ms)
    cooldown = f32(f32(spawn.spawn_cooldown_ms) - f32(f32(len(world.players)) * f32(dt_ms)))
    while cooldown < 0.0:
        cooldown = f32(cooldown + 250.0)

        # `fild (elapsed + 1)` stays exact on the x87 stack; each multiply and add
        # rounds at PC24, and the sine scale is 0x38d1b718, one ulp above f32(1e-4).
        t = float(elapsed + 1)
        tint = RGBA(
            clamp01(x87_pc24_add(x87_pc24_mul(t, f32(1.0 / 120000.0)), f32(0.3))),
            clamp01(x87_pc24_add(x87_pc24_mul(t, 10000.0), f32(0.3))),
            clamp01(x87_pc24_add(math.sin(x87_pc24_mul(t, f32_from_bits(0x38D1B718))), f32(0.3))),
            1.0,
        )

        # fcos/fsin stay wide into the PC24 `* 256.0f`, then add the PC24 `height * 0.5f`.
        theta = x87_pc24_mul(float(elapsed), f32(0.001))
        half_height = x87_pc24_mul(TERRAIN_SIZE, 0.5)
        right = Vec2(x87_pc24_add(TERRAIN_SIZE, 64.0), x87_pc24_add(x87_pc24_cos_mul(theta, 256.0), half_height))
        creature = world.creatures.creature(
            creature_spawn(world.creatures, right, tint, CreatureTypeId.ALIEN, rng, survival_elapsed_ms=elapsed),
        )
        creature.ai_mode = CreatureAiMode.ORBIT_PLAYER_WIDE

        left = Vec2(-64.0, x87_pc24_add(x87_pc24_sin_mul(theta, 256.0), half_height))
        creature = world.creatures.creature(
            creature_spawn(world.creatures, left, tint, CreatureTypeId.SPIDER_SP1, rng, survival_elapsed_ms=elapsed),
        )
        creature.ai_mode = CreatureAiMode.ORBIT_PLAYER_WIDE
        creature.flags |= CreatureFlags.AI7_LINK_TIMER
        creature.move_speed = x87_pc24_mul(creature.move_speed, f32(1.4))
    spawn.spawn_cooldown_ms = float(cooldown)


def quest_mode_update(world: WorldState, spawn: QuestSpawnState, *, dt_ms: float) -> None:
    """Port of `quest_mode_update` (0x004070e0): the spawn timeline, then the completion transition.

    The scaled dt keeps the timeline (the quest score), the stall timer and the
    completion transition slowed under Reflex Boost. The questhit stinger and the
    completion music are left as flags for the presentation pass.
    """

    state = world.state
    if any(c.active for c in world.creatures.entries) or not quest_spawn_table_empty(spawn.spawn_entries):
        spawn.spawn_timeline_ms = f32(f32(spawn.spawn_timeline_ms) + f32(dt_ms))
    quest_spawn_timeline_update(world, spawn, dt_ms=dt_ms)

    spawn.completed = False
    spawn.play_hit_sfx = False
    spawn.play_completion_music = False
    if any(c.active for c in world.creatures.entries) or not quest_spawn_table_empty(spawn.spawn_entries):
        spawn.completion_transition_ms = -1.0
        return

    # No player-alive gate: if the timer crosses 2500 ms while the death
    # animation still plays, the quest completes despite the player dying.
    timer = spawn.completion_transition_ms
    state.bonuses.reflex_boost = 0.0
    if timer < 0.0:
        timer = 0.0
    elif 800.0 < timer <= 850.0:
        spawn.play_hit_sfx = True
        timer = 851.0
    elif 2000.0 < timer <= 2050.0:
        timer = 2051.0
        spawn.play_completion_music = True
    elif timer > 2500.0:
        spawn.completed = True
    spawn.completion_transition_ms = timer + dt_ms


# Per-mode spawn state. Typ-o and tutorial keep theirs in the gameplay state.
type ModeState = SurvivalSpawnState | RushSpawnState | QuestSpawnState | None
