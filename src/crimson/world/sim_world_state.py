from __future__ import annotations

import struct
from collections.abc import Sequence
from typing import cast

import msgspec

from grim.color import RGBA
from grim.geom import Vec2

from ..creatures.runtime import CreatureAiMode, CreaturePool, CreatureState, CreatureTypeId
from ..creatures.spawn import SpawnEnv
from ..creatures.spawn_ids import CreatureFlags
from ..gameplay import GameplayState
from ..math_parity import f32
from ..replay.types import ReplayCreatureSlotResidue
from ..sim.presentation_step import DeterministicPresentationPlan
from ..sim.state_types import PlayerState
from ..sim.world_state import WorldEvents, WorldState
from ..weapon_runtime import init_default_alt_weapon
from ..weapons import WEAPON_TABLE, WeaponId


def _weapon_damage_scale_map() -> dict[int, float]:
    table: dict[int, float] = {}
    for entry in WEAPON_TABLE:
        if int(entry.weapon_id) <= 0:
            continue
        table[int(entry.weapon_id)] = float(cast(float, entry.damage_scale))
    return table


def apply_creature_pool_residue(
    creatures: list[CreatureState],
    residue: Sequence[ReplayCreatureSlotResidue],
) -> None:
    """Seed the fresh pool with the run-start residue captured natively.

    `creature_reset_all` (0x4281e0) clears `active` and detaches linked
    spawn-slot owners, but leaves the other creature fields intact. Spawn
    paths overwrite only the fields they write, so stale reads (link_index,
    target_heading, AI7 timers, ...) must see the previous occupant's values."""

    for slot in residue:
        idx = int(slot.index)
        if not (0 <= idx < len(creatures)):
            continue
        entry = creatures[idx]
        entry.active = False
        entry.phase_seed = int(slot.phase_seed)
        entry.plague_infected = bool(slot.collision_flag)
        entry.collision_timer = float(slot.collision_timer)
        entry.lifecycle_stage = float(slot.lifecycle_stage)
        entry.pos = Vec2(float(slot.pos.x), float(slot.pos.y))
        entry.vel = Vec2(float(slot.vel.x), float(slot.vel.y))
        entry.hp = float(slot.hp)
        entry.max_hp = float(slot.max_hp)
        entry.heading = float(slot.heading)
        entry.target_heading = float(slot.target_heading)
        entry.size = float(slot.size)
        entry.hit_flash_timer = float(slot.hit_flash_timer)
        entry.tint = RGBA(float(slot.tint_r), float(slot.tint_g), float(slot.tint_b), float(slot.tint_a))
        entry.force_target = int(slot.force_target)
        entry.target = Vec2(float(slot.target.x), float(slot.target.y))
        entry.contact_damage = float(slot.contact_damage)
        entry.move_speed = float(slot.move_speed)
        entry.attack_cooldown = float(slot.attack_cooldown)
        entry.reward_value = float(slot.reward_value)
        entry.type_id = CreatureTypeId(int(slot.type_id))
        entry.target_player = int(slot.target_player)
        entry.link_index = int(slot.link_index)
        entry.target_offset = Vec2(float(slot.target_offset.x), float(slot.target_offset.y))
        entry.orbit_angle = float(slot.orbit_angle)
        entry.orbit_radius = _f32_from_bits(int(slot.orbit_radius_u32))
        entry.flags = CreatureFlags(int(slot.flags))
        entry.ai_mode = CreatureAiMode(int(slot.ai_mode))
        entry.anim_phase = float(slot.anim_phase)


def _f32_from_bits(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", int(bits) & 0xFFFFFFFF))[0]


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
    weapon.shot_cooldown = 0.8


def reset_world_players(
    players: list[PlayerState],
    *,
    state: GameplayState,
    world_size: float,
    player_count: int,
    spawn_pos: Vec2 | None = None,
) -> None:
    previous_players = tuple(players)
    players.clear()

    if spawn_pos is None:
        center = f32(float(world_size) * 0.5)
        base = Vec2(center, center)
    else:
        base = Vec2(f32(spawn_pos.x), f32(spawn_pos.y))
    count = max(1, int(player_count))

    for idx in range(count):
        offset = f32(float(idx * 0x50))
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
        player.perk_counts = [0] * len(player.perk_counts)
        player.plaguebearer_active = False
        player.speed_bonus_timer = 0.0
        player.shield_timer = 0.0
        _reset_player_weapon_native(player)
        init_default_alt_weapon(player)

        # `gameplay_reset_state` immediately follows `player_reset_all` with
        # these represented per-player writes. The native move target is held
        # by the input runtime rather than PlayerState in this port.
        player.low_health_timer = 100.0
        player.auto_target = 0
        player.aux_timer = 0.0
        players.append(player)


class SimWorldState(msgspec.Struct):
    world_size: float = 1024.0
    demo_mode_active: bool = False
    quest_fail_retry_count: int = 0
    hardcore: bool = False
    preserve_bugs: bool = False

    world_state: WorldState = cast(WorldState, None)
    spawn_env: SpawnEnv = cast(SpawnEnv, None)
    state: GameplayState = cast(GameplayState, None)
    players: list[PlayerState] = msgspec.field(default_factory=list)
    creatures: CreaturePool = cast(CreaturePool, None)

    damage_scale_by_type: dict[int, float] = msgspec.field(default_factory=_weapon_damage_scale_map)
    presentation_elapsed_ms: float = 0.0
    bonus_anim_phase: float = 0.0
    game_tune_started: bool = False
    last_events: WorldEvents = msgspec.field(
        default_factory=lambda: WorldEvents(hits=[], deaths=(), pickups=[], sfx=[]),
    )
    last_presentation: DeterministicPresentationPlan = msgspec.field(default_factory=DeterministicPresentationPlan)
    def __post_init__(self) -> None:
        self.reset(seed=0xBEEF, player_count=1)

    def reset(
        self,
        *,
        seed: int = 0xBEEF,
        player_count: int = 1,
        spawn_pos: Vec2 | None = None,
    ) -> None:
        self.world_state = WorldState.build(
            world_size=float(self.world_size),
            demo_mode_active=bool(self.demo_mode_active),
            hardcore=bool(self.hardcore),
            quest_fail_retry_count=int(self.quest_fail_retry_count),
            preserve_bugs=bool(self.preserve_bugs),
        )
        self.spawn_env = self.world_state.spawn_env
        self.state = self.world_state.state
        self.players = self.world_state.players
        self.creatures = self.world_state.creatures
        self.state.rng.srand(int(seed))

        self.last_events = WorldEvents(hits=[], deaths=(), pickups=[], sfx=[])
        self.last_presentation = DeterministicPresentationPlan()

        self.presentation_elapsed_ms = 0.0
        self.bonus_anim_phase = 0.0
        self.game_tune_started = False

        reset_world_players(
            self.players,
            state=self.state,
            world_size=float(self.world_size),
            player_count=int(player_count),
            spawn_pos=spawn_pos,
        )

    def load_world_state(self, world_state: WorldState) -> None:
        self.world_state = world_state
        self.spawn_env = self.world_state.spawn_env
        self.state = self.world_state.state
        self.players = self.world_state.players
        self.creatures = self.world_state.creatures
        self.last_events = WorldEvents(hits=[], deaths=(), pickups=[], sfx=[])
        self.last_presentation = DeterministicPresentationPlan()


    def apply_step_metadata(
        self,
        *,
        events: WorldEvents,
        presentation: DeterministicPresentationPlan,
        dt_sim: float,
        game_tune_started: bool,
    ) -> None:
        self.last_events = events
        self.last_presentation = presentation

        if float(dt_sim) > 0.0:
            self.presentation_elapsed_ms += float(dt_sim) * 1000.0
            self.bonus_anim_phase += float(dt_sim) * 1.3

        self.game_tune_started = bool(game_tune_started)

    def close_session(self) -> None:
        self.last_events = WorldEvents(hits=[], deaths=(), pickups=[], sfx=[])
        self.last_presentation = DeterministicPresentationPlan()

        self.game_tune_started = False
