from __future__ import annotations

import math
from typing import cast

import msgspec

from grim.geom import Vec2

from ..creatures.runtime import CreaturePool
from ..creatures.spawn import SpawnEnv
from ..gameplay import GameplayState
from ..sim.presentation_step import DeterministicPresentationPlan
from ..sim.state_types import PlayerState
from ..sim.world_state import WorldEvents, WorldState
from ..weapon_runtime import init_default_alt_weapon, weapon_assign_player
from ..weapons import WEAPON_TABLE, WeaponId


def _weapon_damage_scale_map() -> dict[int, float]:
    table: dict[int, float] = {}
    for entry in WEAPON_TABLE:
        if int(entry.weapon_id) <= 0:
            continue
        table[int(entry.weapon_id)] = float(cast(float, entry.damage_scale))
    return table


def reset_world_players(
    players: list[PlayerState],
    *,
    state: GameplayState,
    world_size: float,
    player_count: int,
    spawn_pos: Vec2 | None = None,
) -> None:
    players.clear()

    base = Vec2(float(world_size) * 0.5, float(world_size) * 0.5) if spawn_pos is None else spawn_pos
    count = max(1, int(player_count))
    if count <= 1:
        offsets = [Vec2()]
    else:
        radius = 32.0
        step = math.tau / float(count)
        offsets = [Vec2.from_angle(float(idx) * step) * radius for idx in range(count)]

    for idx in range(count):
        pos = (base + offsets[idx]).clamp_rect(0.0, 0.0, float(world_size), float(world_size))
        player = PlayerState(index=idx, pos=pos)
        weapon_assign_player(player, WeaponId.PISTOL, state=state)
        init_default_alt_weapon(player)
        players.append(player)

    # Reset-time loadout bootstrap should not leak queued reload SFX.
    state.sfx_queue.clear()


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
