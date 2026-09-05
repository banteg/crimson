from __future__ import annotations

from dataclasses import dataclass, field

from crimson.sim.gameplay_state import GameplayState
from grim.geom import Vec2

from ..creatures.runtime import CreaturePool
from ..creatures.spawn import SpawnEnv
from ..sim.presentation_step import DeterministicPresentationPlan
from ..sim.state_types import PlayerState
from ..sim.world_reset import reset_world_players
from ..sim.world_state import WorldEvents, WorldState
from ..weapons import build_damage_scale_by_type


@dataclass(slots=True)
class SimWorldState:
    world_size: float = 1024.0
    demo_mode_active: bool = False
    quest_fail_retry_count: int = 0
    hardcore: bool = False
    preserve_bugs: bool = False

    world_state: WorldState = field(init=False)

    damage_scale_by_type: dict[int, float] = field(default_factory=build_damage_scale_by_type)
    presentation_elapsed_ms: float = 0.0
    bonus_anim_phase: float = 0.0
    game_tune_started: bool = False
    last_events: WorldEvents = field(
        default_factory=lambda: WorldEvents(hits=[], deaths=(), pickups=[], sfx=[]),
    )
    last_presentation: DeterministicPresentationPlan = field(default_factory=DeterministicPresentationPlan)

    @property
    def spawn_env(self) -> SpawnEnv:
        return self.world_state.spawn_env

    @property
    def state(self) -> GameplayState:
        return self.world_state.state

    @property
    def players(self) -> list[PlayerState]:
        return self.world_state.players

    @property
    def creatures(self) -> CreaturePool:
        return self.world_state.creatures

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
        self.creatures.apply_gameplay_reset_target_players(len(self.players))

    def load_world_state(self, world_state: WorldState) -> None:
        self.world_state = world_state
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
